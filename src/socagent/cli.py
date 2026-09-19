"""Command-line interface ``socagent``.

Exit codes: 0 success, 1 the request was refused or a gate failed (for example ``--fail-on``), 2 for
usage or runtime errors.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from socagent.config import Settings
from socagent.container import build_service
from socagent.errors import SocagentError
from socagent.logging_setup import configure_logging
from socagent.normalizers import NORMALIZERS
from socagent.reporting import FORMATS, render, write_report
from socagent.security import redact
from socagent.service import IRService, parse_duration
from socagent.simulate import simulate, write_records

_STATUSES: list[str] = ["open", "investigating", "contained", "closed"]


def _parse_time(text: str) -> datetime:
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SocagentError(f"invalid timestamp {text!r}; use ISO 8601") from exc
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="socagent", description="AI incident response agent")
    parser.add_argument("--db", type=Path, help="database path (default: SOCAGENT_DB_PATH)")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="ingest a JSON Lines alert export")
    ingest.add_argument("--source", required=True, choices=sorted(NORMALIZERS))
    ingest.add_argument("file", type=Path)

    sim = sub.add_parser("simulate", help="write synthetic alerts in each vendor format")
    sim.add_argument("--out", type=Path, required=True)
    sim.add_argument("--start", help="ISO timestamp of the first alert (default: 6 hours ago)")
    sim.add_argument("--seed", type=int, default=7)

    triage = sub.add_parser("triage", help="correlate, investigate and propose response actions")
    triage.add_argument("--lookback", default="24h")
    triage.add_argument("--now", help="ISO timestamp treated as the current time")
    triage.add_argument(
        "--fail-on",
        choices=["P1", "P2", "P3"],
        help="exit 1 if an open incident of this priority or higher exists",
    )

    incidents = sub.add_parser("incidents", help="list and inspect incidents").add_subparsers(
        dest="incidents_command", required=True
    )
    listing = incidents.add_parser("list")
    listing.add_argument("--status", choices=_STATUSES)
    show = incidents.add_parser("show")
    show.add_argument("id")
    show.add_argument("--format", default="md", help=f"comma list from: {', '.join(FORMATS)}")
    show.add_argument(
        "--out", type=Path, help="write the report(s) to this directory instead of printing"
    )
    status = incidents.add_parser("status")
    status.add_argument("id")
    status.add_argument("status", choices=_STATUSES)
    status.add_argument("--actor", required=True)
    status.add_argument("--assignee")

    actions = sub.add_parser(
        "actions", help="review, approve and execute proposed actions"
    ).add_subparsers(dest="actions_command", required=True)
    alist = actions.add_parser("list")
    alist.add_argument("--incident")
    alist.add_argument("--status")
    approve = actions.add_parser("approve")
    approve.add_argument("id")
    approve.add_argument("--approver", required=True)
    approve.add_argument("--note", default="")
    reject = actions.add_parser("reject")
    reject.add_argument("id")
    reject.add_argument("--approver", required=True)
    reject.add_argument("--reason", required=True)
    execute = actions.add_parser("execute")
    execute.add_argument("id")
    execute.add_argument("--executor", required=True)

    audit = sub.add_parser("audit", help="show or verify the audit log")
    audit.add_argument("--verify", action="store_true")
    audit.add_argument("--limit", type=int, default=50)
    return parser


def _cmd_triage(args: argparse.Namespace, service: IRService) -> int:
    result = service.triage(
        lookback=parse_duration(args.lookback), now=_parse_time(args.now) if args.now else None
    )
    print(
        f"Considered {result.alerts_considered} alerts, {len(result.incidents)} incidents, {result.new_actions} new proposed actions "
        f"({result.details['suppressed_singletons']} low-severity singletons suppressed)."
    )
    for i in result.incidents:
        print(f"{i.id}  {i.priority}  risk {i.risk_score:>3}  {i.status:<13} {i.title}")
    if args.fail_on:
        limit = int(args.fail_on[1])
        if any(
            int(i.priority[1]) <= limit and i.status != "closed" for i in service.incidents.list()
        ):
            return 1
    return 0


def _cmd_incidents(args: argparse.Namespace, service: IRService) -> int:
    cmd = args.incidents_command
    if cmd == "list":
        rows = service.incidents.list(args.status)
        for i in rows:
            print(
                f"{i.id}  {i.priority}  risk {i.risk_score:>3}  {i.status:<13} {len(i.alert_ids):>3} alerts  {i.title}"
            )
        if not rows:
            print("no incidents")
    elif cmd == "show":
        formats = [f.strip() for f in args.format.split(",") if f.strip()]
        incident, actions = service.get_incident(args.id)
        if args.out:
            for path in write_report(incident, actions, args.out, formats):
                print(f"Wrote {path}")
        else:
            for fmt in formats:
                print(render(incident, actions, fmt))
    else:
        updated = service.set_status(args.id, args.status, args.actor, args.assignee)
        print(f"{updated.id} is now {updated.status}")
    return 0


def _cmd_actions(args: argparse.Namespace, service: IRService) -> int:
    cmd = args.actions_command
    if cmd == "list":
        if args.incident:
            incident, _ = service.get_incident(args.incident)
            rows = service.actions.for_incident(incident.id)
        else:
            rows = service.actions.all(args.status)
        for a in rows:
            need = "senior" if a.requires_senior else "required" if a.requires_approval else "none"
            print(
                f"{a.id}  {a.incident_id}  {a.status:<16} {a.urgency:<9} impact={a.impact:<6} approval={need:<8} {a.type} {a.target}"
            )
        if not rows:
            print("no actions")
        return 0
    action = service.actions.resolve_prefix(args.id)
    if cmd == "approve":
        done = service.action_service.approve(action.id, args.approver, args.note)
        print(f"{done.id} approved by {done.approved_by}")
    elif cmd == "reject":
        done = service.action_service.reject(action.id, args.approver, args.reason)
        print(f"{done.id} rejected")
    else:
        done = service.action_service.execute(action.id, args.executor)
        print(f"{done.id} {done.status}: {done.result}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = _parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    try:
        settings = Settings()
        if args.db:
            settings = settings.model_copy(update={"db_path": args.db})
        configure_logging(settings.log_level, json_output=settings.log_json)

        if args.command == "simulate":
            start = (
                _parse_time(args.start)
                if args.start
                else datetime.now(timezone.utc).replace(microsecond=0) - parse_duration("6h")
            )
            for path in write_records(simulate(start=start, seed=args.seed), args.out):
                print(f"wrote {path}")
            return 0

        with build_service(settings) as service:
            if args.command == "ingest":
                print(service.ingest_file(args.source, args.file).model_dump_json(indent=2))
                return 0
            if args.command == "triage":
                return _cmd_triage(args, service)
            if args.command == "incidents":
                return _cmd_incidents(args, service)
            if args.command == "actions":
                return _cmd_actions(args, service)
            entries = service.audit.entries(args.limit)
            if args.verify:
                ok, reason = service.audit.verify()
                print("audit log verified: chain intact" if ok else f"AUDIT LOG TAMPERED: {reason}")
                return 0 if ok else 1
            for e in entries:
                print(
                    f"{e.id:>5}  {e.timestamp.isoformat()}  {e.actor:<14} {e.action:<24} {e.subject}  {e.detail}"
                )
            return 0
    except (SocagentError, ValidationError) as exc:
        print(f"error: {redact(str(exc))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
