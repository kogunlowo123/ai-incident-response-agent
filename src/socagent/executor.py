"""Action lifecycle: approval, rejection and (guarded) execution, all audited.

Rules enforced here:

* an action must be approved by a named approver before it can run;
* approvers are checked against the policy, and high-impact actions need a senior approver;
* approvals expire, so a stale approval cannot be used later;
* dependencies (for example a forensic snapshot before isolation) must have run first;
* protected targets are re-checked at execution time;
* execution is a dry run unless live mode and a connector are configured;
* every transition is recorded in the tamper-evident audit log in the same transaction.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Protocol, runtime_checkable

from pydantic import SecretStr

from socagent.config import Policy
from socagent.db import ActionStore, AuditLog, Database
from socagent.errors import ActionError, ProviderError
from socagent.models import Action
from socagent.providers.http import JsonClient
from socagent.security import redact

_POLICY_ACTOR = "policy"


@runtime_checkable
class Connector(Protocol):
    """Carries out an approved action against a real system (SOAR, EDR, identity provider)."""

    def execute(self, action: Action, *, approved_by: str, executed_by: str) -> str:
        """Perform ``action`` and return a short result. Raise :class:`ActionError` on failure."""


class DryRunConnector:
    """Performs nothing; reports what would have happened."""

    def execute(self, action: Action, *, approved_by: str, executed_by: str) -> str:
        return f"dry run: would {action.type.replace('_', ' ')} {action.target}"


class WebhookConnector:
    """Posts the approved action to a SOAR or automation webhook, which performs it.

    The URL is a secret (webhook URLs usually embed a token). The payload names the action, target,
    incident and the humans who approved and triggered it.
    """

    def __init__(self, client: JsonClient, url: SecretStr) -> None:
        self._client = client
        self._url = url

    def execute(self, action: Action, *, approved_by: str, executed_by: str) -> str:
        payload = {
            "action": action.type,
            "target": action.target,
            "incident": action.incident_id,
            "action_id": action.id,
            "approved_by": approved_by,
            "executed_by": executed_by,
        }
        try:
            self._client.request("POST", self._url.get_secret_value(), json=payload)
        except ProviderError as exc:
            raise ActionError(f"connector failed: {redact(str(exc))[:200]}") from exc
        return f"sent to connector: {action.type} {action.target}"


class ActionService:
    """State machine and audit trail for response actions."""

    def __init__(
        self,
        db: Database,
        actions: ActionStore,
        audit: AuditLog,
        policy: Policy,
        connector: Connector,
        *,
        mode: str = "dry_run",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._db = db
        self._actions = actions
        self._audit = audit
        self._policy = policy
        self._connector = connector
        self._mode = mode
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # -- recommendations ---------------------------------------------------------------------------

    def save_recommendations(self, actions: list[Action]) -> int:
        """Store proposals. Existing actions keep their approval state; returns how many are new."""
        created = 0
        with self._db.transaction():
            for action in actions:
                existing = self._actions.get(action.id)
                if existing is None:
                    self._actions.save(action)
                    self._audit.append(
                        _POLICY_ACTOR,
                        "action.propose",
                        action.id,
                        f"{action.type} {action.target} ({action.status})",
                    )
                    created += 1
                else:
                    self._actions.save(
                        action.model_copy(
                            update={
                                "status": existing.status,
                                "approved_by": existing.approved_by,
                                "approved_at": existing.approved_at,
                                "executed_by": existing.executed_by,
                                "executed_at": existing.executed_at,
                                "result": existing.result,
                            }
                        )
                    )
        return created

    # -- transitions -------------------------------------------------------------------------------

    def _load(self, action_id: str) -> Action:
        action = self._actions.get(action_id)
        if action is None:
            raise ActionError(f"action {action_id} not found")
        return action

    def _check_approver(self, action: Action, approver: str) -> None:
        if not approver.strip():
            raise ActionError("an approver name is required")
        if (
            self._policy.approvers
            and approver not in self._policy.approvers
            and approver not in self._policy.senior_approvers
        ):
            raise ActionError(f"{approver} is not an authorised approver")
        if action.requires_senior and approver not in self._policy.senior_approvers:
            raise ActionError(
                "this action is high impact and needs a senior approver"
                + ("" if self._policy.senior_approvers else "; none are configured in the policy")
            )

    def approve(self, action_id: str, approver: str, note: str = "") -> Action:
        """Approve a pending action.

        Raises:
            ActionError: If the action is not pending, is protected, or the approver is not permitted.
        """
        action = self._load(action_id)
        if action.status == "manual_only":
            raise ActionError("this target is protected by policy; handle it manually")
        if action.status != "pending_approval":
            raise ActionError(f"action is {action.status}, not pending approval")
        self._check_approver(action, approver)
        updated = action.model_copy(
            update={"status": "approved", "approved_by": approver, "approved_at": self._clock()}
        )
        with self._db.transaction():
            self._actions.save(updated)
            self._audit.append(
                approver,
                "action.approve",
                action.id,
                f"{action.type} {action.target}. {note}".strip(),
            )
        return updated

    def reject(self, action_id: str, approver: str, reason: str) -> Action:
        """Reject a pending or approved action."""
        action = self._load(action_id)
        if action.status not in {"pending_approval", "approved"}:
            raise ActionError(f"action is {action.status} and cannot be rejected")
        self._check_approver(action, approver)
        updated = action.model_copy(update={"status": "rejected", "result": reason[:300]})
        with self._db.transaction():
            self._actions.save(updated)
            self._audit.append(approver, "action.reject", action.id, reason[:300])
        return updated

    def execute(self, action_id: str, executor: str) -> Action:
        """Execute an approved action (dry run unless live mode is configured).

        Raises:
            ActionError: If the action is unapproved, expired, has unmet dependencies or is protected.
        """
        action = self._load(action_id)
        if not executor.strip():
            raise ActionError("an executor name is required")
        if action.status != "approved":
            raise ActionError(f"action is {action.status}; it must be approved before it can run")
        if self._is_protected(action):
            self._record(
                action.model_copy(update={"status": "manual_only"}),
                executor,
                "action.blocked",
                "target became protected",
            )
            raise ActionError("this target is protected by policy; handle it manually")
        if action.approved_by != _POLICY_ACTOR and action.approved_at is not None:
            age = self._clock() - action.approved_at
            if age > timedelta(minutes=self._policy.approval_ttl_minutes):
                self._record(
                    action.model_copy(update={"status": "expired"}),
                    executor,
                    "action.expire",
                    f"approval is {int(age.total_seconds() // 60)} minutes old",
                )
                raise ActionError("the approval has expired; approve the action again")
        unmet = [
            d
            for d in action.depends_on
            if (dep := self._actions.get(d)) is not None and dep.status != "executed"
        ]
        if unmet:
            raise ActionError(f"depends on actions that have not run: {', '.join(unmet)}")

        self._audit.append(
            executor,
            "action.execute.start",
            action.id,
            f"mode={self._mode} {action.type} {action.target}",
        )
        try:
            result = self._connector.execute(
                action, approved_by=action.approved_by, executed_by=executor
            )
        except ActionError as exc:
            failed = action.model_copy(
                update={"status": "failed", "result": str(exc)[:300], "executed_by": executor}
            )
            self._record(failed, executor, "action.execute.failed", str(exc)[:300])
            raise
        done = action.model_copy(
            update={
                "status": "executed",
                "executed_by": executor,
                "executed_at": self._clock(),
                "result": result,
            }
        )
        self._record(done, executor, "action.execute.done", result)
        return done

    # -- helpers -----------------------------------------------------------------------------------

    def _record(self, action: Action, actor: str, event: str, detail: str) -> None:
        with self._db.transaction():
            self._actions.save(action)
            self._audit.append(actor, event, action.id, detail)

    def _is_protected(self, action: Action) -> bool:
        p = self._policy
        return (
            (
                action.type in {"isolate_host", "snapshot_host"}
                and action.target in p.protected_hosts
            )
            or (
                action.type in {"disable_user", "reset_credentials", "revoke_sessions"}
                and action.target in p.protected_users
            )
            or (action.type == "block_ip" and action.target in p.protected_ips)
        )
