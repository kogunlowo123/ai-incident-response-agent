"""Correlation agent: groups alerts that share observables within a time window into incidents."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import timedelta
from itertools import pairwise

from socagent.config import Policy
from socagent.models import Alert


class _UnionFind:
    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, item: int) -> int:
        while self._parent[item] != item:
            self._parent[item] = self._parent[self._parent[item]]
            item = self._parent[item]
        return item

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[max(ra, rb)] = min(ra, rb)


def incident_id_for(alerts: list[Alert]) -> str:
    """Stable id derived from the earliest alert of the group."""
    earliest = min(alerts, key=lambda a: (a.timestamp, a.id))
    return "INC-" + hashlib.sha256(earliest.id.encode()).hexdigest()[:8].upper()


class CorrelationAgent:
    """Links alerts through shared entities, ignoring noise and over-connected hubs.

    Two alerts are linked when they share an observable and are no more than the correlation window
    apart (chained, so a long attack with steady activity stays together). Observables that appear in
    more than ``max_entity_degree`` alerts, such as a scanner address or a shared service account, are
    hubs and are not used for linking, because they would merge unrelated activity into one incident.
    """

    def __init__(self, policy: Policy) -> None:
        self._window = timedelta(minutes=policy.correlation_window_minutes)
        self._max_degree = policy.max_entity_degree
        self._noise = {f"user:{u}" for u in policy.noise_users} | {
            f"ip:{i}" for i in policy.noise_ips
        }

    def hubs(self, alerts: list[Alert]) -> set[str]:
        """Entity keys too common to link on."""
        counts: dict[str, int] = defaultdict(int)
        for alert in alerts:
            for key in alert.entity_keys():
                counts[key] += 1
        return {key for key, n in counts.items() if n > self._max_degree}

    def correlate(self, alerts: list[Alert]) -> list[list[Alert]]:
        """Return groups of alerts, each sorted by time, ordered by their first alert."""
        ordered = sorted(alerts, key=lambda a: (a.timestamp, a.id))
        blocked = self._noise | self.hubs(ordered)
        by_entity: dict[str, list[int]] = defaultdict(list)
        for index, alert in enumerate(ordered):
            for key in alert.entity_keys() - blocked:
                by_entity[key].append(index)

        groups = _UnionFind(len(ordered))
        for indexes in by_entity.values():
            for earlier, later in pairwise(indexes):
                if ordered[later].timestamp - ordered[earlier].timestamp <= self._window:
                    groups.union(earlier, later)

        buckets: dict[int, list[Alert]] = defaultdict(list)
        for index, alert in enumerate(ordered):
            buckets[groups.find(index)].append(alert)
        return sorted(buckets.values(), key=lambda g: (g[0].timestamp, g[0].id))
