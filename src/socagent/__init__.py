"""Incident response agent: normalise alerts, correlate, investigate, propose and audit containment."""

from socagent._version import __version__
from socagent.config import Settings
from socagent.container import build_service
from socagent.models import Action, Alert, Incident, Severity
from socagent.service import IRService

__all__ = [
    "Action",
    "Alert",
    "IRService",
    "Incident",
    "Settings",
    "Severity",
    "__version__",
    "build_service",
]
