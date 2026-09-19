"""Exception hierarchy for the socagent package."""

from __future__ import annotations


class SocagentError(Exception):
    """Base class for all errors raised deliberately by socagent."""


class ConfigurationError(SocagentError):
    """Raised when settings or configuration files are missing, inconsistent or invalid."""


class IngestError(SocagentError):
    """Raised when alerts cannot be read."""


class StoreError(SocagentError):
    """Raised when the database cannot be read or written."""


class ActionError(SocagentError):
    """Raised when a response action violates policy or is in the wrong state."""


class ReportError(SocagentError):
    """Raised when a report cannot be rendered or written."""


class ProviderError(SocagentError):
    """Raised when an upstream provider returns a non-retryable failure."""


class TransientProviderError(ProviderError):
    """Raised for retryable upstream failures such as rate limits or 5xx responses."""
