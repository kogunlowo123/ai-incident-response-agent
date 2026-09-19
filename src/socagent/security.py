"""Secret redaction and observable validation."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

REDACTION = "[REDACTED]"

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{16,}"),
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END "
        r"(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    re.compile(
        r"(?i)(?:^|[\s\"'/-])(?:password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]?"
        r"(?!\[REDACTED\])[^\s'\",;]{4,}"
    ),
)
_ARG_SECRET = re.compile(
    r"(?i)(?P<flag>(?:--?)(?:password|passwd|pwd|pass|token|secret|apikey|api-key))(?P<sep>[\s=:]+)"
    r"(?P<value>(?!\[REDACTED\])[^\s'\"]+)"
)
_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_HASH_LENGTHS = {32, 40, 64}
_EMAIL = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$")


def redact(text: str) -> str:
    """Replace credential-shaped substrings, including secrets passed as command-line arguments."""
    text = _ARG_SECRET.sub(lambda m: f"{m['flag']}{m['sep']}{REDACTION}", text)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(_replace, text)
    return text


def _replace(match: re.Match[str]) -> str:
    value = match.group(0)
    key = re.search(r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]", value)
    if key:
        prefix = value[: key.end()]
        return f"{prefix} {REDACTION}"
    return REDACTION


def normalize_ip(value: str) -> str | None:
    """Return the canonical form of an IP address, or ``None`` if invalid."""
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def is_private_ip(value: str) -> bool:
    """True for internal addresses: RFC 1918, loopback, link-local and IPv6 unique-local.

    Documentation and benchmarking ranges count as external here, unlike ``ipaddress.is_private``,
    because blocking decisions should only exclude the organisation's own address space.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in network for network in _INTERNAL_NETWORKS if network.version == ip.version)


def normalize_hash(value: str) -> str | None:
    """Lowercase a hex digest of a plausible length (MD5, SHA-1, SHA-256), else ``None``."""
    candidate = value.strip().lower()
    if len(candidate) in _HASH_LENGTHS and re.fullmatch(r"[0-9a-f]+", candidate):
        return candidate
    return None


def normalize_domain(value: str) -> str | None:
    """Lowercase a DNS name without a trailing dot, or ``None`` if it is not a valid domain."""
    candidate = value.strip().lower().rstrip(".")
    return candidate if _DOMAIN.match(candidate) else None


def normalize_host(value: str) -> str | None:
    """Lowercase a hostname, or ``None`` if it is not plausible."""
    candidate = value.strip().lower().rstrip(".")
    return candidate if _HOSTNAME.match(candidate) else None


def normalize_user(value: str) -> str | None:
    """Reduce ``DOMAIN\\alice``, ``alice@corp.com`` and ``alice`` to the same lowercase ``alice``."""
    candidate = value.strip().lower()
    if "\\" in candidate:
        candidate = candidate.rsplit("\\", 1)[1]
    if "@" in candidate:
        candidate = candidate.split("@", 1)[0]
    return candidate if candidate and len(candidate) <= 256 else None


def normalize_email(value: str) -> str | None:
    """Lowercase an email address, or ``None`` if it is malformed."""
    candidate = value.strip().lower()
    return candidate if _EMAIL.match(candidate) else None


def url_domain(url: str) -> str | None:
    """Domain of ``url`` if it has a valid DNS host, else ``None``."""
    try:
        host = urlsplit(url if "//" in url else f"//{url}").hostname
    except ValueError:
        return None
    return normalize_domain(host) if host else None
