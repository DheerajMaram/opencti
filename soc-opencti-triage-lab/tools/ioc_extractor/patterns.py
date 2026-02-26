"""
Compiled regex patterns for IOC extraction from log and text content.
Uses Python standard library only (re).
"""
import re

# Valid IPv4, word-boundary anchored
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# FQDNs: 2+ labels, TLD 2-24 chars, up to 10 middle label repetitions (allows malware.delivery)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){0,10}"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,24}\b"
)

# http/https URLs
URL_PATTERN = re.compile(
    r"\bhttps?://[^\s<>\"')\]]+",
    re.IGNORECASE
)

# MD5 (32), SHA-1 (40), SHA-256 (64), SHA-512 (128) hex
HASH_PATTERN = re.compile(
    r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})\b"
)

# Standard email addresses
EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

# CVE-YYYY-NNNNN (NNNNN can be 4+ digits)
CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,}\b",
    re.IGNORECASE
)


def refang(text: str) -> str:
    """Convert defanged indicators to normal form: hxxp -> http, [.] / (.) -> ."""
    if not text:
        return text
    t = text.replace("hxxp://", "http://").replace("hxxps://", "https://")
    t = re.sub(r"\[\.\]", ".", t)
    t = re.sub(r"\(\.\)", ".", t)
    return t


def is_private_ip(ip: str) -> bool:
    """Check if IP is RFC-1918, loopback, or link-local."""
    if not ip or ip.count(".") != 3:
        return False
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return False
        # Loopback
        if parts[0] == 127:
            return True
        # Link-local 169.254.0.0/16
        if parts[0] == 169 and parts[1] == 254:
            return True
        # RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        return False
    except (ValueError, IndexError):
        return False
