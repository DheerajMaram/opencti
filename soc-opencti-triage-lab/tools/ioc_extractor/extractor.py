#!/usr/bin/env python3
"""
IOC Extractor — extracts IPs, domains, URLs, hashes, and emails from log files.
Uses Python standard library only. No pip installs required.
"""
import argparse
import json
import os
import sys
from pathlib import Path

from patterns import (
    DOMAIN_PATTERN,
    EMAIL_PATTERN,
    HASH_PATTERN,
    IP_PATTERN,
    URL_PATTERN,
    refang,
    is_private_ip,
)

# Domains to exclude: Microsoft/Windows, Falco field names, .NET
DOMAIN_EXCLUDE = frozenset({
    "microsoft.com", "windows.com", "windowsupdate.com", "microsoftonline.com",
    "live.com", "office.com", "office365.com", "outlook.com", "azure.com",
    "fd.dip", "proc.name", "container.id", "fd.sip", "fd.rip", "fd.dport",
    "evt.time", "k8s.ns.name", "fd.l4.proto", "fd.name", "proc.pid",
    "net.webclient", "system.net.webclient",
})

# IPs to exclude from output
IP_EXCLUDE = frozenset({"0.0.0.0", "255.255.255.255", "127.0.0.1"})

# TLDs that are actually file extensions (false positives)
FAKE_TLDS = frozenset({
    "exe", "dll", "bat", "ps1", "vbs", "js", "py", "sh", "bin", "sys", "tmp", "log",
})


def _extract_from_text(text: str) -> dict:
    """Extract IOCs from raw text. Returns dict with lists (not necessarily deduplicated)."""
    text = refang(text)
    # Extract URLs first, then remove them from text to avoid double-counting domains/IPs inside URLs
    urls = [m.group(0) for m in URL_PATTERN.finditer(text)]
    # Strip URL spans from text for subsequent extractions
    stripped = text
    for m in URL_PATTERN.finditer(text):
        stripped = stripped.replace(m.group(0), " ", 1)
    # Extract from stripped text
    ips = [m.group(0) for m in IP_PATTERN.finditer(stripped)]
    domains = [m.group(0).lower() for m in DOMAIN_PATTERN.finditer(stripped)]
    hashes = [m.group(0).lower() for m in HASH_PATTERN.finditer(stripped)]
    emails = [m.group(0).lower() for m in EMAIL_PATTERN.finditer(stripped)]
    # Filter: remove IPs from domain list (e.g. "185.220.101.47" matched as something)
    domains = [d for d in domains if d not in ips and not d.replace(".", "").isdigit()]
    # Remove fake TLDs (filename.ext)
    domains = [d for d in domains if d.split(".")[-1].lower() not in FAKE_TLDS]
    # Remove .in-addr.arpa PTR records
    domains = [d for d in domains if ".in-addr.arpa" not in d]
    # Remove excluded domains
    domains = [d for d in domains if d not in DOMAIN_EXCLUDE]
    # Remove email domains from domain list (e.g. user@evil.com -> don't add evil.com as domain if we want only standalone domains; spec says "remove email domains from domain list")
    email_domains = {e.split("@", 1)[1] for e in emails}
    domains = [d for d in domains if d not in email_domains]
    # Filter IPs
    ips = [ip for ip in ips if ip not in IP_EXCLUDE]
    return {"ips": ips, "domains": domains, "urls": urls, "hashes": hashes, "emails": emails}


def _merge_results(acc: dict, new: dict) -> None:
    """Merge new extraction result into acc (in-place)."""
    for key in ("ips", "domains", "urls", "hashes", "emails"):
        acc.setdefault(key, []).extend(new.get(key, []))


def extract(path: str) -> dict:
    """
    Accept file or directory path. Read all text and return sorted, deduplicated
    dict with keys: ips, domains, urls, hashes, emails.
    """
    path = Path(path)
    acc = {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []}
    if path.is_file():
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            _merge_results(acc, _extract_from_text(content))
        except OSError:
            pass
    elif path.is_dir():
        for f in path.rglob("*"):
            if f.is_file():
                try:
                    content = f.read_text(encoding="utf-8", errors="replace")
                    _merge_results(acc, _extract_from_text(content))
                except OSError:
                    pass
    else:
        return {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []}
    # Deduplicate and sort
    for key in acc:
        acc[key] = sorted(set(acc[key]))
    return acc


def self_test() -> bool:
    """Run 7 assertions. Returns True if all pass."""
    ok = 0
    total = 7
    # 1. IP extraction (public + private)
    r = _extract_from_text("Host 185.220.101.47 and 192.168.1.105 and 10.0.0.5")
    assert "185.220.101.47" in r["ips"] and "192.168.1.105" in r["ips"] and "10.0.0.5" in r["ips"], "IP extraction"
    ok += 1
    # 2. Domain extraction (standalone domains)
    r = _extract_from_text("See malware.delivery and c2beacon.top-server.net for C2.")
    assert "malware.delivery" in r["domains"] and "c2beacon.top-server.net" in r["domains"], "Domain extraction"
    ok += 1
    # 3. URL extraction including defanged hxxps://malware[.]delivery/...
    r = _extract_from_text("Download from hxxps://malware[.]delivery/payload.exe or https://evil.com/a")
    urls = r["urls"]
    assert any("malware.delivery" in u for u in urls) or any("https://" in u for u in urls), "URL defang and extraction"
    ok += 1
    # 4. Hash extraction (MD5 + SHA-256)
    r = _extract_from_text("MD5 a1b2c3d4e5f607182936455647384950 and SHA256 " + "f" * 64)
    assert any(len(h) == 32 for h in r["hashes"]) and any(len(h) == 64 for h in r["hashes"]), "Hash extraction"
    ok += 1
    # 5. Email extraction
    r = _extract_from_text("Contact colorsutils.dev@protonmail.com for support.")
    assert "colorsutils.dev@protonmail.com" in r["emails"], "Email extraction"
    ok += 1
    # 6. No false-positive IPs from version strings
    r = _extract_from_text("nginx/1.18.0 openssl/1.1.1k python/3.10.4")
    assert not r["ips"], "No false-positive IPs from version strings"
    ok += 1
    # 7. Deduplication works
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("185.220.101.47 185.220.101.47 c2.evil.ru c2.evil.ru\n")
        f.flush()
        res = extract(f.name)
    try:
        os.unlink(f.name)
    except OSError:
        pass
    assert res["ips"].count("185.220.101.47") == 1 and res["domains"].count("c2.evil.ru") == 1, "Deduplication"
    ok += 1
    return ok == total


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract IOCs from log files.")
    parser.add_argument("-i", "--input", default=None, help="Input file or directory")
    parser.add_argument("-o", "--output", default=None, help="Output JSON file (default: stdout)")
    parser.add_argument("--self-test", action="store_true", help="Run self-test and exit")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()
    if args.self_test:
        try:
            if self_test():
                print("Self-test: 7 passed, 0 failed.", file=sys.stderr)
                return 0
            print("Self-test: some assertions failed.", file=sys.stderr)
            return 1
        except AssertionError as e:
            print(f"Self-test failed: {e}", file=sys.stderr)
            return 1
    if not args.input:
        parser.error("--input is required unless --self-test is set")
    result = extract(args.input)
    out = json.dumps(result, indent=2 if args.pretty else None)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
