#!/usr/bin/env python3
"""
Push extracted IOCs from a case directory into OpenCTI as a Report with observables.
Uses pycti; load config from YAML. Auto-discovers iocs.json or expected-iocs.json
and alert.json for title/description.
"""
import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

import yaml

try:
    from pycti import OpenCTIApiClient
except ImportError:
    print("pycti is required. Install with: pip install pycti", file=sys.stderr)
    sys.exit(1)

from typing import Optional


def load_config(config_path: str) -> dict:
    """Load YAML config; expect opencti.url and opencti.token."""
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_or_create_label(client: OpenCTIApiClient, value: str, color: str = "#ff0000") -> str:
    """Return label id for value; create with color if not exists."""
    existing = client.label.read(
        filters={
            "mode": "and",
            "filters": [{"key": "value", "values": [value]}],
            "filterGroups": [],
        }
    )
    if existing:
        return existing["id"]
    created = client.label.create(value=value, color=color)
    return created["id"]


def hash_type_by_length(h: str) -> str:
    """Return OpenCTI hash type: MD5, SHA-1, SHA-256, SHA-512 by hex length."""
    n = len(h)
    if n == 32:
        return "MD5"
    if n == 40:
        return "SHA-1"
    if n == 64:
        return "SHA-256"
    if n == 128:
        return "SHA-512"
    return "SHA-256"


def run(
    config_path: str,
    case_dir: str,
    iocs_path: Optional[str],
    title: Optional[str],
    description: Optional[str],
    confidence: int,
    label_value: str,
) -> int:
    base = Path(case_dir)
    if not base.is_dir():
        print(f"Case directory not found: {case_dir}", file=sys.stderr)
        return 1
    config = load_config(config_path)
    opencti_cfg = config.get("opencti", {})
    url = opencti_cfg.get("url")
    token = opencti_cfg.get("token")
    if not url or not token:
        print("Config must set opencti.url and opencti.token", file=sys.stderr)
        return 1
    iocs_file = Path(iocs_path) if iocs_path else None
    if not iocs_file:
        for name in ("iocs.json", "expected-iocs.json"):
            p = base / name
            if p.is_file():
                iocs_file = p
                break
    if not iocs_file or not iocs_file.is_file():
        print(f"No iocs.json or expected-iocs.json in {base}", file=sys.stderr)
        return 1
    with open(iocs_file, "r", encoding="utf-8") as f:
        iocs = json.load(f)
    alert_file = base / "alert.json"
    if alert_file.is_file() and (title is None or description is None):
        with open(alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)
        if title is None:
            title = alert.get("name") or alert.get("title") or alert.get("rule", {}).get("name") or "SOC-LAB Case"
        if description is None:
            description = alert.get("description") or alert.get("rule", {}).get("description") or ""
    if title is None:
        title = "SOC-LAB Case"
    if description is None:
        description = ""
    client = OpenCTIApiClient(url=url, token=token)
    label_id = get_or_create_label(client, label_value)
    report_name = f"SOC-LAB {title}"
    published = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    report = client.report.create(
        name=report_name,
        description=description,
        published=published,
        confidence=confidence,
        objectLabel=[label_id],
    )
    if not report:
        print("Failed to create report", file=sys.stderr)
        return 1
    report_id = report["id"]
    observables_created = 0
    for ip in iocs.get("ips", []):
        obs = client.stix_cyber_observable.create(
            observableData={"type": "ipv4-addr", "value": ip},
            objectLabel=[label_id],
        )
        if obs:
            client.report.add_stix_object_or_stix_relationship(
                id=report_id,
                stixObjectOrStixRelationshipId=obs["id"],
            )
            client.stix_cyber_observable.add_label(id=obs["id"], label_id=label_id)
            observables_created += 1
    for domain in iocs.get("domains", []):
        obs = client.stix_cyber_observable.create(
            observableData={"type": "domain-name", "value": domain},
            objectLabel=[label_id],
        )
        if obs:
            client.report.add_stix_object_or_stix_relationship(
                id=report_id,
                stixObjectOrStixRelationshipId=obs["id"],
            )
            client.stix_cyber_observable.add_label(id=obs["id"], label_id=label_id)
            observables_created += 1
    for url_val in iocs.get("urls", []):
        obs = client.stix_cyber_observable.create(
            observableData={"type": "url", "value": url_val},
            objectLabel=[label_id],
        )
        if obs:
            client.report.add_stix_object_or_stix_relationship(
                id=report_id,
                stixObjectOrStixRelationshipId=obs["id"],
            )
            client.stix_cyber_observable.add_label(id=obs["id"], label_id=label_id)
            observables_created += 1
    for h in iocs.get("hashes", []):
        ht = hash_type_by_length(h)
        obs = client.stix_cyber_observable.create(
            observableData={"type": "file", "hashes": {ht: h}},
            objectLabel=[label_id],
        )
        if obs:
            client.report.add_stix_object_or_stix_relationship(
                id=report_id,
                stixObjectOrStixRelationshipId=obs["id"],
            )
            client.stix_cyber_observable.add_label(id=obs["id"], label_id=label_id)
            observables_created += 1
    for email in iocs.get("emails", []):
        obs = client.stix_cyber_observable.create(
            observableData={"type": "email-addr", "value": email},
            objectLabel=[label_id],
        )
        if obs:
            client.report.add_stix_object_or_stix_relationship(
                id=report_id,
                stixObjectOrStixRelationshipId=obs["id"],
            )
            client.stix_cyber_observable.add_label(id=obs["id"], label_id=label_id)
            observables_created += 1
    print(f"Report created: {report_id}. Observables added: {observables_created}.", file=sys.stderr)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Push case IOCs to OpenCTI as a Report.")
    parser.add_argument("--config", "-c", default="config.yml", help="Path to config YAML")
    parser.add_argument("--case", default=None, help="Case directory (e.g. scenarios/case-01)")
    parser.add_argument("--iocs", default=None, help="Path to iocs.json (default: case/iocs.json or expected-iocs.json)")
    parser.add_argument("--title", default=None, help="Report title (overrides alert.json)")
    parser.add_argument("--description", default=None, help="Report description (overrides alert.json)")
    parser.add_argument("--confidence", type=int, default=None, help="Confidence 0-100 (default from config)")
    parser.add_argument("--label", default=None, help="Label value (default from config)")
    args = parser.parse_args()
    config_path = args.config
    if not os.path.isfile(config_path):
        print(f"Config not found: {config_path}", file=sys.stderr)
        return 1
    config = load_config(config_path)
    defaults = config.get("defaults", {})
    confidence = args.confidence if args.confidence is not None else defaults.get("confidence", 75)
    label_value = args.label or defaults.get("label", "SOC-LAB")
    if not args.case:
        parser.error("--case is required")
    return run(
        config_path=config_path,
        case_dir=args.case,
        iocs_path=args.iocs,
        title=args.title,
        description=args.description,
        confidence=confidence,
        label_value=label_value,
    )


if __name__ == "__main__":
    sys.exit(main())
