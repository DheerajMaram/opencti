# IOC Extractor

Extracts Indicators of Compromise (IPs, domains, URLs, hashes, emails) from log files. Uses **Python standard library only** — no pip installs required.

## Usage

```bash
# Self-test (7 assertions)
python3 extractor.py --self-test

# Extract from a directory (e.g. scenario logs)
python3 extractor.py -i ../../scenarios/case-01/logs/

# Extract from a single file, write to JSON
python3 extractor.py -i /path/to/sysmon.txt -o iocs.json --pretty
```

## Output schema

```json
{
  "ips": [],
  "domains": [],
  "urls": [],
  "hashes": [],
  "emails": []
}
```

All lists are sorted and deduplicated. Defanged indicators (e.g. `hxxp://`, `[.]`) are normalized before extraction.
