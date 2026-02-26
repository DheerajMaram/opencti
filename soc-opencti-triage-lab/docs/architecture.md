# SOC OpenCTI Triage Lab — Architecture

## High-level data flow

```
Scenario Logs (Sysmon, Zeek)  →  IOC Extractor  →  iocs.json
                                                                  ↘
                                                                     OpenCTI Ingestion Client  →  OpenCTI Platform
                                                                  ↗                                    ├── Elasticsearch
                                                                  expected-iocs.json (or iocs.json)    ├── Redis
                                                                                                        ├── MinIO
                                                                                                        └── RabbitMQ → Workers (3×)
```

## Data flow steps

1. **Simulate** — Scenario directories (`case-01`, `case-02`, `case-03`) contain synthetic alert and log data (Sysmon, Zeek, Falco/audit, CloudTrail-style).
2. **Extract** — The IOC extractor (`tools/ioc_extractor/extractor.py`) reads log files and outputs a normalized JSON with `ips`, `domains`, `urls`, `hashes`, `emails`.
3. **Ingest** — The OpenCTI client (`tools/opencti_client/push_observables.py`) loads IOCs (from `iocs.json` or `expected-iocs.json`), creates a Report, creates STIX cyber observables for each IOC, links them to the report, and applies the SOC-LAB label.
4. **Pivot** — Analysts use the OpenCTI UI to search observables, view reports, and correlate across cases.
5. **Report** — Case reports in `docs/case-reports/` document the attack narrative, evidence, IOCs, ATT&CK mapping, and response.

## Technology stack

| Component            | Role                                      |
|---------------------|-------------------------------------------|
| OpenCTI 6.2.x       | CTI platform (reports, observables, graph)|
| Elasticsearch 8.12  | Search and indexing                       |
| Redis 7.2            | Caching / streams                         |
| RabbitMQ 3.13        | Message queue for workers                 |
| MinIO                | S3-compatible object store                |
| Python 3             | IOC extractor (stdlib), OpenCTI client (pycti, PyYAML) |
| Docker Compose       | Single-node OpenCTI + dependencies        |

## STIX 2 object model (observables)

| IOC type | OpenCTI / STIX type   | Example observableData                          |
|----------|------------------------|-------------------------------------------------|
| IPv4     | ipv4-addr              | `{"type": "ipv4-addr", "value": "1.2.3.4"}`    |
| Domain   | domain-name            | `{"type": "domain-name", "value": "evil.com"}` |
| URL      | url                    | `{"type": "url", "value": "https://..."}`       |
| Hash     | file                   | `{"type": "file", "hashes": {"SHA-256": "..."}}`|
| Email    | email-addr             | `{"type": "email-addr", "value": "a@b.com"}`   |

## Port reference

| Service       | Port(s)   |
|---------------|-----------|
| OpenCTI UI    | 8080      |
| Elasticsearch | 9200      |
| RabbitMQ mgmt | 15672     |
| MinIO console | 9001      |
