# SOC OpenCTI Triage Lab

A portfolio-grade lab for SOC analysts: triage scenarios with synthetic logs, IOC extraction, and ingestion into OpenCTI for pivoting and reporting.

**→ [How to fully utilise this project](docs/how-to-fully-utilise.md)** — end-to-end workflow, OpenCTI usage, case reports, and portfolio tips.  
**→ [Useful APIs](docs/useful-apis.md)** — OpenCTI GraphQL (queries, pycti examples) and optional external APIs for enrichment.

---

## What This Demonstrates

| Skill / area | Evidence in this repo |
|--------------|------------------------|
| Log analysis (Sysmon, Zeek, Falco, CloudTrail-style) | Scenario logs in `scenarios/case-01`–`case-03` |
| IOC extraction (IP, domain, URL, hash, email) | `tools/ioc_extractor` — regex-based, stdlib-only |
| STIX 2 / OpenCTI observables | `tools/opencti_client/push_observables.py` — Report + observables + label |
| Threat intelligence workflow | Extract → Ingest → Pivot → Document (case reports) |
| ATT&CK mapping & incident reporting | `docs/case-reports/case-01.md`–`case-03.md` |
| Docker-based CTI platform | `docker/docker-compose.yml` — OpenCTI 6.2 + Elasticsearch, Redis, RabbitMQ, MinIO |

---

## Architecture

```
Scenario Logs  →  IOC Extractor  →  iocs.json  →  OpenCTI Client  →  OpenCTI Platform
                     (Python)         (or expected-iocs.json)           ├── Elasticsearch
                                                                        ├── Redis
                                                                        ├── MinIO
                                                                        └── RabbitMQ → Workers (3×)
```

Full detail: [docs/architecture.md](docs/architecture.md).

---

## Quick Start

**1. Start OpenCTI** (from repo root):

```bash
cp docker/.env.example docker/.env
# Edit docker/.env: set OPENCTI_ADMIN_PASSWORD and OPENCTI_ADMIN_TOKEN (UUID)
cd docker && docker compose up -d && cd ..
```

Wait until the platform is up (e.g. http://localhost:8080). Log in and create an API token under **Settings → Access token**.

**2. Run the IOC extractor self-test**:

```bash
cd tools/ioc_extractor
python3 extractor.py --self-test
# Expected: Self-test: 7 passed, 0 failed.
```

**3. Extract IOCs and push to OpenCTI** (after copying `tools/opencti_client/config.example.yml` to `config.yml` and setting `opencti.url` and `opencti.token`):

```bash
cd tools/ioc_extractor
python3 extractor.py -i ../../scenarios/case-01/logs/ -o ../../scenarios/case-01/iocs.json --pretty
cd ../opencti_client
python3 push_observables.py --config config.yml --case ../../scenarios/case-01
```

---

## Case Pipelines (copy-paste)

**Case 01 — PowerShell dropper**

```bash
cd tools/ioc_extractor
python3 extractor.py -i ../../scenarios/case-01/logs/ -o ../../scenarios/case-01/iocs.json --pretty
cd ../opencti_client
python3 push_observables.py --config config.yml --case ../../scenarios/case-01
```

**Case 02 — LockBit ransomware**

```bash
cd tools/ioc_extractor
python3 extractor.py -i ../../scenarios/case-02/logs/ -o ../../scenarios/case-02/iocs.json --pretty
cd ../opencti_client
python3 push_observables.py --config config.yml --case ../../scenarios/case-02
```

**Case 03 — Malicious npm supply chain**

```bash
cd tools/ioc_extractor
python3 extractor.py -i ../../scenarios/case-03/logs/ -o ../../scenarios/case-03/iocs.json --pretty
cd ../opencti_client
python3 push_observables.py --config config.yml --case ../../scenarios/case-03
```

---

## Case Index

| Case | Severity | Summary | ATT&CK (examples) | Report |
|------|----------|---------|--------------------|--------|
| 01 | 🔴 HIGH | PowerShell dropper via phishing; C2 and persistence | T1566.001, T1059.001, T1547.001, T1482 | [case-01.md](docs/case-reports/case-01.md) |
| 02 | 🔴🔴 CRITICAL | LockBit 3.0 via RDP brute force; backup sabotage; lateral movement | T1110.001, T1059.001, T1490, T1567.002 | [case-02.md](docs/case-reports/case-02.md) |
| 03 | 🔴🔴 CRITICAL | Malicious npm package; reverse shell; cloud credential theft | T1195.001, T1059.004, T1552.007, T1078.004 | [case-03.md](docs/case-reports/case-03.md) |

---

## Repo Structure

```
soc-opencti-triage-lab/
├── README.md
├── .gitignore
├── docker/
│   ├── docker-compose.yml
│   ├── .env.example
│   └── README.md
├── scenarios/
│   ├── case-01/
│   │   ├── alert.json
│   │   ├── expected-iocs.json
│   │   └── logs/
│   │       ├── sysmon.txt
│   │       └── zeek_dns.log
│   ├── case-02/
│   │   ├── alert.json
│   │   ├── expected-iocs.json
│   │   └── logs/
│   │       ├── sysmon.txt
│   │       └── zeek_dns.log
│   └── case-03/
│       ├── alert.json
│       ├── expected-iocs.json
│       └── logs/
│           ├── sysmon.txt
│           └── zeek_dns.log
├── tools/
│   ├── ioc_extractor/
│   │   ├── extractor.py
│   │   ├── patterns.py
│   │   ├── requirements.txt
│   │   └── README.md
│   └── opencti_client/
│       ├── push_observables.py
│       ├── config.example.yml
│       ├── requirements.txt
│       └── README.md
└── docs/
    ├── architecture.md
    ├── screenshots/
    │   └── README.md
    └── case-reports/
        ├── case-01.md
        ├── case-02.md
        └── case-03.md
```

---

## Requirements

| Requirement | Version / note |
|-------------|----------------|
| Python | 3.8+ (3.10+ recommended) |
| Docker | For OpenCTI stack (docker-compose) |
| RAM | 8 GB+ recommended for Elasticsearch + OpenCTI |
| pycti | For OpenCTI client (`pip install pycti`) |
| PyYAML | For OpenCTI client config (`pip install PyYAML`) |

IOC extractor: **no pip installs** (standard library only).
