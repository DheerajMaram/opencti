# How to Fully Utilise This Project

This guide walks you through using the SOC OpenCTI Triage Lab end-to-end: from running the platform and ingesting data to pivoting in OpenCTI and using it in your portfolio.

---

## 1. Run the full pipeline (extract → ingest)

**Prerequisites:** OpenCTI running at http://localhost:8080, and `tools/opencti_client/config.yml` with `opencti.url` and `opencti.token` (use the admin token from `docker/.env` or create one in **Settings → Access token**).

**For each case (01, 02, 03):**

```bash
# From repo root (Windows: use python instead of python3 if needed)
cd tools/ioc_extractor
python extractor.py -i ../../scenarios/case-01/logs/ -o ../../scenarios/case-01/iocs.json --pretty
cd ../opencti_client
python push_observables.py --config config.yml --case ../../scenarios/case-01
```

Repeat for `case-02` and `case-03` (change paths accordingly). This populates OpenCTI with **Reports** and **Observables** (IPs, domains, URLs, hashes, emails) tagged with the **SOC-LAB** label.

---

## 2. Use OpenCTI to explore and pivot

| Goal | Where to go |
|------|----------------|
| **See SOC reports** | Left menu → **Analysis** → **Reports**. Filter by label **SOC-LAB**. |
| **See all observables** | **Observations** → **Observables** (or **Indicators**). Filter by **SOC-LAB**. |
| **Search for an IOC** | Top bar **Q Search** → type an IP, domain, or hash → open the observable or report. |
| **Pivot from a report** | Open a report → **Knowledge** tab to see linked observables; click one to see its details and other reports. |
| **Pivot from an observable** | Open an observable (e.g. IP or domain) → see which reports and other entities reference it. |
| **Dashboard** | **Dashboard** to see counts (reports, indicators) and widgets once data is present. |

Use this to demonstrate: *“I ingested IOCs into OpenCTI and used the platform to search and pivot between reports and observables.”*

---

## 3. Tie in the case reports (narrative + ATT&CK)

The written analyses live in **`docs/case-reports/`**:

- **case-01.md** — PowerShell dropper via phishing (HIGH)
- **case-02.md** — LockBit via RDP brute force (CRITICAL)
- **case-03.md** — Malicious npm supply chain (CRITICAL)

**How to use them:**

- **During triage:** Read the case report *after* you’ve looked at the scenario logs and extracted IOCs; compare your list with **Expected IOCs** and the **Reproduce IOC extraction** commands in the report.
- **In OpenCTI:** When viewing a SOC-LAB report, keep the corresponding case report open for the attack narrative, evidence table, and ATT&CK mapping.
- **For portfolio:** Show that you can both run the technical pipeline (extract → push) and produce analyst-style output (summary, evidence, IOCs, ATT&CK, containment).

---

## 4. Reproduce extraction and compare

To show you can run the extractor and validate results:

```bash
cd tools/ioc_extractor
python extractor.py --self-test                    # 7 passed
python extractor.py -i ../../scenarios/case-01/logs/   # stdout: ips, domains, urls, hashes
```

Compare the extracted JSON with **`scenarios/case-0X/expected-iocs.json`** and with the “Extracted IOCs” table in **`docs/case-reports/case-0X.md`**. This demonstrates repeatable, scripted IOC extraction from logs.

---

## 5. Add your own scenario (optional)

To fully customise and extend the lab:

1. **New case folder:** e.g. `scenarios/case-04/` with:
   - `alert.json` (name, description, severity, host, rule/MITRE)
   - `logs/` (e.g. `sysmon.txt`, `zeek_dns.log` — real or synthetic)
   - `expected-iocs.json` (optional; schema: `ips`, `domains`, `urls`, `hashes`, `emails`)
2. **Extract:**  
   `python extractor.py -i ../../scenarios/case-04/logs/ -o ../../scenarios/case-04/iocs.json --pretty`
3. **Ingest:**  
   `python push_observables.py --config config.yml --case ../../scenarios/case-04`
4. **Document:** Copy **`docs/case-reports/case-01.md`** to **case-04.md** and fill in summary, evidence, IOCs, ATT&CK, and response steps.

This shows you can design scenarios, run the same toolchain, and document incidents in the same format.

---

## 6. Use in your portfolio / CV

- **GitHub:** Keep the repo public; README and this doc explain what the project does and how to run it.
- **CV / LinkedIn:** e.g. *“SOC OpenCTI Triage Lab: log-based IOC extraction, STIX 2 ingestion into OpenCTI, ATT&CK-mapped case reports.”*
- **Screenshots:** Add to **`docs/screenshots/`** (see `docs/screenshots/README.md`): e.g. OpenCTI dashboard with SOC-LAB reports, a report’s Knowledge tab, and a search/pivot on an IOC.
- **Interview talking points:** You can say you ran a CTI platform (OpenCTI), automated IOC extraction from logs, pushed data via the API, and produced structured case reports with ATT&CK mapping and containment steps.

---

## 7. Quick reference

| Step | Command / location |
|------|--------------------|
| Start OpenCTI | `cd docker && docker compose up -d` |
| Log in | http://localhost:8080 — admin credentials in `docker/.env` |
| Extract IOCs (case 01) | `tools/ioc_extractor`: `python extractor.py -i ../../scenarios/case-01/logs/ -o ../../scenarios/case-01/iocs.json --pretty` |
| Push to OpenCTI | `tools/opencti_client`: `python push_observables.py --config config.yml --case ../../scenarios/case-01` |
| View SOC reports | OpenCTI → **Analysis** → **Reports** → filter label **SOC-LAB** |
| Read case narrative | `docs/case-reports/case-01.md`, `case-02.md`, `case-03.md` |
| Architecture | `docs/architecture.md` |

Using the project fully means: **run the pipeline for all cases → explore and pivot in OpenCTI → use the case reports for narrative and ATT&CK → optionally add a scenario and document it → showcase the repo and screenshots in your portfolio.**
