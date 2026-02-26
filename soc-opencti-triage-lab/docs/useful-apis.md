# Useful APIs for This Project

APIs you can use with the SOC OpenCTI Triage Lab: OpenCTI (core) and optional external services for enrichment or automation.

---

## 1. OpenCTI GraphQL API (core)

All platform data is accessed via the **GraphQL API**. The lab already uses it through **pycti** in `tools/opencti_client/push_observables.py`.

### Base URL and auth

| Item | Value |
|------|--------|
| **Endpoint** | `http://localhost:8080/graphql` (or `https://your-opencti/graphql`) |
| **Playground** | `http://localhost:8080/public/graphql` — interactive queries and schema docs |
| **Auth** | HTTP header: `X-OpenCTI-Token: <your-token>` or `Authorization: Bearer <token>` |

Token: from **Settings → Access token** in the UI, or the admin token in `docker/.env` (`OPENCTI_ADMIN_TOKEN`).

### Example: query reports (SOC-LAB)

**GraphQL (playground or curl):**

```graphql
query ReportsByLabel {
  reports(
    filters: {
      mode: and
      filters: [{ key: "objectLabel", values: ["SOC-LAB"] }]
      filterGroups: []
    }
    first: 50
  ) {
    edges {
      node {
        id
        name
        description
        published
        objectLabel { value }
      }
    }
    pageInfo { hasNextPage endCursor globalCount }
  }
}
```

**Python (pycti):**

```python
from pycti import OpenCTIApiClient
client = OpenCTIApiClient(url="http://localhost:8080", token="YOUR_TOKEN")
reports = client.report.list(
    filters={"mode": "and", "filters": [{"key": "objectLabel", "values": ["SOC-LAB"]}], "filterGroups": []},
    first=50,
)
for r in reports:
    print(r["name"], r["published"])
```

### Example: query observables (IPs, domains, hashes)

**GraphQL:**

```graphql
query ObservablesByLabel {
  stixCyberObservables(
    filters: {
      mode: and
      filters: [{ key: "objectLabel", values: ["SOC-LAB"] }]
      filterGroups: []
    }
    first: 100
  ) {
    edges {
      node {
        id
        entity_type
        observable_value
        objectLabel { value }
      }
    }
    pageInfo { globalCount }
  }
}
```

**Python (pycti):**

```python
observables = client.stix_cyber_observable.list(
    filters={"mode": "and", "filters": [{"key": "objectLabel", "values": ["SOC-LAB"]}], "filterGroups": []},
    first=100,
)
for o in observables:
    print(o.get("entity_type"), o.get("observable_value"))
```

### Example: search the platform (Q Search)

**GraphQL:**

```graphql
query Search($search: String) {
  stixCyberObservables(search: $search, first: 20) {
    edges { node { id entity_type observable_value } }
  }
  reports(search: $search, first: 20) {
    edges { node { id name published } }
  }
}
# Variables: { "search": "185.220.101.47" }
```

**Python (pycti):**

```python
# Search observables
obs = client.stix_cyber_observable.list(search="185.220.101.47", first=20)
# Search reports
reps = client.report.list(search="SOC-LAB", first=20)
```

### Example: get objects in a report

**GraphQL:**

```graphql
query ReportWithObjects($id: String!) {
  report(id: $id) {
    id
    name
    objects(first: 100) {
      edges { node { id entity_type ... on IPv4Addr { value } ... on DomainName { value } } }
    }
  }
}
```

**Python (pycti):** use `client.report.read(id=report_id)` with `customAttributes` if you need nested objects, or list observables and filter by report relationship.

### Useful pycti methods in this project

| What you need | pycti method |
|---------------|----------------|
| Create report | `client.report.create(name=..., description=..., published=..., objectLabel=[...])` |
| Create observable | `client.stix_cyber_observable.create(observableData={...}, objectLabel=[...])` |
| Add observable to report | `client.report.add_stix_object_or_stix_relationship(id=report_id, stixObjectOrStixRelationshipId=obs_id)` |
| List reports | `client.report.list(filters=..., first=N)` |
| List observables | `client.stix_cyber_observable.list(filters=..., first=N)` |
| Get or create label | `client.label.read(filters=...)` then `client.label.create(value=..., color=...)` |

Full schema and more operations: open **http://localhost:8080/public/graphql** and use the **Docs** panel.

---

## 2. Optional external APIs (enrichment / automation)

Use these to enrich IOCs before or after pushing to OpenCTI, or to build a small enrichment script for the lab.

| API | Purpose | Typical use in this project |
|-----|---------|-----------------------------|
| **AbuseIPDB** | IP reputation, country, usage type | Enrich IPs from `iocs.json` before/after ingestion; add context to a report. [abuseipdb.com/api](https://www.abuseipdb.com/api) |
| **VirusTotal** | IP/domain/hash reputation, detections | Check extracted hashes or IPs; optional script to add “VT link” to report. [virustotal.com/api](https://www.virustotal.com/gui/join-us) |
| **Shodan** | IP, open ports, banners | Enrich C2 or payload-server IPs for lab write-ups. [shodan.io](https://developer.shodan.io/) |
| **AlienVault OTX** | Pulses, IOCs, context | Look up IOCs; optionally feed OpenCTI via connector. [otx.alienvault.com/api](https://otx.alienvault.com/api) |
| **MITRE ATT&CK (STIX)** | Tactics, techniques, IDs | Already used in case reports; can query [attack.mitre.org](https://attack.mitre.org/) or STIX API for T-codes. |

**Example (conceptual):** a small Python script that reads `scenarios/case-01/iocs.json`, calls AbuseIPDB for each IP, and writes a short enrichment note or appends context to the OpenCTI report via the GraphQL API.

---

## 3. Quick reference

| Goal | API / tool |
|------|------------|
| Query or mutate OpenCTI | **OpenCTI GraphQL** — `http://localhost:8080/graphql` (header `X-OpenCTI-Token`) |
| Try queries interactively | **Playground** — `http://localhost:8080/public/graphql` |
| Use from Python | **pycti** — `pip install pycti==6.2.14`; `OpenCTIApiClient(url=..., token=...)` |
| Enrich IPs | AbuseIPDB, VirusTotal, Shodan (optional) |
| Threat intel context | AlienVault OTX, MITRE ATT&CK |

For this project, the main API you need is **OpenCTI’s GraphQL API** (via playground or pycti). External APIs are optional for making the lab more realistic or portfolio-ready.
