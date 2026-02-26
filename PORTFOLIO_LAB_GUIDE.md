# OpenCTI: How It Works, Customization & Portfolio Lab Guide

A practical guide for understanding OpenCTI, customizing it, and building a lab to showcase in your portfolio.

---

## 1. How This Project Works

### What is OpenCTI?

**OpenCTI** (Open Cyber Threat Intelligence Platform) is an open-source platform for managing **cyber threat intelligence**. It lets organizations:

- **Structure** threat data using [STIX 2](https://oasis-open.github.io/cti-documentation/) standards
- **Store** and organize technical (TTPs, observables) and non-technical (attribution, victimology) information
- **Visualize** knowledge as a graph and link everything to sources (reports, MISP, etc.)
- **Integrate** with tools like MISP, TheHive, MITRE ATT&CK via connectors

### Architecture (High Level)

```
┌─────────────────────────────────────────────────────────────────┐
│  Frontend (React)  →  http://localhost:3000 (dev) / 8080 (Docker) │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│  Backend (Node.js GraphQL API)  →  port 4000                      │
└───────────────────────────────┬─────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
   Elasticsearch            Redis                 RabbitMQ
   (search/index)        (stream/cache)         (message queue)
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
                        ┌───────▼───────┐
                        │  Worker       │  ← writes data from RabbitMQ
                        │  (Python/JS)  │
                        └───────────────┘
```

- **Frontend**: `opencti-platform/opencti-front` (React)
- **Backend/API**: `opencti-platform/opencti-graphql` (Node.js, GraphQL)
- **Worker**: ingests data from RabbitMQ into the platform
- **Connectors**: external Python (or other) processes that push STIX bundles to OpenCTI (feeds, enrichment, import/export)

### Two Ways to Run OpenCTI

| Goal | How | Where |
|------|-----|--------|
| **Use it (production-like)** | Docker Compose from [OpenCTI-Platform/docker](https://github.com/OpenCTI-Platform/docker) | Clone `docker` repo, configure `.env`, run `docker-compose up -d` → http://localhost:8080 |
| **Develop platform/frontend** | Dev stack (Docker for deps + Node for app) | This repo: start infra in `opencti-platform/opencti-dev`, then backend + frontend (see below) |

**Quick start (development in this repo):**

1. **Start infrastructure** (Elasticsearch, Redis, RabbitMQ, MinIO, etc.):
   ```powershell
   cd opencti-platform\opencti-dev
   docker compose up -d
   ```

2. **Backend** (from repo root):
   ```powershell
   cd opencti-platform\opencti-graphql
   # First time: copy config and set admin password/token
   # config: copy default.json → development.json, set admin.password and admin.token (UUID)
   yarn install
   yarn start
   ```
   → API: http://127.0.0.1:4000

3. **Frontend**:
   ```powershell
   cd opencti-platform\opencti-front
   yarn install
   yarn start
   ```
   → UI: http://127.0.0.1:3000

For **production-style** deployment (e.g. for a lab or portfolio), use the **official Docker setup** from the [docker](https://github.com/OpenCTI-Platform/docker) repository; this repo is the application source code.

---

## 2. What to Add & How to Customize

### A. Use the Platform as-is

- **Dashboards**: Create custom dashboards (Settings → Dashboards) and set one as default for a role/group.
- **Taxonomy / labels**: Use and create labels, kill chain phases, marking definitions to fit your use cases.
- **Data**: Import STIX bundles, CSV, use connectors (MITRE ATT&CK, MISP, etc.) to populate the knowledge base.
- **Feeds & export**: Configure feeds (CSV, STIX) and export connectors for detection-as-code (SIEM, EDR, etc.).

### B. Customize the Codebase

- **Frontend** (`opencti-platform/opencti-front`): Change UI, add views, adjust theme or layout (React).
- **Backend** (`opencti-platform/opencti-graphql`): Add GraphQL types/resolvers, new entities or behaviors.
- **Configuration**: Use `config/production.json` (or `development.json`) for URLs, auth, Elasticsearch, Redis, RabbitMQ, S3/MinIO, etc. See [configuration docs](https://docs.opencti.io/latest/deployment/configuration/).

### C. Extend via Connectors (Best for Portfolio Projects)

Connectors are **separate processes** that send STIX 2 data into OpenCTI. You can:

- **Write a custom connector** (e.g. Python using [client-python](https://github.com/OpenCTI-Platform/opencti/tree/master/client-python) / `pycti`):
  - **EXTERNAL_IMPORT**: Your own threat feed (e.g. scrape a blog, RSS, or API).
  - **INTERNAL_ENRICHMENT**: Enrich entities (e.g. IP → abuse score, geo).
  - **INTERNAL_IMPORT_FILE**: Import from custom file formats.
  - **INTERNAL_EXPORT_FILE**: Export to your own format.
  - **STREAM**: Real-time integration with another platform.

Use the [connectors repo](https://github.com/OpenCTI-Platform/connectors) templates and [connector development docs](https://docs.opencti.io/latest/development/connectors/) to bootstrap. This is a strong portfolio piece: “Custom OpenCTI connector for X”.

### D. Integrations

- **API**: All operations go through the GraphQL API; you can build scripts or small apps (Python, Node, etc.) to create reports, indicators, relationships.
- **Python client**: Use `client-python` (pycti) from this repo for automation and connector development.

---

## 3. Building a Lab for Your Portfolio

### Why OpenCTI for a Lab?

- Real-world **CTI platform** used by enterprises.
- Demonstrates **STIX/TAXII**, **threat intelligence workflows**, **integration** (connectors, API).
- Good for roles in **SOC, CTI, security engineering, detection engineering**.

### Lab Ideas

1. **“Personal CTI lab”**
   - Deploy OpenCTI via Docker.
   - Ingest MITRE ATT&CK + one open-source feed (e.g. abuse.ch, or a custom RSS).
   - Create a short report and link it to attack patterns and indicators; document the workflow.

2. **“Custom connector”**
   - Build a connector that:
     - Pulls from a public API (e.g. vulnerability feed, threat feed) or parses a blog/RSS.
     - Normalizes to STIX 2 and pushes to OpenCTI via `send_stix2_bundle`.
   - Put the connector in a public repo with a README and screenshots of data in OpenCTI.

3. **“Detection-as-code pipeline”**
   - Use OpenCTI indicators + export connector (or your own script) to generate Sigma/YARA or SIEM rules.
   - Document: OpenCTI → export → rule format → optional deployment steps.

4. **“Integration showcase”**
   - OpenCTI + one other tool (e.g. MISP, TheHive, or a custom dashboard that reads from the GraphQL API).
   - Document architecture and data flow.

### Steps to Build the Lab

1. **Deploy OpenCTI**
   - Use [OpenCTI-Platform/docker](https://github.com/OpenCTI-Platform/docker): clone, configure `.env` (admin password, tokens, `OPENCTI_BASE_URL`), then `docker-compose up -d`.
   - On Windows, ensure Docker Desktop and WSL2 are set up; for Elasticsearch you may need `vm.max_map_count` (Linux/WSL).

2. **Add data**
   - Enable built-in connectors (e.g. MITRE ATT&CK) from the OpenCTI UI.
   - Import a STIX bundle or CSV, or run your custom connector.

3. **Document and screenshot**
   - Dashboard, knowledge graph, a sample report, and (if applicable) connector runs.
   - Write a short “Architecture” and “How to run” section.

4. **Showcase in portfolio**
   - **GitHub**: One repo for “OpenCTI lab” or “OpenCTI connector X” with README, config notes, and screenshots.
   - **Blog/portfolio**: “Building a threat intelligence lab with OpenCTI” + link to repo and optional live demo (e.g. VM or cloud instance).
   - **CV/LinkedIn**: e.g. “Threat intelligence lab using OpenCTI and custom connectors (STIX 2, Python).”

### What to Include in the Repo

- `README.md`: What the lab does, architecture diagram (optional), prerequisites (Docker, etc.).
- How to run: exact `docker-compose` (or dev) steps and URL (e.g. http://localhost:8080).
- If you built a connector: source code, `requirements.txt`, `config.yml.sample`, and how to register/run it against your OpenCTI instance.
- Screenshots or short screen recording of the main workflow.
- Optional: `docker-compose.override.yml` or env example for your lab only (no secrets).

---

## 4. Useful Links

- **Documentation**: https://docs.opencti.io  
- **Demo instance**: https://demo.opencti.io (reset nightly)  
- **Docker deployment**: https://github.com/OpenCTI-Platform/docker  
- **Connectors**: https://github.com/OpenCTI-Platform/connectors  
- **API/usage**: https://docs.opencti.io/latest/development/api-usage/  
- **Configuration**: https://docs.opencti.io/latest/deployment/configuration/  

---

## 5. Summary

| Question | Answer |
|----------|--------|
| **How does it work?** | React frontend + GraphQL backend + Elasticsearch/Redis/RabbitMQ + worker; connectors push STIX into the platform. |
| **What to add?** | Data (feeds, imports), custom dashboards, and/or custom connectors; optionally frontend/backend changes. |
| **How to customize?** | Config files; frontend/backend code in this repo; connectors (Python/other) in separate repos. |
| **How to build a lab?** | Deploy with Docker, ingest data, optionally build a connector or integration, document and add screenshots. |
| **Portfolio** | Repo + README + “CTI lab with OpenCTI” or “Custom OpenCTI connector” + architecture and run instructions. |

Use this file as a single reference for understanding, customizing, and showcasing OpenCTI in your portfolio.
