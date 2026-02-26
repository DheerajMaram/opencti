# OpenCTI Stack for SOC Triage Lab

This directory contains the Docker Compose stack for the SOC OpenCTI Triage Lab.

## Setup

1. Copy the example environment file and set your values:
   ```bash
   cp .env.example .env
   ```
2. Generate a valid UUID for `OPENCTI_ADMIN_TOKEN`:
   ```bash
   python3 -c "import uuid; print(uuid.uuid4())"
   ```
   Paste the output into `.env` as `OPENCTI_ADMIN_TOKEN`.

3. On Linux/WSL, ensure Elasticsearch can allocate enough memory:
   ```bash
   sudo sysctl -w vm.max_map_count=262144
   ```

## Run

```bash
docker compose up -d
```

OpenCTI will be available at the URL set in `OPENCTI_BASE_URL` (default: http://localhost:8080). Log in with `OPENCTI_ADMIN_EMAIL` and `OPENCTI_ADMIN_PASSWORD`.

## Stop

```bash
docker compose down
```

To remove volumes as well: `docker compose down -v`.
