# Case Report — CASE-01: PowerShell Dropper via Phishing

| Field | Value |
|-------|--------|
| Severity | 🔴 HIGH |
| Date/Time | 2024-01-15 14:32–14:33 UTC |
| Host | CORP-FIN-042 |
| User | jdoe |

## 1. Summary

A user (jdoe) on workstation CORP-FIN-042 opened a malicious Office document that executed PowerShell with an encoded command. PowerShell downloaded a second-stage payload from `https://185.220.101.47/stage2/payload.bin` and saved it as `svchost.exe` in the user’s Temp folder. The binary executed, established a C2 channel to `45.142.212.100` (c2beacon.top-server.net), and performed persistence via a Run key and a scheduled task. Reconnaissance commands (`whoami`, `net user /domain`, `nltest /domain_trusts`) indicate post-exploitation activity. The attack chain is consistent with phishing (T1566.001) leading to execution and C2.

## 2. Evidence

### 2.1 Process Tree

```
explorer.exe
└── EXCEL.EXE
    └── powershell.exe -NoProfile -Exec Bypass -Enc <base64>
        ├── Network: 185.220.101.47:443 (update.evil-domain.ru)
        ├── File create: C:\Users\jdoe\AppData\Local\Temp\svchost.exe
        └── svchost.exe (dropper)
            ├── Network: 45.142.212.100:443 (c2beacon.top-server.net)
            ├── Registry: HKCU\...\Run\WindowsUpdateHelper
            ├── schtasks /create /sc onlogon ...
            ├── cmd.exe /c whoami & net user /domain
            └── nltest /domain_trusts
```

### 2.2 Key Log Evidence

| Source | Time (UTC) | Event / Finding |
|--------|------------|------------------|
| Sysmon | 14:32:10 | Excel started by explorer |
| Sysmon | 14:32:11 | PowerShell started by Excel, encoded command |
| Sysmon | 14:32:12 | PowerShell connected to 185.220.101.47:443 |
| Sysmon | 14:32:13 | File created: Temp\svchost.exe (MD5/SHA256 logged) |
| Sysmon | 14:32:14 | svchost.exe executed |
| Sysmon | 14:33:01 | svchost.exe connected to 45.142.212.100:443 |
| Sysmon | 14:33:02 | Registry Run key WindowsUpdateHelper set |
| Sysmon | 14:33:03 | schtasks created for onlogon |
| Sysmon | 14:33:15 | cmd whoami & net user /domain |
| Sysmon | 14:33:16 | nltest /domain_trusts |
| Zeek DNS | — | update.evil-domain.ru → 185.220.101.47 |
| Zeek DNS | — | c2beacon.top-server.net → 45.142.212.100 |

### 2.3 Network Evidence

- First-stage C2 / payload server: **185.220.101.47** (HTTPS), hostname **update.evil-domain.ru**; URL **https://185.220.101.47/stage2/payload.bin**.
- Second-stage C2: **45.142.212.100** (HTTPS), hostname **c2beacon.top-server.net**; recurring DNS from 192.168.1.105.

## 3. Extracted IOCs

| Type | Value | Context |
|------|--------|---------|
| IPv4 | 185.220.101.47 | Payload server / first-stage C2 |
| IPv4 | 192.168.1.105 | Compromised host (internal) |
| IPv4 | 45.142.212.100 | Second-stage C2 |
| Domain | update.evil-domain.ru | First-stage C2 |
| Domain | c2beacon.top-server.net | Second-stage C2 |
| URL | https://185.220.101.47/stage2/payload.bin | Dropper download |
| File MD5 | 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d | svchost.exe (dropper) |
| File SHA256 | 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b | svchost.exe |
| File MD5 | a1b2c3d4e5f607182936455647384950 | PowerShell process (script) |
| File SHA256 | a1b2c3d4e5f607182936455647384950a1b2c3d4e5f607182936455647384950 | PowerShell (script) |

### Reproduce IOC extraction

```bash
cd tools/ioc_extractor
python3 extractor.py -i ../../scenarios/case-01/logs/ -o ../../scenarios/case-01/iocs.json --pretty
```

## 4. OpenCTI Pivots

- Search for **185.220.101.47** or **45.142.212.100** to find other reports or observables mentioning the same infrastructure.
- Search for **c2beacon.top-server.net** or **update.evil-domain.ru** to link to other campaigns.
- Search for file hashes (MD5/SHA256 of svchost.exe) to find other sightings or malware analyses.
- Use the **SOC-LAB** label to filter all lab-ingested reports and observables.
- In the report’s Knowledge tab, follow links from observables to other entities (e.g. indicators, campaigns) if enriched.

## 5. ATT&CK Mapping

| Tactic | Technique | Sub-technique | Evidence |
|--------|-----------|----------------|----------|
| Initial Access | Phishing | Spearphishing Attachment (T1566.001) | Excel launched PowerShell; SIEM rule T1566.001 |
| Execution | PowerShell (T1059.001) | — | PowerShell -Enc, DownloadString |
| Defense Evasion | Masquerading (T1036.005) | Match Legitimate Name or Location | svchost.exe in Temp |
| Defense Evasion | Obfuscated Files or Information (T1027.010) | Command Obfuscation | Base64-encoded PowerShell |
| Persistence | Registry Run Keys (T1547.001) | — | WindowsUpdateHelper Run key |
| Persistence | Scheduled Task/Job (T1053.005) | — | schtasks /sc onlogon |
| Command and Control | Application Layer Protocol (T1071.001) | Web Protocols | HTTPS to C2 IPs |
| Collection | Domain Trust Discovery (T1482) | — | nltest /domain_trusts |

## 6. Severity & Rationale

- **HIGH** because:
  - Execution from a user context with clear C2 and persistence.
  - Domain recon suggests intent for lateral movement or privilege escalation.
  - Use of encoded PowerShell and a masqueraded binary indicates a structured attack, not opportunistic malware.
  - No evidence (in this data) of lateral movement or data exfiltration yet; hence not CRITICAL.

## 7. Containment, Eradication & Prevention

### Immediate Containment

1. Isolate host CORP-FIN-042 from the network (disable NIC or segment).
2. Disable or lock account jdoe until credential reset and review.
3. Block 185.220.101.47, 45.142.212.100, and domains update.evil-domain.ru, c2beacon.top-server.net at perimeter and DNS.
4. Search EDR/other endpoints for the same hashes and C2 connections.

### Eradication

1. Remove Run key `HKCU\...\Run\WindowsUpdateHelper` and scheduled task `WindowsUpdateHelper`.
2. Delete `C:\Users\jdoe\AppData\Local\Temp\svchost.exe` and collect for analysis.
3. Rebuild or fully clean the host; reset jdoe password and enforce MFA.
4. Review Excel/email for the initial phishing artifact and block sender/attachment hashes.

### Prevention

1. Restrict or disable PowerShell for standard users; use constrained language mode or allowlisting where needed.
2. Block Office macros or use application control to prevent Excel from spawning PowerShell.
3. Deploy EDR with script and macro visibility; alert on encoded PowerShell and Temp-executable patterns.
4. User awareness: do not enable macros or run unexpected attachments.

## 8. Limitations

- The exact phishing email and attachment hash are not in the provided logs.
- Scope of data accessed or exfiltrated (if any) is unknown from these logs.
- No visibility into whether other hosts were targeted or compromised via the same campaign.
- C2 protocol and payload decryption were not analyzed in this report.
