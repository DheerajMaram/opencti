# Case Report — CASE-02: Ransomware via RDP Brute Force

| Field | Value |
|-------|--------|
| Severity | 🔴🔴 CRITICAL |
| Date/Time | 2024-02-20 09:02–09:16 UTC |
| Host | CORP-SRV-WEB01 |
| User | SYSTEM (post-compromise) |

## 1. Summary

CrowdStrike detected LockBit 3.0 ransomware on CORP-SRV-WEB01. Evidence shows RDP brute force from **194.165.16.75** (multiple 4625 logon failures) followed by a successful logon (4624). The attacker ran PowerShell to download and execute LockBit 3.0 from **https://lockbit3.onion.pet/tools/lb3.ps1**; the payload **lb3.exe** was dropped in `C:\Windows\Temp`. The ransomware then disabled recovery (vssadmin, wbadmin, bcdedit), disabled Windows Defender (DisableAntiSpyware), moved laterally to **192.168.10.25** over SMB, and exfiltrated or staged data via **31.13.64.35** (Mega.nz). A ransom note **!!READ_ME_LOCKBIT!!.txt** was created in the web root. Severity is CRITICAL due to confirmed ransomware, backup sabotage, and lateral movement.

## 2. Evidence

### 2.1 Brute-force timeline

| Time (UTC) | Event |
|------------|--------|
| 09:02:11 – 09:05:22 | Multiple EventID 4625 (logon failure) from 194.165.16.75, TargetUserName=administrator, LogonType=10 (RDP) |
| 09:14:58 | EventID 4624 — successful RDP logon from 194.165.16.75 |
| 09:15:01 | PowerShell spawned; DownloadString from lockbit3.onion.pet |
| 09:15:02 | Outbound 91.92.109.55:443 (lockbit3.onion.pet) |
| 09:15:05 | lb3.exe created in C:\Windows\Temp (MD5/SHA256 logged) |
| 09:15:06 | lb3.exe executed |
| 09:15:30 – 09:15:33 | vssadmin, wbadmin, bcdedit; DisableAntiSpyware registry |
| 09:15:45 | Connection to 192.168.10.25:445 (SMB) |
| 09:16:10 – 09:16:11 | Connections to 31.13.64.35:443 (g.api.mega.co.nz, storage.mega.nz) |
| 09:16:30 | !!READ_ME_LOCKBIT!!.txt created |

### 2.2 Post-access command sequence

| Order | Action | Evidence |
|-------|--------|----------|
| 1 | Download LockBit 3.0 | PowerShell DownloadString https://lockbit3.onion.pet/tools/lb3.ps1 |
| 2 | Drop & execute | C:\Windows\Temp\lb3.exe |
| 3 | Delete shadows | vssadmin delete shadows /all /quiet |
| 4 | Delete backup catalog | wbadmin delete catalog -quiet |
| 5 | Disable recovery | bcdedit /set {default} recoveryenabled No |
| 6 | Disable Defender | DisableAntiSpyware = 1 |
| 7 | Lateral movement | SMB to 192.168.10.25:445 |
| 8 | Exfil / staging | HTTPS to 31.13.64.35 (Mega) |
| 9 | Ransom note | !!READ_ME_LOCKBIT!!.txt in wwwroot |

### 2.3 Network Evidence

- Attacker source: **194.165.16.75** (RDP).
- Payload/C2: **91.92.109.55** (lockbit3.onion.pet).
- Lateral: **192.168.10.25:445** (SMB).
- Exfil/staging: **31.13.64.35** (g.api.mega.co.nz, storage.mega.nz).
- Internal victim: **192.168.10.5** (CORP-SRV-WEB01 in Zeek).

## 3. Extracted IOCs

| Type | Value | Context |
|------|--------|---------|
| IPv4 | 194.165.16.75 | RDP brute force source |
| IPv4 | 91.92.109.55 | LockBit payload / C2 |
| IPv4 | 31.13.64.35 | Mega.nz exfil/staging |
| IPv4 | 192.168.10.5 | Compromised host |
| IPv4 | 192.168.10.25 | Lateral movement target |
| Domain | lockbit3.onion.pet | LockBit infrastructure |
| Domain | g.api.mega.co.nz | Mega API |
| Domain | storage.mega.nz | Mega storage |
| URL | https://lockbit3.onion.pet/tools/lb3.ps1 | Payload download |
| File MD5 | c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9 | lb3.exe |
| File SHA256 | c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6 | lb3.exe |

### Reproduce IOC extraction

```bash
cd tools/ioc_extractor
python3 extractor.py -i ../../scenarios/case-02/logs/ -o ../../scenarios/case-02/iocs.json --pretty
```

## 4. OpenCTI Pivots

- Search **194.165.16.75** and **91.92.109.55** for other incidents or reports.
- Search **lockbit3.onion.pet** and hashes of lb3.exe for LockBit 3.0 intelligence.
- Use **SOC-LAB** label to group all lab case observables.
- Correlate **192.168.10.25** with other SMB or lateral-movement events in the platform.

## 5. ATT&CK Mapping

| Tactic | Technique | Sub-technique | Evidence |
|--------|-----------|----------------|----------|
| Credential Access | Brute Force (T1110) | Password Guessing (T1110.001) | 4625 from 194.165.16.75; 4624 success |
| Execution | PowerShell (T1059.001) | — | DownloadString lb3.ps1 |
| Defense Evasion | Impair Defenses (T1562.001) | Disable or Modify Tools | DisableAntiSpyware |
| Impact | Inhibit System Recovery (T1490) | — | vssadmin, wbadmin, bcdedit |
| Lateral Movement | Remote Services (T1021.002) | SMB/Windows Admin Shares | 192.168.10.25:445 |
| Exfiltration | Exfiltration to Cloud (T1567.002) | Exfiltration to Cloud Storage | Mega.nz IPs |
| Impact | Data Encrypted for Impact (T1486) | — | LockBit; ransom note |

## 6. Severity & Rationale

- **CRITICAL** because:
  - Confirmed ransomware (LockBit 3.0) with ransom note and recovery inhibition.
  - Backup and recovery mechanisms were deliberately disabled.
  - Lateral movement to 192.168.10.25 indicates potential for multi-host encryption.
  - Data exfiltration or staging to Mega.nz increases regulatory and reputational risk.

## 7. Containment, Eradication & Prevention

### Immediate Containment

1. Isolate CORP-SRV-WEB01 and 192.168.10.25 from the network.
2. Block 194.165.16.75, 91.92.109.55, 31.13.64.35 and lockbit3.onion.pet at firewall and DNS.
3. Disable RDP from the internet or restrict to VPN + MFA.
4. Identify all hosts that communicated with 192.168.10.25 or shared SMB with the victim.

### Eradication

1. Do not pay ransom without formal decision; preserve evidence (images, logs, lb3.exe).
2. Rebuild CORP-SRV-WEB01 and 192.168.10.25 from known-good backups (after validating backup integrity).
3. Rotate all credentials that could have been exposed (local admin, service accounts, domain).
4. Remove persistence and malware artifacts; hunt for LockBit hashes and lockbit3.onion.pet across the estate.

### Prevention

1. Enforce MFA and strong password policy for RDP; prefer VPN + bastion over direct internet RDP.
2. Restrict RDP with network segmentation and allowlisting; deploy EDR on all internet-facing and critical servers.
3. Maintain offline/immutable backups; test restore regularly.
4. Block or alert on outbound connections to known ransomware C2 and cloud storage from servers.

## 8. Limitations

- Whether 192.168.10.25 was also encrypted or only used for staging is not clear from these logs.
- Full scope of encrypted and exfiltrated data is unknown.
- No visibility into whether the same attacker (194.165.16.75) has compromised other organizations.
- Decryption capability (e.g. free decryptors) was not assessed.
