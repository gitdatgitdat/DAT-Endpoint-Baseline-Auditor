# Endpoint Baseline Auditor (Windows)

PowerShell tool that audits common security baselines on a single PC or across a fleet.  
Produces JSON/CSV plus a one-file HTML report, with clear pass/fail reasons and exit codes for automation.

---

# What it checks

- **BitLocker (OS volume)** – protection **On**
- **BitLocker TPM protector** – protector types include **TPM**
- **Secure Boot + TPM** – Secure Boot enabled and TPM present/ready
- **Credential Guard + LSA Protection** – Device Guard running + `RunAsPPL` set
- **Microsoft Defender (core)** – real-time on; signature age ≤ `-MaxSigAgeDays` (default **7**)
- **Microsoft Defender (advanced)** – Tamper Protection on, MAPS (Basic/Advanced) enabled, **any** ASR rule in *Block*
- **Windows Firewall** – Domain/Private/Public profiles **enabled**
- **RDP disabled**
- **RDP NLA** – if RDP is enabled, **NLA required**
- **SMBv1 disabled**
- **SMB signing required** (server)
- **Local Administrators allowlist** *(optional)* – only members in `-AllowedAdmins`
- **LAPS present** *(optional)* – when `-RequireLAPS` is set

Each failing item contributes to `Reasons` and sets `Compliance = NonCompliant`.

---

# Quick start  

Local snapshot (console preview + artifacts)
.\Get-EndpointBaseline.ps1 -Json .\baseline.json -Csv .\baseline.csv -LogPath .\logs

Multi-host - Create samples\hosts.csv:

ComputerName  
PC1  
PC2  
PC3.domain.local  

Run (implicit auth), or add -Credential (Get-Credential) if needed:  
.\Get-EndpointBaseline.ps1 -HostsCsv .\samples\hosts.csv -Json .\fleet.json -Csv .\fleet.csv -LogPath .\logs  

---

# HTML report

From JSON/CSV files (wildcards OK)  
.\New-EndpointBaselineHtml.ps1 -InputPath .\fleet.json -OutHtml .\reports\fleet.html -Open  

---

# Parameters

-ComputerName <string[]>     # Remote targets; omit for local  
-HostsCsv <path>             # CSV/TXT of targets (headers like ComputerName/Host/Name/FQDN)  
-Credential <pscredential>   # Optional; otherwise uses current context (Kerberos/NTLM)  
-Json <path>                 # Write JSON  
-Csv <path>                  # Write CSV  
-LogPath <path>              # File or directory for run logs  
-MaxSigAgeDays <int>         # Defender signature age window (default 7)  
-AllowedAdmins <string[]>    # Allowlist for local Administrators group  
-RequireLAPS                 # Require LAPS presence  

---

# Output schema (per machine)

Compliance — Compliant | NonCompliant | Unknown

Reasons — semicolon-separated failing checks, e.g. BitLocker:Status=Off; SMB1Disabled:SMB1=Enabled

Detail fields: BitLocker, BitLockerTPM, SecureBootTPM, CredentialGuard, Defender, DefenderAdv, Firewall, RDP, RDP_NLA, SMB1, SMBSigning, Admins, LAPS, CollectedAt (UTC)

---

# Exit codes

0 – all compliant  
1 – at least one NonCompliant  
2 – any Unknown (e.g., remoting error)  

---

# Requirements

Remote collection: WinRM/PowerShell Remoting enabled + reachable; name/DNS working; permissions granted.

Local rights: Some checks (BitLocker, local groups, firewall) may require elevated PowerShell.
