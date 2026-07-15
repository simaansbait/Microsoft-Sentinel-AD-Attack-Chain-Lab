# Microsoft Sentinel Active Directory Attack Chain Detection Lab

## Overview

This project demonstrates an end-to-end Security Operations Center investigation in Microsoft Sentinel involving a multi-stage Active Directory attack chain.

The lab covers:

- Windows Security Event collection
- KQL threat hunting
- Scheduled analytics rules
- Incident creation
- Cross-host event correlation
- Active Directory attack investigation
- MITRE ATT&CK mapping
- Containment and remediation
- Incident documentation and resolution

The simulated attack begins from a low-privileged user session on `CLIENT01` and progresses through reconnaissance, password attacks, credential abuse, lateral movement, domain account creation, privilege escalation, persistence, and administrative access to the Domain Controller.

> This project was performed in an isolated lab environment for defensive security training.

---

## Lab Architecture

| Component | Configuration |
|---|---|
| Active Directory Domain | `simaanlab.local` |
| Domain Controller | `DC01` |
| Windows Endpoint | `CLIENT01` |
| SIEM | Microsoft Sentinel |
| Log Collection | Azure Arc + Azure Monitor Agent |
| Collection Configuration | Data Collection Rule |
| Log Analytics Table | `SecurityEvent` |

### Log Collection Flow

```text
Windows Security Event Log
        ↓
Azure Monitor Agent
        ↓
Data Collection Rule
        ↓
Log Analytics Workspace
        ↓
Microsoft Sentinel
        ↓
SecurityEvent Table
```

Both `DC01` and `CLIENT01` were connected to Azure Arc, Azure Monitor Agent, and the relevant Data Collection Rule.

---

## Key Accounts

| Account | Role |
|---|---|
| `david.hr` | Initial low-privileged user context on `CLIENT01` |
| `sarah.finance` | Target of password attacks |
| `Service.Backup` | Domain Admin account used for lateral movement |
| `svc.deploy` | Persistence account created and added to Domain Admins |

The persistence account used the display name:

```text
Deployment Service
```

---

## Attack Chain Summary

```text
david.hr session on CLIENT01
        ↓
Reconnaissance and domain discovery
        ↓
Password attacks against sarah.finance
        ↓
Account lockout and successful credential use
        ↓
Service.Backup credentials used
        ↓
SMB lateral movement to DC01
        ↓
svc.deploy domain account created
        ↓
svc.deploy added to Domain Admins
        ↓
Privileged interactive logon
        ↓
Remote administrative access to DC01
        ↓
Detection, investigation, containment, and remediation
```

---

## Stage 1 — Reconnaissance

The activity began on `CLIENT01` under:

```text
SIMAANLAB\david.hr
```

Commands included:

```cmd
whoami
whoami /groups
hostname
nltest
net user /domain
```

These commands were used to identify:

- The current user
- Group memberships
- Endpoint hostname
- Domain information
- Domain accounts
- Potential remote systems

Relevant telemetry:

```text
4688 — A new process was created
```

### Evidence

![Attacker Context](Images/01-reconnaissance/01-client01-attacker-context.png)

![Group Membership Discovery](Images/01-reconnaissance/02-david-hr-group-membership.png)

![Domain Controller Discovery](Images/01-reconnaissance/03-domain-controller-discovery.png)

![Sentinel Reconnaissance Events](Images/01-reconnaissance/04-sentinel-4688-recon-david-hr.png)

---

## Stage 2 — Password Attacks

Repeated password attempts were performed against:

```text
SIMAANLAB\sarah.finance
```

The activity produced:

```text
4625 — Failed logon
4740 — Account lockout
4624 — Successful logon
4688 — runas.exe execution
```

Microsoft Sentinel incidents were generated for:

- Multiple failed logons
- Account lockout
- Successful logon after multiple failed attempts

### Evidence

![Password Guessing](Images/02-password-attacks/01-client01-password-guessing-sarah-finance.png)

![Account Lockout Event](Images/02-password-attacks/02-sentinel-4740-account-lockout-sarah-finance.png)

![Failed Logons](Images/02-password-attacks/03-sentinel-4625-failed-logons-sarah-finance.png)

![Brute Force Incident](Images/02-password-attacks/04-brute-force-incident-sarah-finance.png)

![Account Lockout Incident](Images/02-password-attacks/05-account-lockout-incident-sarah-finance.png)

![Successful Logon](Images/02-password-attacks/06-client01-successful-logon-sarah-finance.png)

![Runas Execution](Images/02-password-attacks/07-sentinel-4688-david-initiated-runas.png)

![Successful Logon Event](Images/02-password-attacks/08-sentinel-4624-successful-logon-sarah-finance.png)

![Successful Logon After Failures Incident](Images/02-password-attacks/09-successful-logon-after-failures-incident.png)

---

## Stage 3 — Lateral Movement to DC01

From the `david.hr` session on `CLIENT01`, valid credentials for the privileged account below were used:

```text
SIMAANLAB\Service.Backup
```

Commands:

```cmd
net use \\DC01\IPC$ /user:SIMAANLAB\Service.Backup *
dir \\DC01\C$
```

The activity demonstrated administrative SMB access to `DC01`.

Relevant telemetry:

```text
4688 — net.exe executed by david.hr on CLIENT01
4624 — Service.Backup network logon on DC01
4672 — Special privileges assigned to Service.Backup
```

A KQL correlation connected activity across both hosts:

```text
SourceHost: CLIENT01
InitiatingUser: David.hr
Process: net.exe
DestinationHost: DC01
RemoteUser: Service.Backup
SourceIp: 192.168.10.20
LogonType: 3
Authentication: Kerberos
```

### Evidence

![Remote Administrative Access](Images/03-lateral-movement-to-dc01/01-client01-remote-admin-access-dc01.png)

![Service Backup Logon](Images/03-lateral-movement-to-dc01/02-sentinel-4624-service-backup-dc01.png)

![Special Privileges](Images/03-lateral-movement-to-dc01/03-sentinel-4672-special-privileges-service-backup.png)

![Lateral Movement Correlation](Images/03-lateral-movement-to-dc01/04-sentinel-correlated-lateral-movement-client01-to-dc01.png)

![Special Privileges Incident](Images/03-lateral-movement-to-dc01/05-special-privileges-incident-service-backup.png)

---

## Stage 4 — Domain Account Creation

Using a privileged PowerShell session running as `Service.Backup`, a new domain account was created:

```text
SamAccountName: svc.deploy
Display Name: Deployment Service
Description: Legacy software deployment service
```

Relevant telemetry:

```text
4720 — A user account was created
```

The event identified:

```text
Actor: SIMAANLAB\Service.Backup
Target: SIMAANLAB\svc.deploy
Computer: DC01
```

### Evidence

![Persistence Account Creation](Images/04-account-manipulation/01-client01-service-backup-created-svc-deploy.png)

![New Domain User Incident](Images/04-account-manipulation/02-new-domain-user-created-incident.png)

---

## Stage 5 — Privilege Escalation and Persistence

`Service.Backup` added `svc.deploy` to:

```text
Domain Admins
```

Relevant telemetry:

```text
4728 — A member was added to a security-enabled global group
```

Windows represented the added member as a Distinguished Name:

```text
CN=Deployment Service,CN=Users,DC=simaanlab,DC=local
```

This is expected behavior for the `MemberName` field in Event ID `4728`.

The new persistence account then performed an interactive logon on `CLIENT01`.

Relevant telemetry:

```text
4624 — Successful interactive logon
4672 — Special privileges assigned
```

### Evidence

![Added to Domain Admins](Images/05-privilege-escalation/01-service-backup-added-account-to-domain-admins.png)

![Privileged Group Modification Event](Images/05-privilege-escalation/02-sentinel-service-backup-added-svc-deploy-to-domain-admins.png)

![Privileged Group Incident](Images/05-privilege-escalation/03-user-added-to-privileged-group-incident.png)

![Privileged Logon](Images/05-privilege-escalation/04-client01-privileged-logon-svc-deploy.png)

![Successful Privileged Logon Event](Images/05-privilege-escalation/05-sentinel-4624-privileged-account-logon.png)

![Special Privileges Event](Images/05-privilege-escalation/06-sentinel-4672-special-privileges-svc-deploy.png)

![Special Privileges Incident](Images/05-privilege-escalation/07-special-privileges-incident-svc-deploy.png)

---

## Stage 6 — Domain Compromise Validation

The persistence account demonstrated remote administrative access to the Domain Controller:

```cmd
dir \\DC01\C$
```

Active Directory access was also validated using read-only commands:

```powershell
Import-Module ActiveDirectory
Get-ADDomain -Server DC01
Get-ADGroupMember "Domain Admins" -Server DC01
```

Relevant telemetry:

```text
4624 — Successful network logon
LogonType: 3
Target account: svc.deploy
Destination: DC01
```

### Evidence

![Remote Admin Access by svc.deploy](Images/06-domain-compromise/01-svc-deploy-remote-admin-access-dc01.png)

![Domain Admin Validation](Images/06-domain-compromise/02-svc-deploy-domain-admin-validation.png)

![Network Logon to DC01](Images/06-domain-compromise/03-sentinel-4624-svc-deploy-network-logon-dc01.png)

---

## Detection Engineering

Seven scheduled analytics rules were created:

1. Multiple Failed Logons - Possible Brute Force
2. Successful Logon After Multiple Failed Attempts
3. Account Lockout Detected
4. New Domain User Created
5. Password Reset Attempt Detected
6. User Added to Privileged Group
7. Special Privileges Assigned to New Logon

Rule documentation is available in:

```text
analytics-rules/
```

The password reset rule was retained as part of the detection set but was not included as a main stage of the simulated attack chain because the persistence account was created with a known password.

---

## KQL Hunting Queries

Reusable KQL queries are available in:

```text
queries/
```

Included queries:

| File | Purpose |
|---|---|
| `01-broad-attack-chain-hunt.kql` | Broad hunt across relevant Windows Event IDs |
| `02-attack-chain-investigation-timeline.kql` | Focused attack-chain timeline |
| `03-lateral-movement-correlation.kql` | Correlation between source process execution and remote logon |
| `04-failed-logons-and-lockout.kql` | Failed-logon and account-lockout investigation |
| `05-successful-logon-after-failures.kql` | Successful logon following multiple failures |
| `06-new-domain-user-created.kql` | Domain account creation events |
| `07-privileged-group-modification.kql` | Privileged group membership changes |
| `08-special-privileges-assigned.kql` | Special privileges assigned to logons |
| `09-privileged-logons.kql` | Successful privileged-account logons |
| `10-process-execution-reconnaissance.kql` | Process execution and discovery activity |
| `11-domain-compromise-network-logon.kql` | Network logons to the Domain Controller |

---

## Investigation Methodology

The investigation followed a realistic SOC workflow.

The initial hunt did not begin by filtering directly for known malicious accounts.

The methodology was:

```text
Broad search by Event ID or behavior
        ↓
Identify suspicious users, hosts, and targets
        ↓
Pivot to related events
        ↓
Correlate endpoint and Domain Controller activity
        ↓
Build an investigation timeline
        ↓
Contain and remediate
```

This approach reduces confirmation bias and better reflects real-world SOC analysis.

### Evidence

![Broad Attack Chain Hunt](Images/07-investigation-and-response/01-sentinel-broad-attack-chain-hunt.png)

![Attack Chain Timeline Part 1](Images/07-investigation-and-response/02-sentinel-attack-chain-investigation-timeline-part1.png)

![Attack Chain Timeline Part 2](Images/07-investigation-and-response/03-sentinel-attack-chain-investigation-timeline-part2.png)

---

## Containment and Remediation

The persistence account was removed from `Domain Admins` and disabled:

```powershell
Remove-ADGroupMember "Domain Admins" -Members "svc.deploy" -Confirm:$false
Disable-ADAccount "svc.deploy"
```

The compromised privileged account was remediated:

```powershell
Set-ADAccountPassword "Service.Backup" -Reset
Disable-ADAccount "Service.Backup"
```

Endpoint cleanup included:

```cmd
net use * /delete /y
klist purge
```

The main incident was:

- Assigned to an analyst
- Documented with an analyst comment
- Classified as a true positive
- Tagged as malicious activity
- Resolved after containment

### Evidence

![Containment](Images/07-investigation-and-response/04-containment-svc-deploy-disabled-and-removed.png)

![Session and Ticket Cleanup](Images/07-investigation-and-response/05-client01-session-and-ticket-cleanup.png)

![Analyst Investigation Comment](Images/07-investigation-and-response/06a-sentinel-analyst-investigation-comment.png)

![Resolved True Positive Incident](Images/07-investigation-and-response/06-sentinel-incident-resolved-true-positive.png)

![Credential Remediation](Images/07-investigation-and-response/07-service-backup-credential-remediation.png)

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|---|---|---|
| Discovery | `T1087` | Account Discovery |
| Discovery | `T1069` | Permission Groups Discovery |
| Discovery | `T1018` | Remote System Discovery |
| Credential Access | `T1110` | Brute Force |
| Lateral Movement | `T1021.002` | SMB/Windows Admin Shares |
| Defense Evasion / Persistence / Privilege Escalation | `T1078` | Valid Accounts |
| Persistence | `T1136.002` | Create Account: Domain Account |
| Persistence / Privilege Escalation | `T1098` | Account Manipulation |
| Privilege Escalation | `T1078.002` | Valid Accounts: Domain Accounts |

Detailed mapping is available in:

```text
docs/mitre-attack-mapping.md
```

---

## Windows Security Event IDs

| Event ID | Description |
|---|---|
| `4624` | Successful logon |
| `4625` | Failed logon |
| `4672` | Special privileges assigned to new logon |
| `4688` | New process created |
| `4720` | User account created |
| `4724` | Password reset attempt |
| `4728` | Member added to a security-enabled global group |
| `4740` | User account locked out |

---

## Troubleshooting

During the project, Event ID `4688` was generated locally on `CLIENT01` but did not initially arrive in Microsoft Sentinel.

The issue was resolved by reinstalling:

```text
AzureMonitorWindowsAgent
```

The actual Azure Monitor Agent configuration path on `CLIENT01` was:

```text
C:\Resources\Directory\AMADataStore.CLIENT01\mcs\mcsconfig.latest.xml
```

The investigation also identified ingestion delays between:

```text
TimeGenerated
```

and:

```text
ingestion_time()
```

This required longer analytics-rule lookup windows to prevent delayed events from being missed.

Detailed troubleshooting documentation is available in:

```text
docs/troubleshooting.md
```

---

## Repository Structure

```text
Microsoft-Sentinel-AD-Attack-Chain-Lab/
│
├── README.md
├── Images/
│   ├── 01-reconnaissance/
│   ├── 02-password-attacks/
│   ├── 03-lateral-movement-to-dc01/
│   ├── 04-account-manipulation/
│   ├── 05-privilege-escalation/
│   ├── 06-domain-compromise/
│   └── 07-investigation-and-response/
├── queries/
├── analytics-rules/
└── docs/
```

---

## Documentation

Additional project documentation:

- [Lab Architecture](docs/lab-architecture.md)
- [Attack Chain](docs/attack-chain.md)
- [MITRE ATT&CK Mapping](docs/mitre-attack-mapping.md)
- [Investigation and Response](docs/investigation-and-response.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Lessons Learned](docs/lessons-learned.md)

---

## Skills Demonstrated

- Microsoft Sentinel
- Kusto Query Language
- Active Directory security
- Windows Security Event analysis
- Azure Arc
- Azure Monitor Agent
- Data Collection Rules
- Detection engineering
- Scheduled analytics rules
- Threat hunting
- Incident investigation
- Event correlation
- Lateral movement detection
- Privilege escalation detection
- Persistence detection
- MITRE ATT&CK mapping
- Containment and remediation
- Incident documentation

---

## Disclaimer

This project was created in an isolated lab environment for educational and defensive security purposes.

All accounts, systems, commands, and attack activity were created specifically for the lab. No production systems or unauthorized environments were targeted.
