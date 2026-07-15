\# Lab Architecture



\## Overview



This lab was designed to simulate a realistic Microsoft Sentinel SOC investigation involving a multi-stage Active Directory attack chain.



The environment includes one Domain Controller, one Windows endpoint, Microsoft Sentinel, Azure Arc, Azure Monitor Agent, and a Data Collection Rule that forwards Windows Security Events into the `SecurityEvent` table.



\## Environment



| Component | Value |

|---|---|

| Active Directory Domain | `simaanlab.local` |

| Domain Controller | `DC01` |

| Endpoint | `CLIENT01` |

| SIEM | Microsoft Sentinel |

| Log Collection | Azure Arc + Azure Monitor Agent |

| Data Collection | Data Collection Rule |

| Sentinel Table | `SecurityEvent` |



\## Systems



\### DC01



`DC01` is the Active Directory Domain Controller for the `simaanlab.local` domain.



It was used to collect and investigate:



\- Successful and failed domain logons

\- Account lockouts

\- Privileged logons

\- Domain account creation

\- Privileged group membership changes

\- Remote administrative access



\### CLIENT01



`CLIENT01` is the endpoint from which the simulated attacker activity originated.



It was used to generate:



\- Discovery and reconnaissance commands

\- Password-guessing activity

\- Credential use through `runas`

\- SMB administrative access to `DC01`

\- Creation of a persistence account

\- Privileged logons



\## Log Collection Architecture



Both `DC01` and `CLIENT01` were onboarded to Azure Arc and connected to Microsoft Sentinel through Azure Monitor Agent.



The collection flow was:



```text

Windows Security Event Log

&#x20;       ↓

Azure Monitor Agent

&#x20;       ↓

Data Collection Rule

&#x20;       ↓

Log Analytics Workspace

&#x20;       ↓

Microsoft Sentinel

&#x20;       ↓

SecurityEvent Table

```



\## Relevant Windows Event IDs



| Event ID | Description |

|---|---|

| `4624` | Successful logon |

| `4625` | Failed logon |

| `4672` | Special privileges assigned to new logon |

| `4688` | New process created |

| `4720` | User account created |

| `4724` | Password reset attempt |

| `4728` | User added to a security-enabled global group |

| `4740` | User account locked out |



\## Important Accounts



| Account | Role in the Lab |

|---|---|

| `david.hr` | Initial low-privileged user context on `CLIENT01` |

| `sarah.finance` | Target of password attacks |

| `Service.Backup` | Privileged Domain Admin account used for lateral movement |

| `svc.deploy` | Persistence account created and added to Domain Admins |



\## Network Context



The lateral movement path was:



```text

CLIENT01

192.168.10.20

&#x20;   ↓ SMB / Administrative Share

DC01

```



The attacker used valid credentials for `Service.Backup` to access:



```text

\\\\DC01\\IPC$

\\\\DC01\\C$

```



The persistence account `svc.deploy` later demonstrated remote administrative access to `DC01`.

