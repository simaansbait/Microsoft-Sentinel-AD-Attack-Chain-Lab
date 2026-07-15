\# MITRE ATT\&CK Mapping



\## Overview



The simulated attack chain was mapped to MITRE ATT\&CK techniques based on the observed behavior and Windows Security Event telemetry.



\## Discovery



\### T1087 — Account Discovery



Observed behavior:



```cmd

net user /domain

```



Purpose:



\- Enumerate domain user accounts

\- Identify potential targets and privileged accounts



Relevant telemetry:



```text

Event ID 4688

```



\### T1069 — Permission Groups Discovery



Observed behavior:



```cmd

whoami /groups

```



Purpose:



\- Identify current group memberships

\- Determine existing privileges



Relevant telemetry:



```text

Event ID 4688

```



\### T1018 — Remote System Discovery



Observed behavior:



```cmd

nltest

hostname

```



Purpose:



\- Discover domain and system context

\- Identify the Domain Controller and endpoint hostname



Relevant telemetry:



```text

Event ID 4688

```



\## Credential Access



\### T1110 — Brute Force



Observed behavior:



\- Multiple failed logons against `sarah.finance`

\- Account lockout

\- Successful logon following failures



Relevant telemetry:



```text

4625 — Failed logon

4740 — Account lockout

4624 — Successful logon

```



\## Defense Evasion, Persistence, and Privilege Escalation



\### T1078 — Valid Accounts



Observed behavior:



\- Use of valid credentials for `Service.Backup`

\- Use of valid credentials for `svc.deploy`



Relevant telemetry:



```text

4624 — Successful logon

4672 — Special privileges assigned

```



\### T1078.002 — Valid Accounts: Domain Accounts



Observed behavior:



\- Domain account authentication

\- Privileged domain account logons

\- Administrative access to the Domain Controller



Accounts:



```text

Service.Backup

svc.deploy

```



\## Lateral Movement



\### T1021.002 — SMB/Windows Admin Shares



Observed behavior:



```cmd

net use \\\\DC01\\IPC$

dir \\\\DC01\\C$

```



Purpose:



\- Establish an authenticated SMB session

\- Access administrative shares on the Domain Controller



Relevant telemetry:



```text

4624 — Network logon

LogonType 3

4688 — net.exe process execution

```



\## Persistence



\### T1136.002 — Create Account: Domain Account



Observed behavior:



```text

svc.deploy domain account created

```



Relevant telemetry:



```text

4720 — User account created

```



\## Account Manipulation



\### T1098 — Account Manipulation



Observed behavior:



\- `svc.deploy` added to `Domain Admins`

\- Password reset monitoring

\- Privileged account membership modification



Relevant telemetry:



```text

4728 — Member added to privileged group

4724 — Password reset attempt

```



\## Technique Summary



| Tactic | Technique | Description |

|---|---|---|

| Discovery | T1087 | Account Discovery |

| Discovery | T1069 | Permission Groups Discovery |

| Discovery | T1018 | Remote System Discovery |

| Credential Access | T1110 | Brute Force |

| Lateral Movement | T1021.002 | SMB/Windows Admin Shares |

| Defense Evasion / Persistence / Privilege Escalation | T1078 | Valid Accounts |

| Persistence | T1136.002 | Create Account: Domain Account |

| Persistence / Privilege Escalation | T1098 | Account Manipulation |

| Privilege Escalation | T1078.002 | Valid Accounts: Domain Accounts |

