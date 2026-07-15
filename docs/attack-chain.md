\# Attack Chain



\## Overview



The lab simulates a multi-stage Active Directory attack originating from a compromised low-privileged user session on `CLIENT01`.



The activity progresses from reconnaissance and credential access to lateral movement, persistence, privilege escalation, domain compromise, investigation, and containment.



\## Stage 1 — Reconnaissance



The initial activity was executed on `CLIENT01` under:



```text

SIMAANLAB\\david.hr

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



\- The current user

\- Group memberships

\- The local hostname

\- Domain information

\- Domain users



Relevant telemetry:



```text

Event ID 4688

```



\## Stage 2 — Password Attacks



Repeated password attempts were performed against:



```text

SIMAANLAB\\sarah.finance

```



The activity generated:



\- Multiple failed logons

\- Account lockout

\- A later successful logon

\- Process execution showing that `david.hr` initiated `runas.exe`



Relevant telemetry:



```text

4625 — Failed logon

4740 — Account lockout

4624 — Successful logon

4688 — runas.exe execution

```



\## Stage 3 — Lateral Movement



From the `david.hr` session on `CLIENT01`, credentials for the privileged account below were used:



```text

SIMAANLAB\\Service.Backup

```



Commands:



```cmd

net use \\\\DC01\\IPC$ /user:SIMAANLAB\\Service.Backup \*

dir \\\\DC01\\C$

```



The activity demonstrated administrative access from `CLIENT01` to `DC01`.



Relevant telemetry:



```text

4688 — net.exe executed by david.hr

4624 — Network logon by Service.Backup on DC01

4672 — Special privileges assigned to Service.Backup

```



The correlated result identified:



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



\## Stage 4 — Domain Account Creation



Using a PowerShell session running as `Service.Backup`, a new domain account was created:



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

Actor: SIMAANLAB\\Service.Backup

Target: SIMAANLAB\\svc.deploy

Computer: DC01

```



\## Stage 5 — Privilege Escalation and Persistence



`Service.Backup` added the new account to:



```text

Domain Admins

```



Relevant telemetry:



```text

4728 — A member was added to a security-enabled global group

```



Windows represented the added account as a Distinguished Name:



```text

CN=Deployment Service,CN=Users,DC=simaanlab,DC=local

```



The new account then performed an interactive privileged logon on `CLIENT01`.



Relevant telemetry:



```text

4624 — Successful interactive logon

4672 — Special privileges assigned

```



\## Stage 6 — Domain Compromise



The persistence account demonstrated administrative access to the Domain Controller:



```cmd

dir \\\\DC01\\C$

```



The account also queried Active Directory:



```powershell

Import-Module ActiveDirectory

Get-ADDomain -Server DC01

Get-ADGroupMember "Domain Admins" -Server DC01

```



Relevant telemetry:



```text

4624 — Network logon to DC01

LogonType: 3

Account: svc.deploy

```



\## Stage 7 — Investigation and Response



The analyst performed:



\- Broad event hunting

\- Entity identification

\- Timeline correlation

\- Incident review

\- Analyst comments

\- True-positive classification

\- Incident resolution



Containment included:



```powershell

Remove-ADGroupMember "Domain Admins" -Members "svc.deploy" -Confirm:$false

Disable-ADAccount "svc.deploy"

Set-ADAccountPassword "Service.Backup" -Reset

Disable-ADAccount "Service.Backup"

```



Endpoint cleanup included:



```cmd

net use \* /delete /y

klist purge

```



\## Final Attack Flow



```text

david.hr session on CLIENT01

&#x20;       ↓

Reconnaissance

&#x20;       ↓

Password attacks against sarah.finance

&#x20;       ↓

Successful credential use

&#x20;       ↓

Service.Backup credentials used

&#x20;       ↓

SMB lateral movement to DC01

&#x20;       ↓

svc.deploy domain account created

&#x20;       ↓

svc.deploy added to Domain Admins

&#x20;       ↓

Privileged logon

&#x20;       ↓

Remote administrative access to DC01

&#x20;       ↓

Detection, investigation, containment, and remediation

```

