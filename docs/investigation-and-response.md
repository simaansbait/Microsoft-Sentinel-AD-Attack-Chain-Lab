\# Investigation and Response



\## Investigation Methodology



The investigation followed a realistic SOC workflow.



The initial hunt did not filter directly for known malicious accounts. Instead, the analyst began with broad searches based on Windows Event IDs and suspicious behavior.



The process was:



```text

Broad Event Search

&#x20;       ↓

Identify Suspicious User, Host, and Target

&#x20;       ↓

Pivot to Related Events

&#x20;       ↓

Correlate Source and Destination Activity

&#x20;       ↓

Build Attack Timeline

&#x20;       ↓

Contain and Remediate

```



\## Broad Hunt



The broad hunt searched for:



```text

4624, 4625, 4672, 4688, 4720, 4728, 4740

```



The search was limited to the attack timeframe and filtered common Windows system identities to reduce noise.



The hunt identified:



\- Process execution by `david.hr`

\- Failed logons against `sarah.finance`

\- Privileged logons by `Service.Backup`

\- Creation of `svc.deploy`

\- Addition of `svc.deploy` to `Domain Admins`

\- Privileged access by `svc.deploy`



\## Investigation Timeline



The focused investigation timeline correlated:



1\. Reconnaissance on `CLIENT01`

2\. Password attacks against `sarah.finance`

3\. Account lockout

4\. Successful credential use

5\. `runas.exe` execution

6\. Lateral movement using `Service.Backup`

7\. Special privileges on `DC01`

8\. Creation of `svc.deploy`

9\. Addition to `Domain Admins`

10\. Interactive privileged logon

11\. Remote administrative access to `DC01`



\## Incident Handling



The main Microsoft Sentinel incident was:



```text

Special Privileges Assigned to New Logon

```



The incident was:



\- Assigned to an analyst

\- Investigated using related Windows Security Events

\- Documented with an analyst comment

\- Classified as a true positive

\- Tagged as malicious activity

\- Resolved after containment



\## Containment Actions



\### Persistence Account



The persistence account was removed from the privileged group:



```powershell

Remove-ADGroupMember "Domain Admins" -Members "svc.deploy" -Confirm:$false

```



The account was disabled:



```powershell

Disable-ADAccount "svc.deploy"

```



Validation:



```powershell

Get-ADUser "svc.deploy" -Properties Enabled |

Select-Object SamAccountName, Enabled

```



Expected result:



```text

svc.deploy    False

```



\### Compromised Privileged Account



The password for `Service.Backup` was reset:



```powershell

Set-ADAccountPassword "Service.Backup" -Reset

```



The account was disabled:



```powershell

Disable-ADAccount "Service.Backup"

```



Validation:



```powershell

Get-ADUser "Service.Backup" -Properties Enabled |

Select-Object SamAccountName, Enabled

```



Expected result:



```text

Service.Backup    False

```



\### Endpoint Session Cleanup



Active SMB connections were removed:



```cmd

net use \* /delete /y

```



Kerberos tickets were purged:



```cmd

klist purge

```



\## Production Response Recommendations



In a production environment, additional actions would include:



\- Isolate `CLIENT01`

\- Reset all credentials used on the endpoint

\- Revoke active sessions

\- Revoke Kerberos tickets

\- Disable unauthorized accounts

\- Remove unauthorized privileged-group membership

\- Review `DC01` activity

\- Hunt for additional privileged logons

\- Review scheduled tasks and services

\- Review remote service creation

\- Search for additional persistence

\- Validate backup-account usage

\- Review changes to GPOs and Active Directory objects



\## Incident Resolution Summary



The investigation confirmed a multi-stage Active Directory compromise involving valid account abuse, lateral movement, domain-account creation, privilege escalation, and remote administrative access to the Domain Controller.



Containment and remediation successfully disabled the malicious persistence account, removed its administrative privileges, reset and disabled the compromised privileged account, and cleaned active sessions and Kerberos tickets from the source endpoint.

