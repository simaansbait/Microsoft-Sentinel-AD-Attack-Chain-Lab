\# Account Lockout Detected



\## Description



Detects an Active Directory account lockout. Account lockouts may result from user error, outdated stored credentials, misconfigured services, or active password-guessing attempts.



\## Data Source



\- Microsoft Sentinel

\- Windows Security Events

\- `SecurityEvent` table

\- Domain Controller Security Log



\## Event ID



\- `4740` — A user account was locked out



\## Analytics Query



```kql

SecurityEvent

| where EventID == 4740

| where TargetUserName !endswith "$"

| project

&#x20;   TimeGenerated,

&#x20;   Computer,

&#x20;   Account,

&#x20;   SubjectUserName,

&#x20;   SubjectDomainName,

&#x20;   TargetUserName,

&#x20;   TargetDomainName,

&#x20;   Activity

```



\## Suggested Scheduling



\- Run query every: `5 minutes`

\- Lookup data from the last: `15 minutes`

\- Alert threshold: More than zero results



\## Incident Creation



Enabled



\## Entity Mapping



\- Account:

&#x20; - Name: `TargetUserName`

&#x20; - NTDomain: `TargetDomainName`

\- Host:

&#x20; - HostName: `Computer`



\## MITRE ATT\&CK



\- Tactic: Credential Access

\- Technique: `T1110` — Brute Force



\## Possible False Positives



\- Users repeatedly entering an incorrect password

\- Mobile devices using an old password

\- Scheduled tasks with expired credentials

\- Services configured with outdated passwords



\## Recommended Analyst Response



1\. Identify the locked account and affected system.

2\. Review preceding `4625` failed-logon events.

3\. Determine the source workstation or application.

4\. Verify whether the activity was expected.

5\. Unlock the account only after identifying the cause.

6\. Reset credentials when compromise is suspected.

