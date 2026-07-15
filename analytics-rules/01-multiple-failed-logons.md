\# Multiple Failed Logons - Possible Brute Force



\## Description



Detects multiple failed Windows logon attempts against the same user account within a short period. This behavior may indicate password guessing, brute-force activity, or repeated use of invalid credentials.



\## Data Source



\- Microsoft Sentinel

\- Windows Security Events

\- `SecurityEvent` table

\- Azure Monitor Agent

\- Data Collection Rule



\## Event ID



\- `4625` — An account failed to log on



\## Analytics Query



```kql

SecurityEvent

| where EventID == 4625

| where TargetUserName !endswith "$"

| where TargetUserName !in\~ (

&#x20;   "SYSTEM",

&#x20;   "LOCAL SERVICE",

&#x20;   "NETWORK SERVICE",

&#x20;   "ANONYMOUS LOGON"

)

| summarize

&#x20;   FailedAttempts = count(),

&#x20;   FirstFailure = min(TimeGenerated),

&#x20;   LastFailure = max(TimeGenerated),

&#x20;   SourceIpAddresses = make\_set(IpAddress, 10),

&#x20;   Workstations = make\_set(WorkstationName, 10)

&#x20;   by

&#x20;       TargetUserName,

&#x20;       TargetDomainName,

&#x20;       Computer

| where FailedAttempts >= 5

| project

&#x20;   FirstFailure,

&#x20;   LastFailure,

&#x20;   TargetDomainName,

&#x20;   TargetUserName,

&#x20;   Computer,

&#x20;   FailedAttempts,

&#x20;   SourceIpAddresses,

&#x20;   Workstations

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

\- Cached credentials after a password change

\- Misconfigured applications or scheduled tasks

\- Services using expired passwords



\## Recommended Analyst Response



1\. Review the number and timing of failed attempts.

2\. Identify the source workstation or IP address.

3\. Check whether the account was subsequently locked.

4\. Search for a successful logon following the failed attempts.

5\. Contact the account owner if the activity is unexpected.

6\. Reset credentials and isolate the source endpoint when malicious activity is confirmed.

