\# Successful Logon After Multiple Failed Attempts



\## Description



Detects a successful Windows logon that occurs shortly after multiple failed logon attempts against the same account. This pattern may indicate that password guessing or brute-force activity successfully obtained valid credentials.



\## Data Source



\- Microsoft Sentinel

\- Windows Security Events

\- `SecurityEvent` table

\- Azure Monitor Agent

\- Data Collection Rule



\## Event IDs



\- `4625` — An account failed to log on

\- `4624` — An account was successfully logged on



\## Analytics Query



```kql

let FailedLogons =

&#x20;   SecurityEvent

&#x20;   | where EventID == 4625

&#x20;   | where TargetUserName !endswith "$"

&#x20;   | summarize

&#x20;       FailedAttempts = count(),

&#x20;       FirstFailure = min(TimeGenerated),

&#x20;       LastFailure = max(TimeGenerated)

&#x20;       by

&#x20;           TargetUserName,

&#x20;           TargetDomainName,

&#x20;           Computer

&#x20;   | where FailedAttempts >= 5;



let SuccessfulLogons =

&#x20;   SecurityEvent

&#x20;   | where EventID == 4624

&#x20;   | where TargetUserName !endswith "$"

&#x20;   | project

&#x20;       SuccessTime = TimeGenerated,

&#x20;       Computer,

&#x20;       Account,

&#x20;       TargetUserName,

&#x20;       TargetDomainName,

&#x20;       LogonType,

&#x20;       IpAddress,

&#x20;       WorkstationName,

&#x20;       AuthenticationPackageName;



FailedLogons

| join kind=inner SuccessfulLogons on

&#x20;   TargetUserName,

&#x20;   TargetDomainName,

&#x20;   Computer

| where SuccessTime > LastFailure

| where SuccessTime <= LastFailure + 30m

| project

&#x20;   SuccessTime,

&#x20;   Computer,

&#x20;   TargetDomainName,

&#x20;   TargetUserName,

&#x20;   FailedAttempts,

&#x20;   FirstFailure,

&#x20;   LastFailure,

&#x20;   Account,

&#x20;   LogonType,

&#x20;   IpAddress,

&#x20;   WorkstationName,

&#x20;   AuthenticationPackageName

```



\## Suggested Scheduling



\- Run query every: `5 minutes`

\- Lookup data from the last: `30 minutes`

\- Alert threshold: More than zero results



\## Incident Creation



Enabled



\## Entity Mapping



\- Account:

&#x20; - Name: `TargetUserName`

&#x20; - NTDomain: `TargetDomainName`

\- Host:

&#x20; - HostName: `Computer`

\- IP:

&#x20; - Address: `IpAddress`



\## MITRE ATT\&CK



\- Tactic: Credential Access

\- Technique: `T1110` — Brute Force

\- Tactic: Defense Evasion / Persistence / Privilege Escalation

\- Technique: `T1078` — Valid Accounts



\## Possible False Positives



\- A legitimate user eventually entering the correct password

\- Cached credentials after a recent password change

\- Users switching between keyboard layouts

\- Applications retrying an outdated password



\## Recommended Analyst Response



1\. Review the failed-attempt count and time interval.

2\. Verify the source IP address and workstation.

3\. Determine whether the successful logon originated from an expected device.

4\. Review subsequent process execution and privileged activity.

5\. Reset the account password when compromise is suspected.

6\. Revoke active sessions and Kerberos tickets.

