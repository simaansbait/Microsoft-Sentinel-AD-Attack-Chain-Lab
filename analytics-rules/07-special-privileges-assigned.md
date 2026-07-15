\# Special Privileges Assigned to New Logon



\## Description



Detects logons in which Windows assigns sensitive privileges to an account. Event ID `4672` is commonly generated for administrative and system accounts.



The rule filters common Windows system identities to reduce noise while retaining privileged domain and service-account activity.



\## Data Source



\- Microsoft Sentinel

\- Windows Security Events

\- `SecurityEvent` table

\- Azure Monitor Agent

\- Data Collection Rule



\## Event ID



\- `4672` — Special privileges assigned to new logon



\## Analytics Query



```kql

SecurityEvent

| where EventID == 4672

| where SubjectUserName !endswith "$"

| where SubjectUserName !startswith "DWM-"

| where SubjectUserName !startswith "UMFD-"

| where SubjectUserName !in\~ (

&#x20;   "SYSTEM",

&#x20;   "LOCAL SERVICE",

&#x20;   "NETWORK SERVICE",

&#x20;   "ANONYMOUS LOGON"

)

| project

&#x20;   TimeGenerated,

&#x20;   Computer,

&#x20;   Account,

&#x20;   SubjectUserName,

&#x20;   SubjectDomainName,

&#x20;   PrivilegeList,

&#x20;   Activity

```



\## Suggested Scheduling



\- Run query every: `5 minutes`

\- Lookup data from the last: `30 minutes`



A longer lookup window may be required when Azure Monitor Agent ingestion delays are observed.



\## Incident Creation



Enabled



\## Alert Grouping



For testing and validation, grouping may be disabled so each alert creates a separate incident.



In production, grouping should be configured carefully to avoid combining unrelated users and hosts into one incident.



\## Entity Mapping



\- Account:

&#x20; - Name: `SubjectUserName`

&#x20; - NTDomain: `SubjectDomainName`

\- Host:

&#x20; - HostName: `Computer`



\## Common Privileges



The `PrivilegeList` field may include:



```text

SeSecurityPrivilege

SeTakeOwnershipPrivilege

SeBackupPrivilege

SeRestorePrivilege

SeDebugPrivilege

SeImpersonatePrivilege

```



\## MITRE ATT\&CK



\- Tactic: Privilege Escalation

\- Technique: `T1078.002` — Valid Accounts: Domain Accounts



\## Possible False Positives



\- Legitimate administrator logons

\- Backup and deployment services

\- Security software

\- Scheduled administrative maintenance



\## Recommended Analyst Response



1\. Identify the account and host receiving special privileges.

2\. Determine whether the account is expected to be privileged.

3\. Correlate with a preceding `4624` successful logon.

4\. Review recent account creation and group-membership changes.

5\. Search for remote logons to Domain Controllers.

6\. Disable unauthorized accounts and revoke active sessions.

