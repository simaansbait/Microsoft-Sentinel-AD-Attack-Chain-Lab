\# User Added to Privileged Group



\## Description



Detects the addition of an account to a security-enabled global group, with a focus on privileged Active Directory groups such as Domain Admins.



Unexpected privileged-group membership changes may indicate privilege escalation, persistence, or misuse of administrative credentials.



\## Data Source



\- Microsoft Sentinel

\- Windows Security Events

\- `SecurityEvent` table

\- Domain Controller Security Log



\## Event ID



\- `4728` — A member was added to a security-enabled global group



\## Analytics Query



```kql

SecurityEvent

| where EventID == 4728

| where TargetUserName in\~ (

&#x20;   "Domain Admins",

&#x20;   "Enterprise Admins",

&#x20;   "Schema Admins"

)

| project

&#x20;   TimeGenerated,

&#x20;   Computer,

&#x20;   Account,

&#x20;   SubjectUserName,

&#x20;   SubjectDomainName,

&#x20;   MemberName,

&#x20;   TargetUserName,

&#x20;   TargetDomainName,

&#x20;   Activity

```



\## Suggested Scheduling



\- Run query every: `5 minutes`

\- Lookup data from the last: `30 minutes`

\- Alert threshold: More than zero results



\## Incident Creation



Enabled



\## Entity Mapping



\- Account — Actor:

&#x20; - Name: `SubjectUserName`

&#x20; - NTDomain: `SubjectDomainName`

\- Host:

&#x20; - HostName: `Computer`



\## Important Field Behavior



Windows may represent the added member in `MemberName` as a Distinguished Name rather than a SamAccountName.



Example:



```text

CN=Deployment Service,CN=Users,DC=simaanlab,DC=local

```



This is expected behavior for Event ID `4728`.



\## MITRE ATT\&CK



\- Tactic: Persistence

\- Tactic: Privilege Escalation

\- Technique: `T1098` — Account Manipulation



\## Possible False Positives



\- Approved administrator onboarding

\- Temporary emergency access

\- Authorized service-account changes

\- Planned infrastructure maintenance



\## Recommended Analyst Response



1\. Identify the administrator who made the change.

2\. Review the account added to the group.

3\. Confirm whether the change was approved.

4\. Search for account creation events occurring shortly before the group modification.

5\. Review subsequent `4624` and `4672` events for the added account.

6\. Remove unauthorized membership and disable the account.

