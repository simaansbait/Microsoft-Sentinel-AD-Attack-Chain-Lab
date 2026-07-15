\# New Domain User Created



\## Description



Detects the creation of a new Active Directory domain account. Unexpected account creation may indicate persistence, unauthorized administrative activity, or misuse of privileged credentials.



\## Data Source



\- Microsoft Sentinel

\- Windows Security Events

\- `SecurityEvent` table

\- Domain Controller Security Log



\## Event ID



\- `4720` — A user account was created



\## Analytics Query



```kql

SecurityEvent

| where EventID == 4720

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

\- Lookup data from the last: `30 minutes`

\- Alert threshold: More than zero results



\## Incident Creation



Enabled



\## Entity Mapping



\- Account — Actor:

&#x20; - Name: `SubjectUserName`

&#x20; - NTDomain: `SubjectDomainName`

\- Account — Created account:

&#x20; - Name: `TargetUserName`

&#x20; - NTDomain: `TargetDomainName`

\- Host:

&#x20; - HostName: `Computer`



\## MITRE ATT\&CK



\- Tactic: Persistence

\- Technique: `T1136.002` — Create Account: Domain Account



\## Possible False Positives



\- Approved employee onboarding

\- New service-account creation

\- Application deployment accounts

\- Administrative testing in a lab environment



\## Recommended Analyst Response



1\. Identify the administrator who created the account.

2\. Confirm whether the account creation was authorized.

3\. Review the account name, description, group memberships, and creation time.

4\. Search for subsequent privileged-group modifications.

5\. Disable the account when unauthorized.

6\. Review activity performed by the creating administrator.

