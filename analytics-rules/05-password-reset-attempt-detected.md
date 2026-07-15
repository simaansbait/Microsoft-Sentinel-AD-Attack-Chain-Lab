\# Password Reset Attempt Detected



\## Description



Detects password reset activity in Active Directory. Password resets are commonly performed by administrators and Help Desk personnel, but unexpected resets may indicate account manipulation or misuse of privileged access.



This rule is included in the lab detection set but was not used as a main attack-chain stage because the persistence account was created with a known password and no additional reset was required.



\## Data Source



\- Microsoft Sentinel

\- Windows Security Events

\- `SecurityEvent` table

\- Domain Controller Security Log



\## Event ID



\- `4724` — An attempt was made to reset an account's password



\## Analytics Query



```kql

SecurityEvent

| where EventID == 4724

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

\- Account — Target:

&#x20; - Name: `TargetUserName`

&#x20; - NTDomain: `TargetDomainName`

\- Host:

&#x20; - HostName: `Computer`



\## MITRE ATT\&CK



\- Tactic: Persistence

\- Technique: `T1098` — Account Manipulation



\## Possible False Positives



\- Help Desk password resets

\- User password-recovery requests

\- Administrative account maintenance

\- Approved service-account credential rotation



\## Recommended Analyst Response



1\. Identify the user who performed the reset.

2\. Confirm whether the reset was linked to an approved ticket.

3\. Review the target account's privileges.

4\. Search for successful logons after the reset.

5\. Investigate unexpected resets of administrative or service accounts.

6\. Disable affected accounts and rotate credentials when malicious activity is confirmed.

