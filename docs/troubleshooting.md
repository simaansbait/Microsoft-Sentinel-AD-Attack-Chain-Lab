\# Troubleshooting



\## Overview



During the lab, Windows Event ID `4688` was generated locally on `CLIENT01` but did not initially appear in Microsoft Sentinel.



Other Windows Security Events were being collected correctly.



This created a telemetry gap because process-creation events were required to document reconnaissance and command execution.



\## Symptoms



On `CLIENT01`:



\- Event ID `4688` was visible in the local Windows Security Event Log

\- Process creation auditing was enabled

\- Commands such as `whoami`, `hostname`, `nltest`, and `net.exe` generated local events



In Microsoft Sentinel:



\- Other Security Events were visible

\- `4688` events from `CLIENT01` were missing

\- Queries against the `SecurityEvent` table returned no matching results



\## Collection Architecture



The system used:



\- Azure Arc

\- Azure Monitor Agent

\- Data Collection Rule

\- Microsoft Sentinel

\- `SecurityEvent` table



\## Relevant AMA Configuration Path



The actual Azure Monitor Agent configuration path on `CLIENT01` was:



```text

C:\\Resources\\Directory\\AMADataStore.CLIENT01\\mcs\\mcsconfig.latest.xml

```



This path was different from several commonly referenced locations.



\## Resolution



The issue was resolved by uninstalling and reinstalling:



```text

AzureMonitorWindowsAgent

```



After reinstallation:



\- The agent reconnected to Azure

\- The DCR configuration was reapplied

\- New `4688` events began arriving in Sentinel

\- Reconnaissance commands could be investigated successfully



\## Validation Query



```kql

SecurityEvent

| where ingestion\_time() > ago(1h)

| where EventID == 4688

| project

&#x20;   TimeGenerated,

&#x20;   IngestionTime = ingestion\_time(),

&#x20;   Computer,

&#x20;   Account,

&#x20;   NewProcessName,

&#x20;   ParentProcessName,

&#x20;   CommandLine

| order by IngestionTime desc

```



\## Ingestion Delay



The lab also observed delays between:



```text

TimeGenerated

```



and:



```text

ingestion\_time()

```



A validation query was used:



```kql

SecurityEvent

| where ingestion\_time() > ago(30m)

| where EventID == 4672

| extend IngestionTime = ingestion\_time()

| extend DelayMinutes = datetime\_diff(

&#x20;   "minute",

&#x20;   IngestionTime,

&#x20;   TimeGenerated

)

| project

&#x20;   TimeGenerated,

&#x20;   IngestionTime,

&#x20;   DelayMinutes,

&#x20;   Computer,

&#x20;   Account,

&#x20;   SubjectUserName,

&#x20;   SubjectDomainName,

&#x20;   PrivilegeList

| order by IngestionTime desc

```



\## Analytics Rule Impact



Short lookup windows can miss delayed events.



For example:



```text

Run every: 5 minutes

Lookup data from the last: 5 minutes

```



may miss events that arrive ten minutes after they were generated.



The lab therefore used longer lookup windows such as:



```text

Run every: 5 minutes

Lookup data from the last: 30 minutes

```



or:



```text

Lookup data from the last: 1 hour

```



\## Lessons from Troubleshooting



\- Always compare local event generation with SIEM ingestion

\- Use `ingestion\_time()` when investigating collection delays

\- Confirm the DCR is associated with the correct Arc-enabled machine

\- Verify the AMA extension is healthy

\- Avoid excessively short analytics-rule lookup windows

\- Reinstalling the agent can resolve corrupted or stale configuration

\- Validate event collection after every configuration change

