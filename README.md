# Wazuh SIEM: Outbound Network Connection Detection via Sysmon

## Objective
Enhance endpoint visibility by developing a custom Wazuh security rule to detect unauthorized outbound network connections. Specifically, this project monitors traffic directed to port 4444, a common port utilized by Command and Control (C2) servers and reverse shells (MITRE ATT&CK: T1071).

## Technical Environment
* **SIEM:** Wazuh Manager (Linux)
* **Endpoint:** Windows 10 (Wazuh Agent)
* **Log Provider:** Microsoft Sysmon (Event ID 3: Network connection detected)

## Custom Security Rule
The following custom rule (ID: 100001) was implemented in `/var/ossec/etc/rules/local_rules.xml` to trigger a critical alert (Level 12) upon detecting the specific connection:

```xml
<group name="sysmon, windows">
  <rule id="100001" level="12">
    <if_group>sysmon</if_group>
    <field name="win.system.eventID">^3$</field>
    <field name="win.eventdata.destinationPort">^4444$</field>
    <description>Critical Outbound Connection</description>
  </rule>
</group>
```
## Proof of Concept & Execution

### 1. Connection Simulation
Generated an outbound TCP connection to port 4444 using PowerShell (`Test-NetConnection`).
<img width="1280" height="492" alt="image" src="https://github.com/user-attachments/assets/8e237ced-60b2-467f-bac8-dc0bd4979451" />

### 2. Local Log Generation
Sysmon successfully captured the network activity locally under Event ID 3.
<img width="1280" height="904" alt="image" src="https://github.com/user-attachments/assets/28ee4d89-22b5-42fb-9e18-736c8a267201" />

### 3. SIEM Alert Trigger
The Wazuh Manager parsed the Sysmon log and successfully triggered the custom rule 100001.
<img width="1280" height="327" alt="image" src="https://github.com/user-attachments/assets/f0ddb925-6661-45b9-9783-ff89f4c77417" />

### 4. Event Breakdown
The JSON structured log verifies the correct extraction of fields (`destinationPort: 4444`, `eventID: 3`).
<img width="1280" height="947" alt="image" src="https://github.com/user-attachments/assets/2b9ea06b-d40b-438a-b9a7-b74b1ae09115" />
