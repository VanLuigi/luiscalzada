# Hunting a Live MySQL Ransomware Bot in a Homelab: From Exposed Root to Full Compromise in Under 6 Hours

**A Microsoft Sentinel + Defender for Endpoint threat hunting exercise, built from scratch on Azure.**

<img width="1731" height="909" alt="Image" src="https://github.com/user-attachments/assets/e7904b6b-c3d0-4d90-bc6c-326423d42802" />

## TL;DR

I created a Windows 11 VM on Azure, installed MySQL 8.0, seeded it with realistic dummy PII/financial data, wired up full audit logging into Microsoft Sentinel, and then **intentionally exposed it to the internet** with a weak root password. Within **6 hours** of exposure, an automated ransomware bot found it, dumped the data, destroyed it, planted a Bitcoin ransom note, purged the binary logs, revoked its own privileges, and shut the server down, all in about **32 seconds** once it got in. This writeup documents the lab build, the detection engineering, and the full threat hunt, reconstructing the attack from raw logs.

## Objective / Skills Demonstrated

- Cloud infrastructure build-out (Azure VM, NSG, Defender for Endpoint onboarding)
- Custom log source engineering (MySQL general query log → Azure Monitor Agent → Sentinel custom table)
- Detection engineering (KQL Analytics Rules for a log source with no native connector)
- Threat hunting and incident timeline reconstruction from raw authentication + query logs
- MITRE ATT&CK mapping and root-cause analysis
- Clear technical writing for a non-trivial, multi-source investigation

## Lab Architecture

<img width="1693" height="929" alt="architecture" src="https://github.com/user-attachments/assets/c1369290-11f1-4788-aba6-8f5fc1228b72" />

| Component | Detail |
|---|---|
| Host | `corp-db03` - Windows 11 VM, Azure |
| Database | MySQL 8.0.45.0 (Community Server) |
| EDR | Microsoft Defender for Endpoint (onboarded) |
| SIEM | Microsoft Sentinel |
| Log ingestion | Azure Monitor Agent (AMA), custom-text-log Data Collection Rule (DCR) |
| Seed data | `sakila` (MySQL sample DB), `world` (MySQL sample DB), `fin_cmpy` (custom-built fake company DB) |

### Dummy Data Design (`fin_cmpy`)

To make the target look like a real target worth stealing from, I built four related tables and populated them programmatically:

- `customers` - full PII (name, email, address, DOB, fake SSN), ~3,500 rows
- `orders` - purchases tied to customers
- `payments` - masked card data + last4 per order
- `credentials` - fake application logins (the "juiciest" table for an attacker)

## Step 1 — Enabling MySQL Audit Logging

MySQL doesn't have a native Sentinel connector, so raw general-query-log ingestion was required.

```sql
SET GLOBAL general_log = 'ON';
SET GLOBAL log_output = 'FILE';
SHOW VARIABLES LIKE 'general_log%';
```

`my.ini` was updated to point logging at:
```
C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log
```

## Step 2 — Shipping Logs to Sentinel

A custom-text-log DCR was created pointing the Azure Monitor Agent at the log file, landing in a new custom table `MySQLAudit_CL`.

| DCR Setting | Value |
|---|---|
| File pattern | `C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log` |
| Table name | `MySQLAudit_CL` |
| Record delimiter | Timestamp |
| Timestamp format | ISO 8601 |

Ingestion verified with:

```kql
MySQLAudit_CL
| project TimeGenerated, RawData, _ResourceId
| where _ResourceId endswith "corp-db03"
```

<img width="1035" height="511" alt="image" src="https://github.com/user-attachments/assets/a08ebad7-d808-40de-a856-7993684f5278" />


## Step 3 — Detection Engineering: Two Analytics Rules

### Rule 1 — `CDF-corp-db03` (Windows logon monitoring)

```kql
let MyDevice = "corp-db03";
DeviceLogonEvents
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| where ActionType == "LogonSuccess"
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
```

<img width="1402" height="709" alt="image" src="https://github.com/user-attachments/assets/8b86f90f-f6f3-4213-9206-f39d3d2074d6" />


### Rule 2 — `CDF-corp-db03-MySQL` (MySQL logon parsing)

The MySQL general log has no structured `ActionType` field it's raw text. This rule parses connection IDs out of the raw log lines, correlates `Connect` events against `Access denied` events by connection ID, and derives a clean `LogonSuccess` / `LogonFailure` classification:

```kql
let MyDevice = "corp-db03";
let FailedConnections =
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Access denied"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| distinct ConnectionId;
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Connect"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| extend ActionType =
    case(
        RawData has "Access denied", "LogonFailure",
        ConnectionId in (FailedConnections), "Ignore",
        "LogonSuccess"
    )
| where ActionType != "Ignore"
| extend Username = replace_string(tostring(split(tostring(split(RawData,"@")[0]), " ")[-1]), "'", "")
| extend IpAddress = replace_string(tostring(split(split(RawData,"@")[1], " ")[0]), "'", "")
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, Username, IpAddress, ActionType, RawData
| order by TimeGenerated desc
```

## Step 4 — Intentionally Weakening the Environment

To simulate a realistic misconfiguration (this happens far more often in the wild than it should), I deliberately:

1. Set the local `Administrator` account password to `qwerty`, added `Guest` to the `Users` group, and ran `gpupdate /force`.
2. Opened MySQL to the network with a trivially guessable credential pair:
   ```sql
   CREATE USER 'root'@'%' IDENTIFIED BY 'root';
   GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
   FLUSH PRIVILEGES;
   ```
3. Disabled Windows Firewall entirely (all profiles).
4. Weakened the Azure NSG to allow **all inbound traffic**.

Timestamp of exposure: **`2026-08-04T16:33:33Z`**

Internal address space for reference/exclusion during hunting: `10.0.0.0/21`, `10.1.0.0/21`, `10.2.0.0/16`, `10.3.0.0/16` (also monitored by Tenable, expected internal scan noise).

## The Attack: Reconstructed Timeline

| Time (UTC) | Event |
|---|---|
| `2026-08-04T16:33:33Z` | Firewall/NSG opened - exposure window begins |
| `2026-08-05T00:20:46Z` | `root@'%'` created with weak password, granted full privileges |
| `2026-08-05T04:04:50Z` | First external probe: `root@64.89.163.146` - access denied, no password |
| `2026-08-05T05:08:03–05Z` | Generic credential-stuffing bot (`77.90.185.30`) tries `root`/`admin`/`sa` - all fail |
| `2026-08-05T06:19:10Z` | `64.89.163.80` fails root login with no password |
| `2026-08-05T06:19:20Z` | `64.89.163.80` fails again |
| **`2026-08-05T06:19:27Z`** | **`64.89.163.80` succeeds** almost certainly guessed `root`/`root` |
| `06:19:27Z – 06:19:57Z` | Recon: `SHOW DATABASES`, schema enumeration via `INFORMATION_SCHEMA`, `SELECT *` against every table in `sakila`, `world`, `fin_cmpy` (including `customers`, `credentials`, `payments`, `orders`) |
| `06:19:56Z – 06:19:57Z` | `DROP DATABASE`/`DROP TABLE` executed against all three schemas |
| `06:19:57Z` | `RECOVER_YOUR_DATA` database/table created; ransom note inserted (0.0132 BTC to `bc1q7jps5432akuflg9flw2vu6hgmmj5hrrdu6c5gm`, contact `ak+24lv3@onionmail.org`, DATAID `24LV3`) |
| `06:19:58Z` | `RESET MASTER` + `PURGE BINARY LOGS`  anti-forensics, kills point-in-time recovery |
| `06:19:59Z` | `REVOKE INSERT, UPDATE, DELETE, DROP, CREATE ON *.* FROM 'root'@'%'` then `SHUTDOWN` — bot locks the door behind itself |
| Aug 5 – Aug 9 (recurring) | Multiple **different** source IPs (`77.90.185.21`, `213.209.159.115`, `64.89.163.x` range, others) repeatedly rediscover the exposed instance, re-read the ransom table, and in some cases re-run the entire drop/ransom sequence, evidence of mass opportunistic internet-wide scanning rather than a single targeted actor |

**Total time from first successful login to full compromise + self-lockout: ~32 seconds.** This is a fully scripted bot, not a human operator.

```kql
let MyDevice = "corp-db03";
let MyTimeframe = todatetime("2026-08-04T16:33:33Z");
let FailedConnections =
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Access denied"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| distinct ConnectionId;
MySQLAudit_CL
| where TimeGenerated > MyTimeframe
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Connect"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| extend ActionType =
    case(
        RawData has "Access denied", "LogonFailure",
        ConnectionId in (FailedConnections), "Ignore",
        "LogonSuccess"
    )
| where ActionType != "Ignore"
| extend RawData = replace_string(RawData, "\t", " ")
| extend Username = replace_string(tostring(split(tostring(split(RawData,"@")[0]), " ")[-1]), "'", "")
| extend IpAddress = replace_string(tostring(split(split(RawData,"@")[1], " ")[0]), "'", "")
| project TimeGenerated, DeviceName, Username, IpAddress, ActionType, RawData
| order by TimeGenerated desc
```

<img width="1237" height="766" alt="image" src="https://github.com/user-attachments/assets/40687fe7-c14d-410c-ba7b-633b49ee9809" />



```kql
let MyDevice = "corp-db03"; // set your own device name
let ServerVulnerableDateTime = todatetime("2026-08-04T16:33:33Z");
MySQLAudit_CL
| where TimeGenerated > ServerVulnerableDateTime
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| extend ActionType = "Query"
| extend Query = split(RawData, "Query")[1]
| project TimeGenerated, DeviceName, ActionType, Query, RawData
| order by TimeGenerated desc
```

<img width="1291" height="723" alt="image" src="https://github.com/user-attachments/assets/84e62c03-ae4c-4b99-82ee-05cd7bde6290" />




## Why the Windows-Level Logs Showed "Nothing Suspicious"

When I first checked `DeviceLogonEvents` for `corp-db03`, nothing stood out, no failed RDP attempts, no suspicious interactive logons. This is expected and worth calling out: **the attacker never authenticated to Windows at all.** The entire attack occurred inside the MySQL protocol on port 3306, which is invisible to OS-level authentication logging. This is exactly why the custom MySQL audit log ingestion pipeline mattered without it, this incident would have been completely dark to a SOC relying only on native Windows/Defender telemetry.


## Indicators of Compromise

| Type | Value |
|---|---|
| Attacker IP (successful) | `64.89.163.80` (and sibling IPs in `64.89.163.0/24`: `.89`, `.94`, `.139`, `.146`, `.148`, `.149`, `.154`, `.159`, `.178`) |
| Scanning/credential-stuffing IPs | `77.90.185.21`, `77.90.185.30`, `213.209.159.115`, `8.222.128.242`, `34.22.251.168`, `35.187.94.117`, `35.195.83.227`, `8.138.155.88`, `34.38.106.221`, `34.38.108.126` |
| Ransom database/table | `RECOVER_YOUR_DATA`, `RECOVER_YOUR_DATA_info` |
| BTC address | `bc1q7jps5432akuflg9flw2vu6hgmmj5hrrdu6c5gm` |
| Contact email | `ak+24lv3@onionmail.org` |
| DATAID | `24LV3` |
| Anti-forensics commands | `RESET MASTER`, `PURGE BINARY LOGS TO 'josh-mde-lab-bin.000001'` |

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1190 – Exploit Public-Facing Application | Internet-exposed MySQL with weak credentials |
| Initial Access | T1078 – Valid Accounts | Guessed `root`/`root` |
| Discovery | T1082 / T1046 | `SHOW DATABASES`, `INFORMATION_SCHEMA` enumeration |
| Collection | T1213 | `SELECT *` against `customers`, `credentials`, `payments` |
| Impact | T1485 – Data Destruction | `DROP DATABASE` / `DROP TABLE` |
| Impact | T1486 – Data Encrypted for Impact (extortion variant) | Ransom note insertion, BTC demand |
| Defense Evasion | T1070.002 – Clear Logs (indirect) | `RESET MASTER`, `PURGE BINARY LOGS` |
| Impact | T1489 – Service Stop | `SHUTDOWN` after privilege revocation |

## Root Cause & Remediation

1. **Root cause:** `root@'%'` with a weak, guessable password, combined with an NSG rule allowing unrestricted inbound access to port 3306.
2. **Never expose database ports directly to the internet.** Require a VPN, bastion host, or Private Link/Private Endpoint for any remote DB administration.
3. **Disable password-less/weak-password root** entirely; enforce strong, unique credentials, and disable remote root login (`root@'%'` should not exist).
4. **Least privilege** application accounts should never have `DROP`/`CREATE`/`SHUTDOWN` rights.
5. **Enable binary logging redundancy** ship binlogs off-host so `RESET MASTER`/`PURGE BINARY LOGS` doesn't destroy all recovery options.
6. **Monitor the application**, not just OS/EDR telemetry this incident was invisible at the Windows logon layer.

## Appendix — Full Ransom Note

```
All your data was backed up by us. You must pay 0.0132 bitcoin to
bc1q7jps5432akuflg9flw2vu6hgmmj5hrrdu6c5gm or in 48 hours, your data
will be publicly disclosed and deleted.

(for more information visit https://bit.ly/22mysql) After payment
send mail to ak+24lv3@onionmail.org and we will provide a link for
you to download your data. Your DATAID is: 24LV3
```

---

*This lab was built entirely in a personal Azure sandbox with synthetic/fake data. No real customer, employee, or financial data was ever present on this system.*
