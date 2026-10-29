# Step 4 - Detection report

- Events analysed: **121,659**
- Events involved in at least one rule alert: **3,226** (2.65%)
- Rule alerts: **33** | ML-only review alerts: **2** | Incidents: **1**
- Severity (rule alerts): {'critical': 14, 'high': 11, 'medium': 8}

## Incidents

### INC-001 - Multi-stage intrusion across HFDC01, HR001  (risk 0.99)

Hosts: HFDC01, HR001 | Users: nmartha, pgustavo, system | 22:32:03 -> 23:47:41 UTC

Kill chain observed: Initial Access > Execution > Defense Evasion > Credential Access > Discovery > Lateral Movement > Persistence > Collection > Command and Control

```
22:32:03 HR001   Initial Access       T1189      Script file downloaded by a web browser
22:32:22 HR001   Execution            T1204.002  Script executed from Downloads / AppData / Temp
22:32:23 HR001   Execution            T1059.005  Script host spawning a shell (wscript/cscript/mshta -> powershell/cmd)
22:32:23 HR001   Defense Evasion      T1027      PowerShell with encoded command
22:32:23 HR001   Defense Evasion      T1564.003  PowerShell hidden window + no profile
22:32:32 HR001   Command and Control  T1105      PowerShell download cradle in script block
22:32:32 HR001   Defense Evasion      T1562.001  PowerShell logging / AMSI bypass in script block
22:32:36 HR001   Command and Control  T1071.001  Sustained high-frequency beaconing from a script engine
22:34:11 HR001   Discovery            T1087      Discovery commands spawned by PowerShell
22:34:52 HR001   Discovery            T1082      Discovery burst inside one process chain
22:51:21 HR001   Command and Control  T1105      PowerShell download cradle in script block
22:51:21 HR001   Defense Evasion      T1564.003  PowerShell hidden window + no profile
22:51:21 HR001   Defense Evasion      T1562.001  PowerShell logging / AMSI bypass in script block
22:54:13 HR001   Lateral Movement     T1021.002  net use with explicit credentials to an admin share
22:54:13 HR001   Credential Access    T1110.003  Password-guessing burst against admin shares
22:54:15 HR001   Lateral Movement     T1021      Account used on several hosts within minutes
22:58:56 HR001   Persistence          T1546.008  Executable or script written to System32 by a script engine
22:59:49 HR001   Execution            T1059.005  Script host spawning a shell (wscript/cscript/mshta -> powershell/cmd)
23:13:31 HR001   Persistence          T1543.003  Service created via sc.exe (local or remote)
23:13:31 HFDC01  Persistence          T1543.003  Service installed that runs cmd/script from a user profile
23:13:31 HFDC01  Persistence          T1543.003  Persistence installed right after lateral movement into the host
23:16:10 HFDC01  Execution            T1204.002  Script executed from Downloads / AppData / Temp
23:16:10 HFDC01  Execution            T1059.005  Script host spawning a shell (wscript/cscript/mshta -> powershell/cmd)
23:16:10 HFDC01  Defense Evasion      T1027      PowerShell with encoded command
23:16:10 HFDC01  Defense Evasion      T1564.003  PowerShell hidden window + no profile
23:16:13 HFDC01  Command and Control  T1071.001  Sustained high-frequency beaconing from a script engine
23:17:50 HFDC01  Discovery            T1087      Discovery commands spawned by PowerShell
23:19:02 HFDC01  Defense Evasion      T1222.001  Ownership/permission change on a System32 binary (takeown / icacls)
23:29:48 HFDC01  Persistence          T1546.008  Executable or script written to System32 by a script engine
23:33:07 HR001   Collection           T1074.001  Data staged in the Recycle Bin / System32 text file by PowerShell
23:34:30 HR001   Persistence          T1546.008  Executable or script written to System32 by a script engine
23:43:10 HFDC01  Lateral Movement     T1021.001  Remote Desktop (type 10) logon
23:44:30 HFDC01  Persistence          T1546.008  Child process spawned by an accessibility binary
```

## Rule coverage (raw event hits per rule)

| rule | title | tactic | technique | raw hits |
|---|---|---|---|---|
| SIG-016 | Script file downloaded by a web browser | Initial Access | T1189 | 4 |
| SIG-001 | Script host spawning a shell (wscript/cscript/mshta -> powershell/cmd) | Execution | T1059.005 | 3 |
| SIG-002 | PowerShell with encoded command | Defense Evasion | T1027 | 7 |
| SIG-003 | PowerShell hidden window + no profile | Defense Evasion | T1564.003 | 5 |
| SIG-004 | PowerShell download cradle in script block | Command and Control | T1105 | 6 |
| SIG-005 | PowerShell logging / AMSI bypass in script block | Defense Evasion | T1562.001 | 4 |
| SIG-006 | Discovery commands spawned by PowerShell | Discovery | T1087 | 67 |
| SIG-007 | net use with explicit credentials to an admin share | Lateral Movement | T1021.002 | 47 |
| SIG-017 | Service created via sc.exe (local or remote) | Persistence | T1543.003 | 1 |
| SIG-008 | Service installed that runs cmd/script from a user profile | Persistence | T1543.003 | 2 |
| SIG-009 | Ownership/permission change on a System32 binary (takeown / icacls) | Defense Evasion | T1222.001 | 3 |
| SIG-010 | Executable or script written to System32 by a script engine | Persistence | T1546.008 | 4 |
| SIG-011 | Data staged in the Recycle Bin / System32 text file by PowerShell | Collection | T1074.001 | 2 |
| SIG-012 | Script executed from Downloads / AppData / Temp | Execution | T1204.002 | 2 |
| SIG-013 | Child process spawned by an accessibility binary | Persistence | T1546.008 | 5 |
| SIG-014 | Remote Desktop (type 10) logon | Lateral Movement | T1021.001 | 2 |
| SIG-015 | LSASS memory access with credential-dumping access mask | Credential Access | T1003.001 | 0 |
| PY-001 | Password-guessing burst (net use /user:) | Credential Access | T1110.003 | 47 |
| PY-002 | Sustained C2 beaconing from script engine | Command and Control | T1071.001 | 3121 |
| PY-003 | Discovery burst in one process chain | Discovery | T1082 | 64 |
| PY-005 | Account used on several hosts in minutes | Lateral Movement | T1021 | 6 |
| PY-006 | Persistence right after lateral movement | Persistence | T1543.003 | 2 |
| ML-001 | Isolation Forest anomalous process | Execution | n/a | 2 |

## All rule alerts (sorted by time)

| id | rule | host | user | time | n | risk | sev | ML |
|---|---|---|---|---|---|---|---|---|
| ALR-0002 | SIG-016 Script file downloaded by a web browser | HR001 | nmartha | 22:32:03 | 4 | 0.58 | medium | - |
| ALR-0003 | SIG-012 Script executed from Downloads / AppData / Temp | HR001 | nmartha | 22:32:22 | 1 | 0.88 | high | 0.542 |
| ALR-0004 | SIG-001 Script host spawning a shell (wscript/cscript/mshta ->  | HR001 | nmartha | 22:32:23 | 1 | 0.93 | critical | 0.977 |
| ALR-0005 | SIG-002 PowerShell with encoded command | HR001 | nmartha | 22:32:23 | 6 | 0.93 | critical | 0.994 |
| ALR-0006 | SIG-003 PowerShell hidden window + no profile | HR001 | nmartha | 22:32:23 | 1 | 0.68 | medium | 0.977 |
| ALR-0007 | SIG-004 PowerShell download cradle in script block | HR001 | nmartha | 22:32:32 | 1 | 0.83 | high | - |
| ALR-0008 | SIG-005 PowerShell logging / AMSI bypass in script block | HR001 | nmartha | 22:32:32 | 1 | 0.98 | critical | - |
| ALR-0009 | PY-002 Sustained high-frequency beaconing from a script engine | HR001 | nmartha | 22:32:36 | 2743 | 0.83 | high | - |
| ALR-0010 | SIG-006 Discovery commands spawned by PowerShell | HR001 | nmartha | 22:34:11 | 66 | 0.67 | medium | 0.899 |
| ALR-0011 | PY-003 Discovery burst inside one process chain | HR001 | nmartha | 22:34:52 | 64 | 0.92 | critical | 0.899 |
| ALR-0012 | SIG-004 PowerShell download cradle in script block | HR001 | nmartha | 22:51:21 | 5 | 0.83 | high | - |
| ALR-0013 | SIG-003 PowerShell hidden window + no profile | HR001 | nmartha | 22:51:21 | 3 | 0.68 | medium | 0.994 |
| ALR-0014 | SIG-005 PowerShell logging / AMSI bypass in script block | HR001 | nmartha | 22:51:21 | 3 | 0.98 | critical | - |
| ALR-0015 | SIG-007 net use with explicit credentials to an admin share | HR001 | nmartha | 22:54:13 | 47 | 0.87 | high | 0.432 |
| ALR-0016 | PY-001 Password-guessing burst against admin shares | HR001 | nmartha | 22:54:13 | 47 | 0.99 | critical | 0.432 |
| ALR-0017 | PY-005 Account used on several hosts within minutes | HR001 | pgustavo | 22:54:15 | 6 | 0.83 | high | - |
| ALR-0018 | SIG-010 Executable or script written to System32 by a script en | HR001 | nmartha | 22:58:56 | 1 | 0.83 | high | - |
| ALR-0019 | SIG-001 Script host spawning a shell (wscript/cscript/mshta ->  | HR001 | pgustavo | 22:59:49 | 1 | 0.93 | critical | 0.994 |
| ALR-0020 | SIG-017 Service created via sc.exe (local or remote) | HR001 | pgustavo | 23:13:31 | 1 | 0.93 | critical | 0.997 |
| ALR-0021 | SIG-008 Service installed that runs cmd/script from a user prof | HFDC01 | pgustavo | 23:13:31 | 2 | 0.83 | high | - |
| ALR-0022 | PY-006 Persistence installed right after lateral movement into | HFDC01 | pgustavo | 23:13:31 | 2 | 0.98 | critical | - |
| ALR-0023 | SIG-012 Script executed from Downloads / AppData / Temp | HFDC01 | system | 23:16:10 | 1 | 0.91 | critical | 0.815 |
| ALR-0024 | SIG-001 Script host spawning a shell (wscript/cscript/mshta ->  | HFDC01 | system | 23:16:10 | 1 | 0.93 | critical | 1.0 |
| ALR-0025 | SIG-002 PowerShell with encoded command | HFDC01 | system | 23:16:10 | 1 | 0.93 | critical | 1.0 |
| ALR-0026 | SIG-003 PowerShell hidden window + no profile | HFDC01 | system | 23:16:10 | 1 | 0.68 | medium | 1.0 |
| ALR-0027 | PY-002 Sustained high-frequency beaconing from a script engine | HFDC01 | system | 23:16:13 | 378 | 0.83 | high | - |
| ALR-0028 | SIG-006 Discovery commands spawned by PowerShell | HFDC01 | system | 23:17:50 | 1 | 0.67 | medium | 0.942 |
| ALR-0029 | SIG-009 Ownership/permission change on a System32 binary (takeo | HFDC01 | system | 23:19:02 | 3 | 0.92 | critical | 0.935 |
| ALR-0030 | SIG-010 Executable or script written to System32 by a script en | HFDC01 | system | 23:29:48 | 2 | 0.83 | high | - |
| ALR-0031 | SIG-011 Data staged in the Recycle Bin / System32 text file by  | HR001 | nmartha | 23:33:07 | 2 | 0.54 | medium | - |
| ALR-0032 | SIG-010 Executable or script written to System32 by a script en | HR001 | nmartha | 23:34:30 | 1 | 0.79 | high | - |
| ALR-0034 | SIG-014 Remote Desktop (type 10) logon | HFDC01 | pgustavo | 23:43:10 | 2 | 0.58 | medium | - |
| ALR-0035 | SIG-013 Child process spawned by an accessibility binary | HFDC01 | system | 23:44:30 | 5 | 0.99 | critical | 0.972 |

## ML sanity check (Isolation Forest vs. rules)

- Process-create events scored: 308
- Of the ML top-15 most anomalous, **8** were also flagged by a rule (precision@15 vs rules = 53%).
- Rule-flagged process events found inside ML top 10%: 11 of 85.
- ML-only review alerts (anomalous, no rule hit): 2.

> There are no per-event ground-truth labels in this dataset, so precision/recall against labels cannot be computed. The comparison above measures *agreement between two independent methods*, not accuracy.