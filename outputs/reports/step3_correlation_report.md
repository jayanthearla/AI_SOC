# Step 3 - Correlation report

- Process chains: **195** (notable: **3**)
- Notable events: **3,271** of 121,659 (2.7%)
- Activity sessions: **5**  |  Lateral links: **24**
- IP -> host map learned from data: {'172.18.39.100': 'ACCT001', '172.18.39.5': 'HFDC01', '172.18.39.106': 'HR001', '172.18.39.105': 'IT001'}

## Notable process chains

| chain | host | user | start (UTC) | events | narrative |
|---|---|---|---|---|---|
| CH-0020 | HR001 | nmartha | 22:32:15 | 35 | svchost.exe => rundll32.exe |
| CH-0024 | HR001 | nmartha | 22:32:22 | 16008 | explorer.exe => wscript.exe (x2) -> powershell.exe (x6) -> conhost.exe (x6) -> route.exe -> ipconfig.exe -> whoami.exe (x2) -> qprocess.exe -> net.exe |
| CH-0119 | HFDC01 | SYSTEM | 23:16:09 | 1022 | services.exe => cmd.exe -> wscript.exe -> powershell.exe -> conhost.exe -> reg.exe -> takeown.exe -> icacls.exe (x2) |

## Sessions

| session | host | start | end | min | users | notable events |
|---|---|---|---|---|---|---|
| SES-003 | HR001 | 22:32:15 | 22:59:50 | 27.6 | nmartha,pgustavo | 94 |
| SES-004 | HR001 | 23:12:24 | 23:16:09 | 3.8 | pgustavo | 4 |
| SES-001 | HFDC01 | 23:13:31 | 23:31:10 | 17.7 | pgustavo,system | 12 |
| SES-005 | HR001 | 23:34:30 | 23:43:04 | 8.6 | nmartha | 6 |
| SES-002 | HFDC01 | 23:43:02 | 23:43:59 | 0.9 | hfdc01$,pgustavo | 17 |

## Lateral links (aggregated)

| src | dst | user | method | count | first |
|---|---|---|---|---|---|
| HR001 | HFDC01 | nmartha | share_access(\\*\IPC$) | 5 | 22:43:10 |
| HR001 | IT001 | pgustavo | remote_logon_type3(Kerberos) | 1 | 22:54:15 |
| HR001 | IT001 | pgustavo | explicit_credentials(4648) | 1 | 22:54:15 |
| HR001 | ACCT001 | pgustavo | remote_logon_type3(Kerberos) | 1 | 22:54:37 |
| HR001 | ACCT001 | pgustavo | explicit_credentials(4648) | 1 | 22:54:37 |
| HR001 | HFDC01 | pgustavo | explicit_credentials(4648) | 5 | 22:55:00 |
| HR001 | HFDC01 | pgustavo | share_access(\\*\C$) | 6 | 23:01:56 |
| HR001 | HFDC01 | pgustavo | remote_logon_type3(NTLM) | 2 | 23:43:02 |
| HR001 | HFDC01 | pgustavo | remote_logon_type10(Negotiate) | 2 | 23:43:10 |