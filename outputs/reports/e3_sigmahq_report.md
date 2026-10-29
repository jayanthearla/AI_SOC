# Detection evaluation vs ground truth - SigmaHQ (unmodified, converted subset)

> Ground truth is analyst-annotated (labels/). The development scenario was used to write the rules, so these are **development-set**
> numbers; use `experiments/` for held-out and baseline comparisons.

## Workload funnel

events 121,659 -> raw rule hits 123 -> alerts 35 -> alert groups 21 (dedup 0.400) -> incidents 0

## Alert level

- TP 26 | FP 9 | unverifiable 0 | precision **0.743** (95% CI 0.571-0.886)
  - FP: SGMA-0001 SGMA-50f852e6 on HR001 (1 events, 1 background)
  - FP: SGMA-0002 SGMA-b8fd0e93 on HR001 (1 events, 1 background)
  - FP: SGMA-0015 SGMA-b8fd0e93 on HR001 (1 events, 1 background)
  - FP: SGMA-0020 SGMA-3a9b8c1e on HFDC01 (2 events, 2 background)
  - FP: SGMA-0021 SGMA-b8fd0e93 on HR001 (2 events, 2 background)
  - FP: SGMA-0029 SGMA-b8fd0e93 on HR001 (1 events, 1 background)
  - FP: SGMA-0030 SGMA-3a9b8c1e on HR001 (2 events, 2 background)
  - FP: SGMA-0032 SGMA-ed74fe75 on HR001 (3 events, 3 background)
  - FP: SGMA-0033 SGMA-b8fd0e93 on HR001 (1 events, 1 background)

## Process level (308 process starts; background = assumed benign)

- malicious 106 | background 197 | ambiguous excluded 5
- TP 68 FP 0 FN 38 | precision **1.000** recall **0.642** F1 0.782

Missed malicious process starts:

- 2019-05-14 22:32:22.132000+00:00 HR001 `wscript.exe` "C:\Windows\System32\WScript.exe" "C:\Users\nmartha\Downloads\autoupdate.vbs" 
- 2019-05-14 22:32:23.492000+00:00 HR001 `conhost.exe` \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 2019-05-14 22:34:11.227000+00:00 HR001 `route.exe` "C:\Windows\system32\ROUTE.EXE" print
- 2019-05-14 22:34:52.560000+00:00 HR001 `ipconfig.exe` "C:\Windows\system32\ipconfig.exe" /all
- 2019-05-14 22:36:15.287000+00:00 HR001 `qprocess.exe` "C:\Windows\system32\qprocess.exe" *
- 2019-05-14 22:36:56.596000+00:00 HR001 `net.exe` "C:\Windows\system32\net.exe" start
- 2019-05-14 22:36:56.647000+00:00 HR001 `net1.exe` C:\Windows\system32\net1 start
- 2019-05-14 22:41:48.721000+00:00 HR001 `conhost.exe` \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 2019-05-14 22:42:04.879000+00:00 HR001 `netstat.exe` "C:\Windows\system32\NETSTAT.EXE" -ano
- 2019-05-14 22:46:15.117000+00:00 HR001 `net.exe` "C:\Windows\system32\net.exe" user /domain
- 2019-05-14 22:46:15.147000+00:00 HR001 `net1.exe` C:\Windows\system32\net1 user /domain
- 2019-05-14 22:48:03.002000+00:00 HR001 `net.exe` "C:\Windows\system32\net.exe" use
- 2019-05-14 22:48:44.356000+00:00 HR001 `netstat.exe` "C:\Windows\system32\NETSTAT.EXE" -ano
- 2019-05-14 22:49:56.158000+00:00 HR001 `reg.exe` "C:\Windows\system32\reg.exe" query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentV
- 2019-05-14 22:51:19.229000+00:00 HR001 `conhost.exe` \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 2019-05-14 22:54:15.044000+00:00 HR001 `net.exe` "C:\Windows\system32\net.exe" use /delete \\IT001\ADMIN$
- 2019-05-14 22:54:37.872000+00:00 HR001 `net.exe` "C:\Windows\system32\net.exe" use /delete \\ACCT001\ADMIN$
- 2019-05-14 22:55:00.378000+00:00 HR001 `net.exe` "C:\Windows\system32\net.exe" use /delete \\HFDC01\ADMIN$
- 2019-05-14 22:57:08.792000+00:00 HR001 `net.exe` "C:\Windows\system32\net.exe" use /delete \\HFDC01\ADMIN$
- 2019-05-14 22:59:48.187000+00:00 HR001 `cmd.exe` "cmd.exe" /c C:\windows\system32\autoupdate.vbs
- 2019-05-14 22:59:48.193000+00:00 HR001 `conhost.exe` \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 2019-05-14 22:59:49.121000+00:00 HR001 `wscript.exe` "C:\Windows\System32\WScript.exe" "C:\windows\system32\autoupdate.vbs" 
- 2019-05-14 22:59:49.644000+00:00 HR001 `conhost.exe` \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 2019-05-14 23:12:24.489000+00:00 HR001 `sc.exe` "C:\Windows\system32\sc.exe" \\HFDC01 query
- 2019-05-14 23:14:27.579000+00:00 HR001 `sc.exe` "C:\Windows\system32\sc.exe" \\HFDC01 qc AdobeUpdater

## Step level

- Step detection rate **0.375** | technique coverage exact 0.111 / family 0.250 | median TTD 1.050 s

| step | name | host | detected | alerts | tech exact | tech family | missed techniques | TTD s |
|---|---|---|---|---|---|---|---|---|
| ST01 | Script delivered via browser | HR001 | **NO** | 0 | 0.000 | 0.000 | T1189 | n/a |
| ST02 | User executes script / WSH spawns shell | HR001 | yes | 6 | 0.000 | 0.500 | T1059.005, T1204.002 | 1.283 |
| ST03 | Obfuscated hidden PowerShell stager | HR001 | yes | 1 | 0.000 | 0.000 | T1027, T1564.003 | -30.093 |
| ST04 | Logging/AMSI bypass + download cradle | HR001 | **NO** | 0 | 0.000 | 0.000 | T1105, T1562.001 | n/a |
| ST05 | C2 beaconing (workstation) | HR001 | **NO** | 0 | 0.000 | 0.000 | T1071.001 | n/a |
| ST06 | Host and domain discovery | HR001 | yes | 2 | 0.000 | 0.500 | T1082, T1087 | 93.180 |
| ST07 | Password spraying admin shares / lateral | HR001 | **NO** | 0 | 0.000 | 0.000 | T1021, T1021.002, T1110.003 | n/a |
| ST08 | Script staged in System32 (HR001) | HR001 | yes | 7 | 0.000 | 0.000 | T1546.008 | -1566.874 |
| ST09 | Remote service created on the DC | HFDC01 | **NO** | 0 | 0.000 | 0.000 | T1543.003 | n/a |
| ST10 | SYSTEM Empire agent on the DC | HFDC01 | yes | 4 | 0.000 | 0.333 | T1027, T1059.005, T1564.003 | 0.818 |
| ST11 | C2 beaconing (DC) | HFDC01 | **NO** | 0 | 0.000 | 0.000 | T1071.001 | n/a |
| ST12 | DC discovery | HFDC01 | **NO** | 0 | 0.000 | 0.000 | T1087 | n/a |
| ST13 | takeown/icacls + overwrite Magnify.exe | HFDC01 | yes | 1 | 0.000 | 0.000 | T1222.001, T1546.008 | 646.669 |
| ST14 | Data staged in Recycle Bin | HR001 | **NO** | 0 | 0.000 | 0.000 | T1074.001 | n/a |
| ST15 | RDP session to the DC | HFDC01 | **NO** | 0 | 0.000 | 0.000 | T1021.001 | n/a |
| ST16 | Accessibility backdoor triggered | HFDC01 | **NO** | 0 | 0.000 | 0.000 | T1546.008 | n/a |

## Incident level

```
{
 "n_incidents": 0,
 "n_true_incidents": 1,
 "fragmentation": 0
}
```

## Per-rule hit precision

| rule | hits | malicious | background | benign | ambiguous | hit precision |
|---|---|---|---|---|---|---|
| SGMA-17a1be64 | 1 | 1 | 0 | 0 | 0 | 1.000 |
| SGMA-3037d961 | 1 | 1 | 0 | 0 | 0 | 1.000 |
| SGMA-3a9b8c1e | 4 | 0 | 4 | 0 | 0 | 0.000 |
| SGMA-502b42de | 53 | 53 | 0 | 0 | 0 | 1.000 |
| SGMA-50f852e6 | 1 | 0 | 1 | 0 | 0 | 0.000 |
| SGMA-7047d730 | 4 | 4 | 0 | 0 | 0 | 1.000 |
| SGMA-79f4ede3 | 5 | 5 | 0 | 0 | 0 | 1.000 |
| SGMA-85ff530b | 1 | 1 | 0 | 0 | 0 | 1.000 |
| SGMA-8de1cbe8 | 2 | 2 | 0 | 0 | 0 | 1.000 |
| SGMA-91edcfb1 | 9 | 9 | 0 | 0 | 0 | 1.000 |
| SGMA-95eadcb2 | 3 | 3 | 0 | 0 | 0 | 1.000 |
| SGMA-ae7fbf8e | 5 | 5 | 0 | 0 | 0 | 1.000 |
| SGMA-b8fd0e93 | 6 | 0 | 6 | 0 | 0 | 0.000 |
| SGMA-ca2092a1 | 1 | 1 | 0 | 0 | 0 | 1.000 |
| SGMA-d95de845 | 6 | 6 | 0 | 0 | 0 | 1.000 |
| SGMA-e0d6c087 | 4 | 4 | 0 | 0 | 0 | 1.000 |
| SGMA-ed74fe75 | 3 | 0 | 3 | 0 | 0 | 0.000 |
| SGMA-f4bbd493 | 7 | 7 | 0 | 0 | 0 | 1.000 |
| SGMA-fb843269 | 7 | 7 | 0 | 0 | 0 | 1.000 |

## Event level (supplementary)

- excluding beacon connections: precision 0.875 recall 0.002 (recall is low by construction: 35k PowerShell log lines are never individually alerted)