# Detection evaluation vs ground truth - full pipeline (rules; ML fused into risk)

> Ground truth is analyst-annotated (labels/). The development scenario was used to write the rules, so these are **development-set**
> numbers; use `experiments/` for held-out and baseline comparisons.

## Workload funnel

events 121,659 -> raw rule hits 3,398 -> alerts 33 -> alert groups 19 (dedup 0.424) -> incidents 1

## Alert level

- TP 33 | FP 0 | unverifiable 0 | precision **1.000** (95% CI 1.000-1.000)

## Process level (308 process starts; background = assumed benign)

- malicious 106 | background 197 | ambiguous excluded 5
- TP 84 FP 1 FN 22 | precision **0.988** recall **0.792** F1 0.880

Missed malicious process starts:

- 2019-05-14 22:32:23.492000+00:00 HR001 `conhost.exe` \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 2019-05-14 22:36:56.647000+00:00 HR001 `net1.exe` C:\Windows\system32\net1 start
- 2019-05-14 22:41:48.721000+00:00 HR001 `conhost.exe` \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 2019-05-14 22:43:10.278000+00:00 HR001 `net1.exe` C:\Windows\system32\net1 group "Domain Admins" /domain
- 2019-05-14 22:44:11.905000+00:00 HR001 `net1.exe` C:\Windows\system32\net1 localgroup Administrators
- 2019-05-14 22:45:18.650000+00:00 HR001 `net1.exe` C:\Windows\system32\net1 user
- 2019-05-14 22:46:15.147000+00:00 HR001 `net1.exe` C:\Windows\system32\net1 user /domain
- 2019-05-14 22:47:16.747000+00:00 HR001 `net1.exe` C:\Windows\system32\net1 group "Domain Computers" /domain
- 2019-05-14 22:51:19.229000+00:00 HR001 `conhost.exe` \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 2019-05-14 22:52:19.428000+00:00 HR001 `conhost.exe` \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 2019-05-14 22:59:48.187000+00:00 HR001 `cmd.exe` "cmd.exe" /c C:\windows\system32\autoupdate.vbs
- 2019-05-14 22:59:48.193000+00:00 HR001 `conhost.exe` \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 2019-05-14 22:59:49.121000+00:00 HR001 `wscript.exe` "C:\Windows\System32\WScript.exe" "C:\windows\system32\autoupdate.vbs" 
- 2019-05-14 22:59:49.644000+00:00 HR001 `conhost.exe` \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 2019-05-14 23:12:24.489000+00:00 HR001 `sc.exe` "C:\Windows\system32\sc.exe" \\HFDC01 query
- 2019-05-14 23:14:27.579000+00:00 HR001 `sc.exe` "C:\Windows\system32\sc.exe" \\HFDC01 qc AdobeUpdater
- 2019-05-14 23:16:09.836000+00:00 HR001 `sc.exe` "C:\Windows\system32\sc.exe" \\HFDC01 start AdobeUpdater
- 2019-05-14 23:16:09.942000+00:00 HFDC01 `cmd.exe` cmd.exe /c "C:\Users\pgustavo\AppData\Roaming\Adobe\Flash Player\autoupdate.vbs" 
- 2019-05-14 23:16:10.718000+00:00 HFDC01 `conhost.exe` \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 2019-05-14 23:35:37.079000+00:00 HR001 `recycler.exe` "C:\Windows\system32\recycler.exe" a -t7z C:\$Recycle.Bin\old.7z C:\$Recycle.Bin\recipe.tx
- 2019-05-14 23:37:55.957000+00:00 HR001 `ftp.exe` "C:\Windows\System32\ftp.exe" -v -s:ftp.txt
- 2019-05-14 23:42:00.723000+00:00 HR001 `mstsc.exe` "C:\Windows\system32\mstsc.exe" 

Flagged but background (possible FPs or labelling gaps):

- 2019-05-14 23:44:30.570000+00:00 HFDC01 `sethc.exe` "C:\Windows\System32\Sethc.exe" /AccessibilitySoundAgent

## Step level

- Step detection rate **1.000** | technique coverage exact 1.000 / family 1.000 | median TTD 1.918 s

| step | name | host | detected | alerts | tech exact | tech family | missed techniques | TTD s |
|---|---|---|---|---|---|---|---|---|
| ST01 | Script delivered via browser | HR001 | yes | 1 | 1.000 | 1.000 |  | -0.085 |
| ST02 | User executes script / WSH spawns shell | HR001 | yes | 2 | 1.000 | 1.000 |  | 0.000 |
| ST03 | Obfuscated hidden PowerShell stager | HR001 | yes | 3 | 1.000 | 1.000 |  | 1.283 |
| ST04 | Logging/AMSI bypass + download cradle | HR001 | yes | 5 | 1.000 | 1.000 |  | -6.767 |
| ST05 | C2 beaconing (workstation) | HR001 | yes | 3 | 1.000 | 1.000 |  | 2.553 |
| ST06 | Host and domain discovery | HR001 | yes | 2 | 1.000 | 1.000 |  | 10.519 |
| ST07 | Password spraying admin shares / lateral | HR001 | yes | 3 | 1.000 | 1.000 |  | 11.537 |
| ST08 | Script staged in System32 (HR001) | HR001 | yes | 5 | 1.000 | 1.000 |  | -1566.874 |
| ST09 | Remote service created on the DC | HFDC01 | yes | 2 | 1.000 | 1.000 |  | 0.000 |
| ST10 | SYSTEM Empire agent on the DC | HFDC01 | yes | 4 | 1.000 | 1.000 |  | 0.439 |
| ST11 | C2 beaconing (DC) | HFDC01 | yes | 1 | 1.000 | 1.000 |  | 3.468 |
| ST12 | DC discovery | HFDC01 | yes | 1 | 1.000 | 1.000 |  | 19.357 |
| ST13 | takeown/icacls + overwrite Magnify.exe | HFDC01 | yes | 2 | 1.000 | 1.000 |  | 0.014 |
| ST14 | Data staged in Recycle Bin | HR001 | yes | 1 | 1.000 | 1.000 |  | 7.047 |
| ST15 | RDP session to the DC | HFDC01 | yes | 1 | 1.000 | 1.000 |  | 7.322 |
| ST16 | Accessibility backdoor triggered | HFDC01 | yes | 1 | 1.000 | 1.000 |  | 3.851 |

## Incident level

```
{
 "n_incidents": 1,
 "n_true_incidents": 1,
 "fragmentation": 0,
 "alerts_in_largest_incident": 33,
 "tactics_observed": [
  "Initial Access",
  "Execution",
  "Defense Evasion",
  "Command and Control",
  "Discovery",
  "Lateral Movement",
  "Credential Access",
  "Persistence",
  "Collection"
 ],
 "tactic_recall": 1.0,
 "tactics_missed": [],
 "kill_chain_kendall_tau": 0.8333333333333334,
 "share_of_alerts_in_incident": 1.0
}
```

## Per-rule hit precision

| rule | hits | malicious | background | benign | ambiguous | hit precision |
|---|---|---|---|---|---|---|
| PY-001 | 47 | 47 | 0 | 0 | 0 | 1.000 |
| PY-002 | 3121 | 3121 | 0 | 0 | 0 | 1.000 |
| PY-003 | 64 | 64 | 0 | 0 | 0 | 1.000 |
| PY-006 | 2 | 2 | 0 | 0 | 0 | 1.000 |
| SIG-001 | 3 | 3 | 0 | 0 | 0 | 1.000 |
| SIG-002 | 7 | 7 | 0 | 0 | 0 | 1.000 |
| SIG-003 | 5 | 5 | 0 | 0 | 0 | 1.000 |
| SIG-004 | 6 | 6 | 0 | 0 | 0 | 1.000 |
| SIG-005 | 4 | 4 | 0 | 0 | 0 | 1.000 |
| SIG-006 | 67 | 67 | 0 | 0 | 0 | 1.000 |
| SIG-007 | 47 | 47 | 0 | 0 | 0 | 1.000 |
| SIG-008 | 2 | 2 | 0 | 0 | 0 | 1.000 |
| SIG-009 | 3 | 3 | 0 | 0 | 0 | 1.000 |
| SIG-010 | 4 | 4 | 0 | 0 | 0 | 1.000 |
| SIG-011 | 2 | 2 | 0 | 0 | 0 | 1.000 |
| SIG-012 | 2 | 2 | 0 | 0 | 0 | 1.000 |
| SIG-013 | 5 | 4 | 1 | 0 | 0 | 0.800 |
| SIG-014 | 2 | 2 | 0 | 0 | 0 | 1.000 |
| SIG-016 | 4 | 3 | 1 | 0 | 0 | 0.750 |
| SIG-017 | 1 | 1 | 0 | 0 | 0 | 1.000 |

## Event level (supplementary)

- excluding beacon connections: precision 0.981 recall 0.002 (recall is low by construction: 35k PowerShell log lines are never individually alerted)