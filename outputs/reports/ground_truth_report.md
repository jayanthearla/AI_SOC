# Ground-truth labelling report

- Dataset: `empire_apt3`  |  attack start (UTC): 2019-05-14T22:30:00+00:00
- Labels are analyst-annotated from process lineage + seeds (see `labels/attack_seeds.yml`) and are **not** derived from rule output.

## Event-level label distribution

| label | all events | process_create only |
|---|---|---|
| malicious | 52,487 | 106 |
| benign | 831 | 0 |
| ambiguous | 72 | 5 |
| background | 68,269 | 197 |

## Malicious events by label source / seed

| source | seed | events |
|---|---|---|
| lineage | SEED-1 | 16,966 |
| lineage | SEED-2 | 64 |
| lineage | SEED-3 | 95 |
| lineage | SEED-4 | 294 |
| scope | SCOPE-PS | 35,002 |
| selector | SEL-DELIVERY | 4 |
| selector | SEL-LATERAL-IPC | 7 |
| selector | SEL-LATERAL-PGUSTAVO | 53 |
| selector | SEL-SERVICE | 2 |

## Annotated attack steps (window sanity check)

| step | name | host | start | end | malicious events | GT first event |
|---|---|---|---|---|---|---|
| ST01 | Script delivered via browser | HR001 | 22:32:00 | 22:32:21 | 3 | 22:32:03.445 |
| ST02 | User executes script / WSH spawns shell | HR001 | 22:32:21 | 22:32:30 | 343 | 22:32:22.132 |
| ST03 | Obfuscated hidden PowerShell stager | HR001 | 22:32:21 | 22:32:30 | 343 | 22:32:22.132 |
| ST04 | Logging/AMSI bypass + download cradle | HR001 | 22:32:30 | 22:33:00 | 273 | 22:32:30.182 |
| ST05 | C2 beaconing (workstation) | HR001 | 22:32:30 | 23:47:45 | 50,963 | 22:32:30.182 |
| ST06 | Host and domain discovery | HR001 | 22:34:00 | 22:50:00 | 5,245 | 22:34:00.708 |
| ST07 | Password spraying admin shares / lateral | HR001 | 22:54:00 | 22:56:00 | 9,580 | 22:54:01.463 |
| ST08 | Script staged in System32 (HR001) | HR001 | 22:58:30 | 23:00:00 | 1,511 | 22:58:30.289 |
| ST09 | Remote service created on the DC | HFDC01 | 23:13:00 | 23:14:30 | 6 | 23:13:31.343 |
| ST10 | SYSTEM Empire agent on the DC | HFDC01 | 23:16:00 | 23:16:30 | 579 | 23:16:09.877 |
| ST11 | C2 beaconing (DC) | HFDC01 | 23:16:10 | 23:31:30 | 827 | 23:16:10.015 |
| ST12 | DC discovery | HFDC01 | 23:17:30 | 23:19:00 | 34 | 23:17:31.281 |
| ST13 | takeown/icacls + overwrite Magnify.exe | HFDC01 | 23:19:00 | 23:30:00 | 189 | 23:19:02.188 |
| ST14 | Data staged in Recycle Bin | HR001 | 23:33:00 | 23:34:00 | 654 | 23:33:00.947 |
| ST15 | RDP session to the DC | HFDC01 | 23:43:00 | 23:43:30 | 13 | 23:43:02.745 |
| ST16 | Accessibility backdoor triggered | HFDC01 | 23:44:20 | 23:46:30 | 119 | 23:44:26.719 |

## Ambiguous items (excluded from strict metrics)

- 22:52:16 HR001 `consent.exe` consent.exe 2260 11328 0000023B598A9080
- 23:06:57 HR001 `mmc.exe` "C:\Windows\system32\mmc.exe" "C:\Windows\system32\eventvwr.msc" /s
- 23:06:57 HR001 `consent.exe` consent.exe 2260 426 0000023B59833A50
- 23:06:58 HR001 `mmc.exe` "C:\Windows\system32\mmc.exe" "C:\Windows\system32\eventvwr.msc" /s
- 23:43:53 HFDC01 `consent.exe` consent.exe 720 348 0000025524042F60