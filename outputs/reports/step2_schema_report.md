# Step 2 - Normalization report

- Events: **121,659**  |  Columns: **60**
- Time range (UTC): 2019-05-12 12:58:22.531000+00:00 -> 2019-05-14 23:47:44.225000+00:00
- Hosts: ACCT001, HFDC01, HR001, IT001
- **Schema coverage** (events typed non-`other`): 98.2%

## Events by normalized type

| event_type | count |
|---|---|
| registry_event | 23,368 |
| process_access | 19,199 |
| ps_pipeline | 18,366 |
| ps_module_log | 15,632 |
| image_load | 14,178 |
| wfp_connection | 6,563 |
| network_connect | 5,951 |
| token_adjusted | 3,259 |
| handle_closed | 2,286 |
| other | 2,244 |
| pipe_event | 1,508 |
| file_create | 1,346 |
| object_handle_request | 1,143 |
| ps_provider | 1,106 |
| handle_duplicated | 1,077 |
| wfp_bind | 1,058 |
| share_access | 497 |
| object_access | 460 |
| logon | 363 |
| group_membership | 363 |
| logoff | 335 |
| process_create_sec | 312 |
| process_create | 308 |
| special_privileges | 268 |
| process_terminate | 243 |
| ps_scriptblock | 140 |
| kerberos_service_ticket | 32 |
| kerberos_tgt | 22 |
| explicit_cred_logon | 20 |
| service_install | 8 |
| ntlm_auth | 2 |
| logon_failed | 2 |

## Events by host

| host | count |
|---|---|
| HR001 | 85,957 |
| HFDC01 | 28,148 |
| IT001 | 6,012 |
| ACCT001 | 1,542 |

## Engineered feature hit counts

| feature | rows true |
|---|---|
| f_encoded_cmd | 13 |
| f_hidden_window | 11 |
| f_no_profile | 9 |
| f_bypass | 0 |
| f_b64_blob | 13 |
| f_download_cradle | 6 |
| f_lolbin | 19,939 |
| f_parent_script_engine | 186 |
| f_parent_office | 0 |
| f_user_writable_path | 140 |
| f_system_user | 2,066 |

## Column list

`event_uid`, `timestamp`, `host`, `log_name`, `event_id`, `event_type`, `record_number`, `user`, `target_user`, `process`, `process_path`, `process_id`, `process_guid`, `parent_process`, `parent_path`, `parent_pid`, `parent_guid`, `command_line`, `parent_command_line`, `integrity_level`, `hashes`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `file_path`, `registry_key`, `target_process`, `granted_access`, `logon_type`, `logon_id`, `auth_package`, `remote_ip`, `service_name`, `service_path`, `share_name`, `script_block`, `original_file_name`, `current_directory`, `description`, `product`, `company`, `user_short`, `cmd_len`, `cmd_n_args`, `cmd_entropy`, `f_encoded_cmd`, `f_hidden_window`, `f_no_profile`, `f_bypass`, `f_b64_blob`, `f_download_cradle`, `f_lolbin`, `f_parent_script_engine`, `f_parent_office`, `f_user_writable_path`, `f_system_user`, `sb_len`, `hour`