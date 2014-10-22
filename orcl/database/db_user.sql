CREATE USER "RAIDMIRROR" IDENTIFIED BY "raidmirror";

grant "CONNECT" TO "RAIDMIRROR";

grant select on v_$instance to "RAIDMIRROR";

grant select on v_$session to "RAIDMIRROR";

grant select on v_$sysstat to "RAIDMIRROR";

grant select on v_$system_event to "RAIDMIRROR";

grant select on v_$event_name to "RAIDMIRROR";

grant select on v_$tablespace to "RAIDMIRROR";

grant select on v_$sort_segment to "RAIDMIRROR";

grant select on v_$datafile to "RAIDMIRROR";

grant select on v_$tempfile to "RAIDMIRROR";

grant select on v_$asm_diskgroup to "RAIDMIRROR";

grant select on v_$asm_disk to "RAIDMIRROR";

grant select on dba_tablespaces to "RAIDMIRROR";

grant select on dba_data_files to "RAIDMIRROR";

grant select on dba_temp_files to "RAIDMIRROR";

grant select on dba_free_space to "RAIDMIRROR";