# Dump LSASS.exe using Imported Microsoft DLLs

**MITRE ATT&CK**: T1003.001 – OS Credential Dumping | Tactic: Credential access

## Intro
This test uses Xordump to dump the memory of the lsass.exe process. Xordump imports legitimate Microsoft DLLs and uses their exported functions to access LSASS memory and create a temporary memory dump. The dump is then read and deleted.

## Detection Queries & Evidence

1. Event ID 1: Sysmon xordump process Execution
```spl
  index=main
  source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=1
  process_name="xordump.exe"
  | table _time EventCode user process_name process_path process_id parent_process_name parent_process_path process
  | sort - _time
```
  ![Event ID 1: Sysmon xordump process Execution](./artifacts/suspicious_process_creation.png)


2. Event ID 10: LSASS.exe process accessed
```spl
  index=main
  source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=10
  TargetImage="*\\lsass.exe"
  | table _time EventCode host SourceImage SourceProcessId TargetImage TargetProcessId GrantedAccess TargetUser
  | sort - _time
```
  ![Event ID 10: LSASS.exe process accessed](./artifacts/lsass_process_accessed.png)


3. Event ID 11: LSASS dmp file created
```spl
  index=main
  source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=11
  TargetFilename="*.dmp"
  | table _time EventCode host user Image ProcessId TargetFilename
  | sort - _time
```
![Event ID 11: LSASS dmp file created](./artifacts/lsass_dmp_file_created.png)


## References
- MITRE ATT&CK: https://attack.mitre.org/tactics/TA0006/
- Atomic Red Team: https://www.atomicredteam.io/docs/atomics/T1003.001#atomic-test-12-dump-lsassexe-using-imported-microsoft-dlls