The default directories that are whitelisted from AppLocker are `C:\Program Files`, `C:\Program Files (x86)` and `C:\Windows`

We can locate user-writeable folders with `AccessChk`  from SysInternals:
```powershell
C:\Tools\SysinternalsSuite>accesschk.exe "student" C:\Windows -wus
Accesschk v6.12 - Reports effective permissions for securable objects
Copyright (C) 2006-2017 Mark Russinovich
Sysinternals - www.sysinternals.com
RW C:\Windows\Tasks
RW C:\Windows\Temp
RW C:\Windows\tracing
RW C:\Windows\Registration\CRMLog
RW C:\Windows\System32\FxsTmp
W C:\Windows\System32\Tasks
RW C:\Windows\System32\AppLocker\AppCache.dat
RW C:\Windows\System32\AppLocker\AppCache.dat.LOG1
RW C:\Windows\System32\AppLocker\AppCache.dat.LOG2
W C:\Windows\System32\Com\dmp
RW C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
W C:\Windows\System32\spool\PRINTERS
W C:\Windows\System32\spool\SERVERS
RW C:\Windows\System32\spool\drivers\color
RW C:\Windows\System32\Tasks\OneDrive Standalone Update Task-S-1-5-21-50316519-3845643015-1778048971-1002
...
```

We also need to check if they have executable permissions with `icacls`:
```powershell
C:\Tools\SysinternalsSuite>icacls.exe C:\Windows\Tasks
C:\Windows\Tasks NT AUTHORITY\Authenticated Users:(RX,WD)
BUILTIN\Administrators:(F)
BUILTIN\Administrators:(OI)(CI)(IO)(F)
NT AUTHORITY\SYSTEM:(F)
NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
CREATOR OWNER:(OI)(CI)(IO)(F)
Successfully processed 1 files; Failed processing 0 files
```

The `RX` flag indicates that `NT AUTHORITY\Authenticated Users` have Read/Execute permissions in `C:\Windows\Tasks`

We can test it by copying calc.exe into this folder:
![[Pasted image 20230624130714.png]]