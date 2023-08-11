# Domain Enumeration

Using Native executables and .NET classes
```powershell
$ADClass = [System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()
```
PowerView
`https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1`

Get current domain
```powershell
Get-NetDomain (PowerView)
Get-ADDomain (Active Directory Module)
```

Get object of another domain
```powershell
Get-NetDomain -Domain moneycorp.local
Get-ADDomain -Identity moneycorp.local
```

Get domain SID for the current domain
```powershell
Get-DomainSID
(Get-ADDomain).DomainSID
```

Get domain policy for the current domain
```powershell
Get-DomainPolicy
(Get-DomainPolicy)."system access"
```

Get domain policy for another domain
```powershell
(Get-DomainPolicy -domain moneycorp.local)."system access"
```

Get domain controllers for the current domain
```powershell
Get-NetDomainController
Get-ADDomainController
```

Get domain controllers for another domain
```powershell
Get-NetDomainController -Domain moneycorp.local
Get-ADDomainController -DomainName moneycorp.local -Discover
```

# User Enumeration

Get a list of users in the current domain
```powershell
Get-NetUser
Get-NetUser -Username student1
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity student1 -Properties *
```

Get a list of all properties for users in the current domain
```powershell
Get-UserProperty

Get-UserProperty –Properties pwdlastset

Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name

Get-ADUser -Filter * -Properties * | select

name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```

Search for a particular string in a user's attributes
```powershell
Find-UserField -SearchField Description -SearchTerm "built"
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select
name,Description
```