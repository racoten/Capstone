# Computer Enumeration

#### Get a list of computers in the current domain

```powershell
Get-NetComputer
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData

# AD PowerShell Module

Get-ADComputer -Filter * | select Name

Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem

Get-ADComputer -Filter *  -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}

Get-ADComputer -Filter * -Properties *
```

# Group Enumeration

#### Get all the groups in the domain
```powershell
Get-NetGroup
Get-NetGroup –Domain <targetdomain>  
Get-NetGroup –FullData

# AD Module
Get-ADGroup -Filter * | select Name  
Get-ADGroup -Filter * -Properties *
```

#### Get all groups containing the word "admin" in group name
```powershell
Get-NetGroup *admin*

# AD Module
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```

#### Get all the members of the Domain Admins group
```powershell
Get-NetGroupMember -GroupName "Domain Admins" -Recurse

# AD Module
Get-ADGroupMember -Identity "Domain Admins" -Recursive
```

#### Get the group membership for a user
```powershell
Get-NetGroup –UserName "student1"

# AD Module
Get-ADPrincipalGroupMembership -Identity student1
```

#### List all the local groups on a machine (needs administrator privs on non-dc machines)

```powershell
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroups
```

#### Get members of all the local groups on a machine (needs administrator  privs on non-dc machines)
```powershell
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Recurse
```

# Logged in users

#### Active logins on computer (needs local admin rights on  the target)
```powershell
Get-NetLoggedon -ComputerName <computer name>
```

#### Get locally logged users on a computer (needs remote registry on the  target - started by-default on server OS)
```powershell
Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

#### Get the last logged user on a computer (needs administrative rights and  remote registry on the target)
```powershell
Get-LastLoggedOn -ComputerName <computer name>
```

# Shares

#### Find shares on hosts in current domain
```powershell
Invoke-ShareFinder -Verbose
```

#### Find sensitive files on computers in the domain
```powershell
Invoke-FileFinder -Verbose
```

#### Get all fileservers of the domain
```powershell
Get-NetFileServer
```

# Learning Objective 1 

#### Enumerate the following for the dollarcorp domain:
- Users
- Computers
- Domain Administrators
- Enterprise Administrators
- Shares