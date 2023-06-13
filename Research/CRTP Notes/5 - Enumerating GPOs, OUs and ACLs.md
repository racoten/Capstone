# Group Policy Objects (GPO)

#### Get list of GPO in current domain
```powershell
Get-NetGPO
Get-NetGPO -ComputerName dcorp-student1.dollarcorp.moneycorp.local
Get-GPO -All (GroupPolicy Module)
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html (Provides RSoP)
```

#### Get GPO(s) which use Restricted Groups or groups.xml for interesting users
```powershell
Get-NetGPOGroup
```

#### Get users which are in a local group of a machine using GPO
```powershell
Find-GPOComputerAdmin –Computername dcorp-student1.dollarcorp.moneycorp.local
```

#### Get machines where the given user is member of a specific group
```powershell
Find-GPOLocation -UserName student1 -Verbose
```

# Organizational Units

#### Get OUs in a domain
```powershell
Get-NetOU -FullData
Get-ADOrganizationalUnit -Filter * -Properties *
```

#### Get GPO applied on an OU. Read GPOname from gplink attribute from
Get-NetOU
```powershell
Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B-83E8F4EF8081}"
Get-GPO -Guid AB306569-220D-43FF-B03B-83E8F4EF8081 (GroupPolicy module)
```

# Learning Objective 2

#### Enumerate following for the dollarcorp domain:
- List all the OUs
- List all the computers in the StudentMachines OU.
- List the GPOs
- Enumerate GPO applied on the StudentMachines OU.

# Access Control Lists (ACLs)

• It is a list of Access Control Entries (ACE) – ACE corresponds to individual permission or audits access. Who has permission and what can be done on an object?

• Two types:

    – Discretionary ACL (DACL) – Defines the permissions trustees (a user or group) have on an object.

    – System ACL (SACL) – Logs success and failure audit messages when an object is accessed.

• ACLs are vital to security architecture of AD.

#### Get the ACLs associated with the specified object
```powershell
Get-ObjectAcl -SamAccountName student1 –ResolveGUIDs
```

#### Get the ACLs associated with the specified prefix to be used for search
```powershell
Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose
```

#### We can also enumerate ACLs using ActiveDirectory module but without
resolving GUIDs
```powershell
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access
```

#### Get the ACLs associated with the specified LDAP path to be used for search
```powershell
Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose
```

#### Search for interesting ACEs
```powershell
Invoke-ACLScanner -ResolveGUIDs
```

#### Get the ACLs associated with the specified path
```powershell
Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"
```

# Learning Objective 3

#### Enumerate following for the dollarcorp domain:
– ACL for the Users group
– ACL for the Domain Admins group
– All modify rights/permissions for the studentx
