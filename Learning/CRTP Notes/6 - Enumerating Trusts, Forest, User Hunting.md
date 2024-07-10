# Trusts

#### Trust direction

One-way Trust

![image](https://user-images.githubusercontent.com/40224197/200670219-c8698f9a-b7bf-4de8-ae99-25d345128e3c.png)

Two-way Trust

![image](https://user-images.githubusercontent.com/40224197/200670383-b96ee2af-ac8a-40cb-be67-9b4cebb91564.png)

Trust Transitivity

![image](https://user-images.githubusercontent.com/40224197/200670499-5b67648e-046d-4d50-a020-1bfa0700da8e.png)

Tree-Root Trust

![image](https://user-images.githubusercontent.com/40224197/200671313-48c94a41-06cb-4cbf-a1d1-68d9cef4d03b.png)

Shortcut Trust

![image](https://user-images.githubusercontent.com/40224197/200671807-cad5f417-fade-444e-8a98-e2ec47d35397.png)

External Trust

![image](https://user-images.githubusercontent.com/40224197/200671514-45b463fa-cb91-4f7b-9094-169300084757.png)

Forest Trust

![image](https://user-images.githubusercontent.com/40224197/200671067-d42bb7c6-4efa-4fcd-92ed-6c3e296e0084.png)

# Trusts Mapping

#### Get a list of all domain trusts for the current domain
```powershell
Get-NetDomainTrust
Get-NetDomainTrust -Domain us.dollarcorp.moneycorp.local

# AD Module
Get-ADTrust
Get-ADTrust -Identity us.dollarcorp.moneycorp.local
```

# Forests

#### Forest Mapping

#### Get details about the current forest
```powershell
Get-NetForest
Get-NetForest -Forest eurocorp.local

# AD Module
Get-ADForest
Get-ADForest -Identity eurocorp.local
```

#### Get all domains in the current forest
```powershell
Get-NetForestDomain
Get-NetForestDomain -Forest eurocorp.local

# AD Module
(Get-ADForest).Domains
```

#### Get all global catalogs for the current forest
```powershell
Get-NetForestCatalog
Get-NetForestCatalog -Forest eurocorp.local

# AD Module
Get-ADForest | select -ExpandProperty GlobalCatalogs
```

#### Map trusts of a forest
```powershell
Get-NetForestTrust
Get-NetForestTrust -Forest eurcorp.local
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```

# Learning Objective 4
- Enumerate all domains in the moneycorp.local forest
- Map the trusts of the dollarcorp.moneycorp.local domain
- Map External trusts in moneycorp.local forest
- Identify external trusts of dollarcorp domain. Can you enumerate trusts for a trusting forest?

# User Hunting

#### Find all machines on the current domain where the current user has local admin access
```powershell
Find-LocalAdminAccess -Verbose
```

This function queries the DC of the current or provided domain for a list of computers (`Get-NetComputer`) and then use multi-threaded `Invoke-CheckLocalAdminAccess` on each machine

#### This can also be done with the help of admin tools like WMI and psremoting, useful when RPC and SMB ports are blocked
```powershell
Find-WMILocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess.ps1
```

![image](https://user-images.githubusercontent.com/40224197/211056469-0f52628f-eba4-4f93-bc06-23af47c7e055.png)

#### Find local admins on all machines of the domain (needs administrator privs on non-dc machines)
```powershell
Invoke-EnumerateLocalAdmin -Verbose
```

This function queries the DC of the current or provided domain for a list of computers (Get-NetComputer) and use multi-threaded `Get-NetLocalGroup` on each machine

![image](https://user-images.githubusercontent.com/40224197/211058703-a3dcada2-96f6-4c95-b83d-493107fadd31.png)

#### Find computers where a domain admin (or specified user/group) has sessions
```powershell
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
```

This function queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using `Get-NetGroupMember`, gets a list of computers (`Get-NetComputer`) and list sessions and logged on users (`GetNetSession`/`Get-NetLoggedon`) from each machine.

#### Confirm admin access
```powershell
Invoke-UserHunter -CheckAccess
```

![image](https://user-images.githubusercontent.com/40224197/211059438-0ad0a825-6942-4b7f-8f9a-4b20146602c3.png)

#### Find computers where a domain admin is logged-in
```powershell
Invoke-UserHunter -Stealth
```

This option queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using `GetNetGroupMember`, gets a list _only_ of high traffic servers (DC, File Servers and Distributed File servers) for less traffic generation and list sessions and logged on users (`Get-NetSession`/`Get-NetLoggedon`) from each machine.
