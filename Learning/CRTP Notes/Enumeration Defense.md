# Domain Enumeration – Defense

• Most of the enumeration mixes really well with the normal traffic to the DC.

• Hardening can be done on the DC (or other machines) to contain the information provided by the queried machine.

• Let's have a look at defending against one of the most lethal enumeration techniques: user hunting.

• Netcease is a script which changes permissions on the NetSessionEnum method by removing permission for Authenticated Users group.

`https://github.com/p0w3rsh3ll/NetCease`

• This fails many of the attacker's session enumeration and hence user hunting capabilities.

 `.\NetCease.ps1`

• Another interesting script from the same author is SAMRi10 which hardens Windows 10 and Server 2016 against enumeration which uses SAMR protocol (like net.exe)

• https://www.helpnetsecurity.com/2016/12/01/samri10-windows-10-hardening/
