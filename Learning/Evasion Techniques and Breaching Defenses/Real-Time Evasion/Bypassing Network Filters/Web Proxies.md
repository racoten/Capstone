Web proxies are a technology that generate request on behalf of the user by terminating the user's request and initiating a new one from its own server.

They usually work with NAT rules so the proxy knows to whom return the response

![[Pasted image 20230617213418.png]]

These act as a sort of Man-In-The-Middle and can cut requests off if certain conditions are met or even change the data by modifying some headers

Even if the traffic is allowed, the request details, like common HTTP headers (Host, User-Agent, Referer, etc) as well as the request method and resource path will almost certainly be logged. If the company uses a central log server with a Security Information and Event Management (SIEM) system, the proxy logs might be subject to a second review and if something is suspicious, an alert might be generated. Since this could jeopardize our penetration test, we must tread carefully and employ a variety of bypass, obfuscation, and normalization techniques on our web-based traffic. In the next section, we’ll explore a few of these techniques.

# Bypassing Web Proxies

We can bypass Web Proxies by having our C2 Implant be proxy aware.

Since Meterpreter's HTTP/S payload is proxy-aware, we must consider ensuring that the domain and URL are clean and the C2 server is safely categorized

If the client has deployed a URL verification or categorization system, like those provided by Cyren, Symantec Bluecoat, or Checkpoint, we should factor their policy settings into our bypass strategy.

Cloud providers and CDNs offer hosting and generic domain auto-assigns to simplify the process of creating safe domains

We should now consider the traces left on proxy logs by C2 sessions

Take into account setting a User-Agent to a browser type permitted by the organization

We can build User-Agents with useragentstring.com 

![[Pasted image 20230617230151.png]]

Once we have selected a User-Agent string, we can apply it to our framework of choice. For example, we can set our custom User-Agent in Meterpreter with the HttpUserAgent advanced configuration option.

