DNS servers may bounce around a request to resolve a domain name. It may be that one of these servers contains a filtering function that will lookup its blocklist and filter it if the requested domain to be resolved is in that list.

If it is in that list, the DNS filtering system will drop or return a sinkhole or a fake IP.

A sinkhole IP will often either redirect to a block page, which presents an error or warning to the user, or to a monitoring device that captures further traffic, which can be analyzed.

# Testing DNS Filters

We can test the OpenDNS' sinkhole by making a request to `www.internetbadguys.com`

If we perform this request using Google's DNS:
```bash
bash -c "echo nameserver 8.8.8.8 > /etc/resolve.conf"
```

The nslookup request is resolved correctly:
```bash
kali@kali:~$ nslookup www.internetbadguys.com
Server: 8.8.8.8
Address: 8.8.8.8#53
Non-authoritative answer:
Name: www.internetbadguys.com
Address: 67.215.92.210
```

But if we instead use OpenDNS' filtering service:
```bash
bash -c "echo nameserver 208.67.222.222 > /etc/resolv.conf"
```

It returns a different IP:
```bash
kali@kali:~$ nslookup www.internetbadguys.com
Server: 208.67.222.222
Address: 208.67.222.222#53
Non-authoritative answer:
Name: www.internetbadguys.com
Address: 146.112.61.108
Name: www.internetbadguys.com
Address: ::ffff:146.112.61.108
```

# Dealing with DNS Filters

Although we could register new domains, these will not have a good reputation since they will be categorized as Newly Seen Domain

It is a good idea to look for information about domain names in advance and perform lookups and inspect traffic

In terms of classification, we should avoid Webmail domains and often opt for something like cooking blog. We can also categorize our own domains using OpenDNS

In addition to guarding and monitoring our domain’s reputation, we should take steps to make the domain name itself appear legitimate. For example, a domain name consisting of legitimate-sounding
text is less suspicious than a domain consisting of random numbers and characters, especially when examined by natural language processing filtering systems. 

One technique popularized by malware authors and penetration testers is known as typos-quatting, which leverages subtle changes in recognizable domain names. For example, if our target uses example.com, we could register the examp1e.com, which is visually similar. Additional examples may include examlpe.com, exomple.com, or examplle.com.

Although this technique could entice a user to click a phishing link, some services can filter and issue alerts regarding typo-squatted domains.

Finally, we must be aware of the status of the IP address of our C2 server. If the IP has been flagged as malicious, some defensive solutions may block the traffic. This is especially common
on shared hosting sites in which one IP address hosts multiple websites. If one site on the shared host ever contained a browser exploit or was ever used in a watering hole509 malware campaign,
the shared host may be flagged. Subsequently, every host that shares that IP may be flagged as well, and our C2 traffic may be blocked.

To guard against this, we should use a variety of lookup tools, like the previously-mentioned Virustotal and IPVoid sites to check the status of our C2 IP address before an engagement.