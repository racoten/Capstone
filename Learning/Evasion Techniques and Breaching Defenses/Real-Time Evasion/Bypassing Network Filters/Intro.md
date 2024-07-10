Commonly, outbound traffic is routed through a series of systems where it is inspected and processed before routing it to the Internet or blocking it due to a violation. The tools used in this model may include simple IP address filters or more complex Intrusion Detection Systems (IDS) and web proxy filters. These advanced tools may perform deep packet inspection, analyzing the entirety of the network application layer’s content.

![[Pasted image 20230617165928.png]]

If the egress connection relies on name resolution, it will first go through an edge DNS server who in turn may perform filtering

If the connection that goes through an internal firewall, the firewall may then check if it should block the connection based on rules like egress SMB traffic blocking

At this point, the traffic may pass through an SSL inspection493 device, which essentially performs SSL decryption and re-encryption, allowing the device to inspect SSL-encrypted traffic. The traffic is typically re-encrypted when it leaves this zone.

If the traffic is still allowed, it may next pass through a traffic filter, like a proxy server or an IDS, and the data may be copied to a full packet capture device.

Next, the traffic may pass through an external firewall that may filter egress traffic (in addition to filtering ingress traffic as expected).

If the traffic passes these inspection points, it is then routed to the Internet.

Domain names are more practical and flexible for several reasons. First, we can easily move our C2 server (listener) to another location by simply updating the DNS record. In addition, since direct-to-IP connections are often considered anomalous, we’ll perform a DNS lookup to connect to our C2 server and adopt a more typical network pattern.

