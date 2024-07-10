RSA’s Netwitness is a common enterprise-level full packet capture system and Moloch is an alternative free open source alternative.

These devices can also be used for deep packet inspection and protocol analysis of the traffic and can generate rich, searchable metadata. Experienced users can use this data to detect
malicious traffic.

From a penetration testing perspective, our goal is not to evade such systems but to rather lower our profile as much as possible to evade detection, using the tactics we discussed in the proxy and DNS filter evasion sections. In addition, before using any tool or framework, we should view our traffic in a test lab with a tool like Wireshark to determine if the tool is generating realistic-looking traffic.

Since these solutions typically log geolocation data, we should also consider this as part of our bypass strategy, especially the perceived location of our C2 server. For example, if we know that our target only typically transacts with US-based sites, geographically different destinations may raise suspicion.