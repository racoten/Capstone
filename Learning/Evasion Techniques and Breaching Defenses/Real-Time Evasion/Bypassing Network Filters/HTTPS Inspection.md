It is tricky to bypass this technique for detection as it is meant to look at the traffic being sent

But we can use Meterpreter's `TLS Certificate Pinning` to keep a low profile. 

Using this technique, we can specify the certificate that will be trusted. Meterpreter will then compare the hash of the certificates and if there is a mismatch, it will terminate itself. This can be controlled by setting the StagerVerifySSLCert option to “true” and configuring HandlerSSLCert with the certificate we trust and want to use.

We can also mimic a banking firm by copying the certificate of a banking website in order to prevent inspection since legitimate banking traffic is not subject to inspection

