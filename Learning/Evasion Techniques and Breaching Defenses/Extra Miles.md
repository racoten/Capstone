# 4.2.5.2
Create the text for a phishing email using a pretext that would make sense for your organization, school, or customer. Frame the text to convince the victim to click on an embedded link that leads to an HTML page on your Kali system.

Manually create the HTML page sitting on your Apache web server so it performs HTML smuggling of a Jscript shellcode runner when the link is opened with Google Chrome. Ensure that the email text and the content of the HTML page encourage the victim to run the Jscript file.

# 5.1.2.2
Process injection with VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread is considered a standard technique, but there are a few others to consider. 

The low-level native APIs NtCreateSection, NtMapViewOfSection, NtUnMapViewOfSection, and NtClose in ntdll.dll can be used as alternatives to VirtualAllocEx and WriteProcessMemory.

Create C# code that performs process injection using the four new APIs instead of VirtualAllocEx and WriteProcessMemory. Convert the code to Jscript with DotNetToJscript. Note that CreateRemoteThread must still be used to execute the shellcode.

# 6.8.3.2
Modify, encrypt, and obfuscate the process hollowing techniques previously implemented in C# to bypass antivirus detection.

# 7.4.2.2 
Create a similar AMSI bypass but instead of modifying the code of AmsiOpenSession, find a suitable instruction to change in AmsiScanBuffer and implement it from reflective PowerShell.

# 8.2.2.2
Examine the default Windows Installer rules and determine how it would be possible to bypass those.

# 8.4.5.2
Perform online research to understand and execute an AppLocker bypass that allows arbitrary C# code execution by abusing the MSBuild native binary.

# 8.5.2.2
PowerShell Empire is a well-known framework for post-exploitation, specifically geared towards Active Directory exploitation. It can also generate client-side code execution payloads.

An alternative and newer framework called Covenant is written in C# and implements much of the same functionality. To obtain code execution on a Windows host an implant called a Grunt is used.

Install the Covenant framework on your Kali machine and use knowledge and techniques from this module to obtain code execution through a Grunt in the face of AppLocker restrictions.

# 9.6.1.2
Censys is a search engine similar to Shodan, searching Internet-connected devices based on their fingerprint information, like webserver type, certificate details, etc. Use this service to find Azure domain-frontable sites. The following guide will show the necessary steps.

# 9.6.2.2
Perform domain fronting with PS Empire.

# 10.1.1.2
Get a reverse shell using the above VIM backdoor as root.

# 10.2.2.2
Modify the example we covered in this section to use a different encoding method such as using a Caesar Cipher.

# 10.3.2.2
1. Get a shell by adding shellcode execution to our shared library example. Consider using the AV bypass code we covered previously as a guide. Continuing the program’s functionality after the shell is fired is not necessary in this case.
2. Hijack an application other than top using the method described in this section.

# 11.2.4.2
Find a way to write user-provided text to a file on the file system without Scratchpad. One potential option might include the Javascript console.

# 11.3.1.2
Experiment with creating simple applications with gtkdialog to streamline the exploitation process. One potential project is a text editor based on our terminal application.

# 14.3.4.2
In addition to the attacks covered here, it’s also possible to combine techniques involving both Windows and Linux boxes.

Log in to the Windows 10 client as the domain administrator user “administrator”, which will generate a TGT in memory. Next, create a reverse shell and use that to export the TGT back to your Kali machine. Transform the TGT into a ccache format.

To simulate a firewalled network, use Impacket to pass the ticket to the domain controller. Try pivoting through the Windows 10 client to obtain a reverse shell.

# 15.3.1.2
While Microsoft documentation specifies that execution of stored procedures is not supported on linked SQL servers with the OPENQUERY keyword, it is actually possible.

Modify the SQL queries to obtain code execution on dc01 using OPENQUERY instead of AT.

# 15.3.2.2
A PowerShell script called PowerUpSQL exists that can help automate all the enumerations and attacks we have performed in this module.

A C# implementation of PowerUpSQL called Database Audit Framework & Toolkit (DAFT) also exists.

Download and use either of them to access, elevate, and own the two SQL servers.

Evil SQL Client (ESC) is yet another implementation of the same features written in C#. It has been prebuilt to work with MSBuild to avoid detection and bypass Application Whitelisting.

# 16.1.3.2
GenericWrite applied to a user account can lead to compromise. Perform enumeration in the labs to discover any GenericWrite misconfigurations and work out how to compromise the relevant account.

# 16.4.1.2
Find the trust key for corp1.com and use it to craft a golden ticket instead of the krbtgt password hash as shown in the previous section.

Obtain code execution on the rdc01.corp1.com domain controller with the crafted ticket. Be sure to log off between attempts to clear out any cached tickets.

# 16.6.2.2
Instead of logging in to the MSSQL server on rdc01.corp1.com, use the MSSQL server on cdc01.corp1.com instead and leverage SQL server links to get code execution on dc01.corp2.com.

# 17.3.2.2
In this module, we performed the entire attack from Metasploit and primarily through the Meterpreter shell. Depending on the chosen tools and attack techniques, another framework may prove more favorable.

Evading security mitigations such as antivirus may also be easier with another framework due to a lack of signatures and behavioral detection against it.

Repeat the attack shown in this module with a different framework like PowerShell Empire or Covenant.

