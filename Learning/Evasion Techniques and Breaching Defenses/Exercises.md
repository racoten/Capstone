# 3.1.3.1 Exercises
1. Repeat the HTML smuggling to trigger a download of a Meterpreter payload in a file format
of your choosing.
2. Modify the smuggling code to also use the window.navigator.msSaveBlob62,63 method to
make the technique work with Microsoft Edge as well.

# 3.2.2.1 Exercises
1. Experiment with VBA programming basics by creating a small macro that prints the current
username and computer name 5 times using the Environ$ function.
2. Create an Excel macro that runs when opening an Excel spreadsheet and executes cmd.exe
using Workbook_Open.80

# 3.2.3.1 Exercises
1. Replicate the Word macro to obtain a reverse shell. Implement it in Excel.
2. Experiment with another PowerShell download cradle like Invoke-WebRequest.

# 3.3.2.1 Exercises
1. Create a convincing phishing pretext Word document for your organization or school that
replaces text after enabling macros.
2. Insert a procedure called MyMacro that downloads and executes a Meterpreter payload after
the text has been switched.

# 3.4.1.1 Exercises
1. Replicate the call to GetUserName and return the answer.
2. Import the Win32 MessageBoxA110 API and call it using VBA.

# 3.5.1.1 Exercises
1. Import and call MessageBox using Add-Type as shown in this section.
2. Apply the same techniques to call the Win32 GetUserName API.

# 3.5.2.1 Exercises
1. Replicate the PowerShell shellcode runner used in the section.
2. Is it possible to use a different file extension like .txt for the run.ps1 file?

# 3.6.1.1 Exercises
1. Execute the Add-Type MessageBox PowerShell code and capture the source code and
assembly being written to disk.
2. Does the current PowerShell shellcode runner write files to disk?

# 3.6.2.1 Exercises
1. Go through the PowerShell code in this section and dump the wanted methods to disclose
the location of GetModuleHandle and GetProcAddress and perform a lookup of a different
Win32 API.
2. What happens if we use the second entry in the $tmp array?

# 3.6.3.1 Exercises
1. Use the PowerShell code to call MessageBoxA using reflection instead of Add-Type.
2. Use Process Monitor to verify that no C# source code is written to disk or compiled.
3. The Win32 WinExec API can be used to launch applications. Modify the existing code to
resolve and call WinExec and open Notepad. Use resources such as MSDN and P/Invoke to
understand the arguments for the function and the associated data types.

# 3.6.4.1 Exercises
1. Generate a Meterpreter shellcode and obtain an in-memory PowerShell shellcode runner
resulting in a reverse shell.
2. The code developed in this section was based on a 32-bit PowerShell process. Identify and
modify needed elements to make this work from a 64-bit PowerShell process.

# 3.7.1.1 Exercises
1. Setup the proxy configuration and verify whether or not the Net.WebClient download cradle
is proxy-aware.
2. Are other PowerShell download cradles proxy aware?

# 3.7.2.1 Exercises
1. Set a custom User-Agent in the download cradle and observe it in the Apache access logs.
2. Instead of a custom User-Agent string, identify one used by Google Chrome and implement
that in the download cradle.

# 4.1.1.1 Exercises
1. Create a simple Jscript file that opens an application.
2. Look through the list of default applications related to file types. Are there any other
interesting file types we could leverage?
3. The .vbs extension is also linked to the Windows Script Host format. Write a simple VBScript
file to open an application.

# 4.1.2.1 Exercises
1. Replicate the Jscript file from this section.
2. Modify the Jscript code to make it proxy-aware with the setProxy211 method. You can use the
Squid proxy server installed on the Windows 10 development machine.

# 4.2.1.1 Exercises
1. Set up the Samba share on your Kali system as shown in this section.
2. Create a Visual Studio project and follow the steps to compile and execute the “Hello World”
application.

# 4.2.2.1 Exercises
1. Set up the DotNetToJscript project, share it on the Samba share, and open it in Visual Studio.
2. Compile the default ExampleAssembly project and convert it into a Jscript file with
DotNetToJscript.
3. Modify the TestClass.cs file to make it launch a command prompt instead of opening a
MessageBox.

# 4.2.5.1 Exercises
1. Recreate the steps to obtain a Jscript shellcode runner.
2. Use DotNetToJscript to obtain a shellcode runner in VBScript format.

# 4.2.6.1 Exercises
1. Install SharpShooter on Kali and generate a Jscript shellcode runner.
2. Expand on the attack by creating a staged attack229 that also leverages HTML smuggling to
deliver the malicious Jscript file.

# 4.3.1.1 Exercises
1. Build the C# project and compile the code in Visual Studio.
2. Perform the dynamic load of the assembly through the download cradle both using LoadFile
and Load (Remember to use a 64-bit PowerShell ISE console).
3. Using what we have learned in these two modules, modify the C# and PowerShell code and
use this technique from within a Word macro. Remember that Word runs as a 32-bit
process.


# 5.1.2.1 Exercises
1. Replicate the steps and inject a reverse Meterpreter shell into the explorer.exe process.
2. Modify the code of the ExampleAssembly project in DotNetToJscript to create a Jscript file
that executes the shellcode inside explorer.exe. Instead of hardcoding the process ID, which
cannot be known remotely, use the Process.GetProcessByName255 method to resolve it
dynamically.
3. Port the code from C# to PowerShell to allow process injection and shellcode execution
from a Word macro through PowerShell. Remember that PowerShell is started as 32-bit, so
instead of injecting into explorer.exe, start a 32-bit process such as Notepad and inject into
that instead.

# 5.3.2.1 Exercises
1. Use Invoke-ReflectivePEInjection to launch a Meterpreter DLL into a remote process and
obtain a reverse shell. Note that Invoke-ReflectivePEInjection.ps1 is in the C:\Tools folder on
the Windows 10 development VM.
2. Copy Invoke-ReflectivePEInjection to your Kali Apache web server and create a small
PowerShell download script that downloads and executes it directly from memory.

# 5.4.2.1 Exercises
1. Replicate the process hollowing technique using shellcode from C#.
2. Modify the code to generate a Jscript file using DotNetToJscript that performs process
hollowing.

# 6.4.2.1 Exercises
1. Generate a Metasploit executable using aes256 encryption and verify that it is flagged.
2. Experiment with different payloads, templates, and encryption techniques to attempt to
bypass Avira.

# 6.5.1.1 Exercises
1. Compile the C# shellcode runner and use it to bypass Avira and ClamAV.
2. Enable the heuristics in Avira. Is the code still flagged?

# 6.5.2.1 Exercises
1. Implement the Caesar cipher with a different key to encrypt the shellcode and bypass
antivirus.
2. Use the Exclusive or (XOR)296 operation to create a different encryption routine and bypass
antivirus. Optional: How effective is this solution?

# 6.6.1.1 Exercises
1. Implement the Sleep function to perform time-lapse detection in the C# project both with
and without encryption.
2. Convert the C# project into a Jscript file with DotNetToJscript. Is it detected?

# 6.6.2.1 Exercises
1. Implement a heuristics detection bypass with VirtualAllocExNuma.
2. Use the Win32 FlsAlloc307 API to create a heuristics detection bypass.
3. Experiment and search for additional APIs that are not emulated by antivirus products.

# 6.7.1.1 Exercises
1. Implement the Caesar cipher encryption and time-lapse detection in a VBA macro.
2. Attempt to reduce the detection rate further by using a different encryption algorithm and
routine along with alternative heuristic bypasses.

# 6.7.2.1 Exercises
1. Use FlexHex to delve into the file format of Microsoft Word as explained in this section.
2. Manually stomp out a Microsoft Word document and verify that it still works while improving
evasion.
3. Use the Evil Clippy316 tool (located in C:\Tools\EvilClippy.exe) to automate the VBA Stomping
process.

# 6.8.1.1 Exercises
1. Perform a scan of the PowerShell download cradle and shellcode runner.
2. What is the detection rate when the PowerShell instead downloads a pre-compiled C# assembly shellcode runner and loads it dynamically?

# 6.8.2.1 Exercises
1. Implement the WMI process creation to de-chain the PowerShell process.
2. Update the PowerShell shellcode runner to 64-bit.

# 6.8.3.1 Exercises
1. Replicate the detection evasion steps in this section to obtain a VBA macro with a
PowerShell download cradle that has a very low detection rate.
2. Use alternative encryption routines and antivirus emulator detections to trigger as few
detections as possible.
3. The Windows 10 victim machine has an instance of Serviio PRO 1.8 DLNA Media Streaming
Server installed. Exploit it336 to obtain SYSTEM privileges while evading the Avira antivirus
with real-time detection enabled.

# 7.1.1.1 Exercises
1. Open WinDbg and attach to a Notepad process.
2. Set a software breakpoint and trigger it.
3. Step through instructions and display register and memory content.

# 7.2.2.1 Exercises
1. Use Frida to trace innocent PowerShell commands and fill out the onEnter and onExit
JavaScript functions of AmsiScanBuffer to observe how the content is being passed.
2. Enter malicious commands and try to bypass AMSI detection by splitting strings into
multiple parts.

# 7.3.1.1 Exercises
1. Inspect the amsiContext structure to locate the AMSI header using Frida and WinDbg.
2. Manually modify the amsiContext structure in WinDbg and ensure AMSI is bypassed.
3. Replicate the .NET reflection to dynamically locate the amsiContext field and modify it.

# 7.4.1.1 Exercises
1. Follow the analysis in WinDbg and locate the TEST and conditional jump instruction.
2. Search for any other instructions inside AmsiOpenSession that could be overwritten just as
easily to achieve the same goal.

# 7.4.2.1 Exercises
1. Recreate the bypass shown in this section by both entering the commands directly in the
command prompt and by downloading and executing them as a PowerShell script from your
Kali Linux Apache web server.
2. Incorporate this bypass into a VBA macro where PowerShell is launched through WMI to
bypass both the Windows Defender detection on the Microsoft Word document and the
AMSI-based detection.

# 7.5.1.1 Exercises
1. Manually run the Fodhelper UAC bypass with the PowerShell commands listed in this
section.
2. Attempt the Fodhelper UAC bypass in Metasploit to trigger the detection. It may be required
to revert the machine between bypass attempts.

# 7.5.2.1 Exercises
1. Recreate the UAC bypass while evading AMSI with any of the AMSI bypasses.
Evasion Techniques and Breaching Defenses
PEN-300 v1.0 - Copyright © Offensive Security Ltd. All rights reserved. 251
2. Use a compiled C# assembly instead of a PowerShell shellcode runner to evade AMSI and
bypass UAC.

# 7.6.2.1 Exercises
1. Set the registry key and check that AMSI is bypassed.
2. Combine the AMSI bypass with the shellcode runner, writing fully-weaponized client-side
code execution with Jscript.
3. Experiment with SharpShooter to generate the same type of payload with an AMSI bypass.

# 7.6.3.1 Exercises
1. Recreate the AMSI bypass by renaming wscript.exe to “amsi.dll” and executing it.
2. Instead of a regular shellcode runner, implement this bypass with a process injection or
hollowing technique and obtain a Meterpreter shell that stays alive after the detection.

# 8.1.2.1 Exercises
1. Configure default rules for all four categories of file types and enable AppLocker on your
Windows 10 victim VM.
2. Copy an executable to a location outside the whitelisted folders and observe how it is
blocked by AppLocker when executing it.
3. Create a small Jscript script, store it outside the whitelisted folders and execute it. Is it
blocked?

# 8.2.1.1 Exercises
1. Repeat the analysis to verify that C:\Windows\Tasks is both writable and executable for the
“student” user. Execute a copied executable from this directory.
2. Locate another directory in C:\Windows that could be used for this bypass.
3. Copy a C# shellcode runner executable into one of the writable and executable folders and
bypass AppLocker to obtain a reverse shell.
4. Create a custom AppLocker rule to block the folder C:\Windows\Tasks. Make it a path rule
of type deny. Consult the online documentation if needed.

# 8.2.2.1 Exercises
1. Bypass AppLocker by executing the proof-of-concept DLL C:\Tools\TestDll.dll, as shown in
this section.
2. Generate a Meterpreter DLL with msfvenom and use that together with rundll32 to bypass
AppLocker to obtain a reverse shell.
3. Enable default rules for DLLs and verify that the Meterpreter DLL is blocked.


# 8.2.3.1 Exercises
1. Repeat the exercise to embed simple Jscript code inside an alternative data stream to
obtain execution.
2. Replace the current Jscript code with a DotNetToJscript shellcode runner and obtain a
Meterpreter reverse shell.

# 8.3.1.1 Exercises
1. Verify that constrained language mode is enabled for a PowerShell prompt executed in the
context of the “student” user.
2. Check if our existing PowerShell shellcode runner is stopped once constrained language
mode is enabled.

# 8.3.2.1 Exercises
1. Recreate the application shown in this section to set up a custom runspace and execute
arbitrary PowerShell code without limitations.
2. Modify the C# code to implement our PowerShell shellcode runner.
3. Create an AppLocker deny rule for
C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe and verify that this does
not hinder our custom runspace.

# 8.3.3.1 Exercises
1. Implement the constrained language mode bypass using InstallUtil as demonstrated in this
section.
2. Create or modify a Microsoft Word macro to use the whitelisting bypass and launch a
PowerShell shellcode runner.

# 8.4.2.1 Exercises
1. Repeat the steps in this section to locate the call to Assembly.Load.
2. Locate the application we can use to invoke Compile and discover how its arguments are
controlled.

# 8.4.4.1 Exercises
1. Repeat the analysis performed in this section to obtain a valid XML file with the PowerShell
script.
2. Modify the PowerShell script to set the GenerateInMemory flag and obtain a usable XML file.

# 8.4.5.1 Exercises
1. Repeat the analysis performed in this section and obtain a proof-of-concept application
whitelisting bypass.
2. Modify the provided code file to invoke SharpUp,478 which is the C# equivalent to PowerUp.
Attempt to create the attack in a way that does not require SharpUp to be written to disk on
the victim machine.

# 8.5.1.1 Exercises
1. Create and execute the proof of concept hta file to bypass AppLocker and obtain Jscript
code execution.
2. Use SharpShooter to generate a Jscript shellcode runner inside a hta file and use it to gain a
reverse shell.

# 8.5.2.1 Exercises
1. Repeat the actions in this section to create a proof of concept XSL file and execute a
transformation through WMIC.
2. Modify the XSL file to use DotNetToJscript and obtain a reverse Meterpreter shell.

# 9.1.1.1 Exercises
1. Repeat the steps above to test OpenDNS blocking.
2. Obtain various domain reputation results with IPVoid.

# 9.2.1.1 Exercises
1. Visit Symantec’s website categorization website522 and verify the category of a couple of
random websites.
2. Compare the domain categorization results for the same domains in OpenDNS and
Symantec.

# 9.3.1.1 Exercises
1. Repeat the previous steps to bypass Norton’s HIPS sensor.
2. Use the impersonate_ssl module in Metasploit to bypass Norton HIPS.
3. Norton doesn’t block Empire’s default HTTPS shell. Why is this? Consider the steps we took
in this section to determine the reason.
4. If you own a domain, obtain a valid SSL certificate from Let’s Encrypt’s free service.

# 9.6.2.1 Exercises
1. Repeat the steps above to perform a domain fronting attack in the lab.
2. Perform the same attack for HTTP and inspect the HTTP packets for the correct Host
header information. This NGINX configuration is available on the server:
```
offsec@ubuntu:/etc/nginx/sites-available$ cat exercise.offseccdn.com
server {
listen 80;
server_name exercise.offseccdn.com;
location / {
proxy_pass http://bad.com
}
```

# 9.7.2.1 Exercises
1. Repeat the steps in the previous section to get a reverse shell.
2. Tunnel SMB through the tunnel and access files on the Windows machine via DNS.

# 10.1.1.1 Exercises
1. Backdoor VIM as described in the module by modifying the user’s .vimrc file directly and
running a command while silencing the output.
2. Backdoor VIM by adding a script to the VIM plugins folder.
3. Backdoor VIM by sourcing a secondary shell script in the user’s .vimrc file while silencing the
output.
4. Create an alias for the user for sudo to preserve the user’s environment and activate it by
sourcing the user’s .bashrc file. Then execute a command as root by running VIM as sudo.
5. Using the linuxvictim user, run VIM via sudo and get a root shell using the :shell command.

# 10.1.2.1 Exercises
1. Use an autocommand call to write a simple VIM keylogger and silence it as in this section,
sourcing it from a separate file than the user’s .vimrc file.
2. Modify the keylogger to only log modified file contents if the user is root.

# 10.2.2.1 Exercises
1. Bypass Kaspersky by running a shell in a C wrapper program as shown in this section.
2. Bypass the other scanners in Antiscan.me using XOR obfuscation as shown in this section.

# 10.3.2.1 Exercises
1. Create a malicious shared library example as shown in this section and run it using
LD_LIBRARY_PATH and the top utility.
Evasion Techniques and Breaching Defenses
2. Create a .bashrc alias for sudo to include LD_LIBRARY_PATH and use the malicious library
example we created to escalate to root privileges.

# 10.3.3.1 Exercises
1. Compile a malicious library file to hook the geteuid function. Load the library with
LD_PRELOAD and get code execution using cp.
2. Get a root shell using the above malicious library by creating a sudo alias.

# 11.1.1.1 Exercises
1. What additional information can be discovered about the kiosk? What type of OS is it
running?
2. Examine the kiosk interface and try different Firefox-specific “about:” keywords and other
inputs in the address bar to see what feedback the kiosk interface provides and what
information can be gathered.

# 11.2.4.1 Exercises
1. Browse around the filesystem using the “Launch Application” dialog and gather as much
useful information about the system as possible.
2. Try out various programs via the “Launch Application” dialog. Which ones seem useful for
information gathering or potential exploitation when launched from Firefox?

# 11.3.1.1 Exercises
1. Improve the terminal, making it more effective or more reliable. Integrate standard error
output.
2. Explore the other widgets and elements of gtkdialog. What other useful features can be
created with it that might be useful for interacting with the system?

# 11.4.3.1 Exercises
1. Determine which locations we can write to as a normal user.
2. Get a list of root-owned processes running on the system and determine their purpose/use.
3. What cron jobs are running on the system currently?
4. Try to determine the mechanism by which the kiosk refresh scripts are replacing
bookmarks.html. Why does it only work when setting a symlink to a directory and not just
pointing to the bookmarks.html file instead?

# 11.5.1.1 Exercises
1. Using Notepad on a Windows machine, open the help dialog and search for different utilities
that might expand our capabilities in a restricted environment. Expand on the examples in
this section to get a direct link through the help pages to open an application. What
applications are available via this method?

# 12.1.1.1 Exercises
1. Dump the SAM and SYSTEM files using a Volume Shadow copy and decrypt the NTLM
hashes with Creddump7.
2. Obtain the NTLM hash for the local administrator account by dumping the SAM and
SYSTEM files from the registry.
3. Run a Meterpreter agent on the Windows 10 client and use hashdump to dump the NTLM
hashes.

# 12.1.2.1 Exercises
1. Repeat the LAPS enumeration and obtain the clear text password using LAPSToolKit from
the Windows 10 victim machine.

# 12.2.2.1 Exercises
1. Combine the code and verify the token impersonation.
2. Use the C# code and combine it with previous tradecraft to obtain a Meterpreter, Covenant,
or Empire SYSTEM shell.
3. Try to use the attack in the context of Local Service instead of Network Service.

# 12.3.2.1 Exercises
1. Log on to the Windows 10 victim VM as the offsec user and dump the cached credentials
with Mimikatz.
2. Dump the cached credentials by calling the Mimikatz kiwi767 extension from Meterpreter.
3. Log on to the Windows 2019 server appsrv01 as the admin user and attempt to dump the
cached credentials with Mimikatz.
4. Use the Mimikatz driver to disable LSA Protection on appsrv01 and dump the credentials.

# 12.4.1.1 Exercises
1. Use Task Manager to create a dump file on your Windows 10 victim VM and parse it with
Mimikatz.
2. Use ProcDump located in the C:\Tools\SysInternals folder to create a dump file and parse it
with Mimikatz.

# 12.4.2.1 Exercises
1. Write and compile a C# application that creates a dump file from LSASS as shown in this
section.
2. Create a PowerShell script that calls MiniDumpWriteDump to create a dump file.

# 13.1.1.1 Exercises
1. Log in to the Windows 10 client as the offsec domain user. Use Mimikatz to pass the hash
and create an mstsc process with restricted admin enabled in the context of the dave user.
2. Repeat the steps to disable restricted admin mode and then re-enable it as part of the attack
through PowerShell remoting.

# 13.1.5.1 Exercises
1. Repeat the attack in this section and obtain clear text credentials.

# 13.2.2.1 Exercises
1. Repeat the steps in this section to implement the proof of concept that executes Notepad on
appsrv01.
2. Use the Python implementation of SCShell (scshell.py) to get code execution on appsrv01
directly from Kali using only the NTLM hash of the dave user.

# 14.1.2.1 Exercises
1. Generate a private keypair with a passphrase on your Kali VM. Try to crack the passphrase
using JTR.
2. Generate a private keypair on your Kali VM and insert your public key in the linuxvictim user’s
authorized_keys file on the linuxvictim host and then SSH to it.

# 14.1.4.1 Exercises
1. Reproduce ControlMaster hijacking in the lab.
2. Reproduce SSH-Agent forwarding hijacking in the lab.

# 14.2.7.1 Exercises
1. Execute an ad-hoc command from the controller against the linuxvictim host.
2. Write a short playbook and run it against the linuxvictim host to get a reverse shell.
3. Inject a shell command task into the getinfowritable.yml playbook we created earlier and use
it to get a Meterpreter shell on the linuxvictim host without first copying the shell to the
linuxvictim host via SSH or other protocols.

# 14.2.12.1 Exercises
1. Copy the Artifactory database and extract, then crack, the user hashes.
2. Log in to Artifactory and deploy a backdoored binary. Download and run it as a normal user
on linuxvictim.

# 14.3.4.1 Exercises
1. As root, steal the domain administrator’s ccache file and use it.
2. Use Impacket to enumerate the AD user’s SPNs and get a shell on the domain controller.

# 15.1.2.1 Exercises
1. Execute the code to authenticate to the SQL server on dc01 as shown in this section.
2. Complete the C# implementation that fetches the SQL login, username, and role
memberships.

# 15.1.3.1 Exercises
1. Create the C# code that will trigger a connection to a SMB share.
2. Capture the Net-NTLM hash with Responder.
3. Crack the password hash for SQLSVC and gain access to appsrv01 and dc01.

# 15.1.4.1 Exercises
1. Install Impacket, prepare the PowerShell shellcode runner, and Base64 encode the
PowerShell download cradle.
2. Launch ntlmrelayx to relay the Net-NTLM hash from dc01 to appsrv01 and set up a
multi/handler in Metasploit.
3. Execute the attack by triggering a connection from the SQL server to SMB on the Kali
machine and obtain a reverse shell from appsrv01.

# 15.2.1.1 Exercises
1. Perform enumeration of login impersonation in dc01.
2. Impersonate the sa login on dc01.
3. Impersonate the dbo user in msdb on dc01.

# 15.2.2.1 Exercises
1. Use xp_cmdshell to get a reverse Meterpreter shell on dc01.
2. Use sp_OACreate and sp_OAMethod to obtain a reverse Meterpreter shell on dc01.

# 15.2.3.1 Exercises
1. Repeat the steps to obtain command execution through the custom assembly.
2. Leverage the technique to obtain a reverse shell.

# 15.3.1.1 Exercises
1. Enumerate linked SQL servers from appsrv01.
2. Implement the code required to enable and execute xp_cmdshell on dc01 and obtain a
reverse shell.

# 15.3.2.1 Exercises
1. Repeat the enumeration steps to find the login security context after following the link first to
dc01 and then back to appsrv01.
2. Obtain a reverse shell on appsrv01 by following the links.

# 16.1.1.1 Exercises
1. Repeat the enumeration techniques with PowerView shown in this section.
2. Filter the output further to only display the ACE for the current user.

# 16.1.2.1 Exercises
1. Enumerate domain users and search for associated GenericAll permissions.
Evasion Techniques and Breaching Defenses
2. Leverage the access right to take over the TestService1 account and obtain code execution
in the context of that user through a reverse shell.
3. Enumerate domain groups and leverage GenericAll permissions to obtain group

# 16.1.3.1 Exercises
1. Enumerate the network to discover accounts with compromisable WriteDACL access rights.
2. Leverage the WriteDACL access right to compromise affected accounts.

# 16.2.2.1 Exercises
1. Repeat the attack and obtain a TGT for the domain controller machine account. Reboot
appsrv01 to ensure no prior tickets are present.
2. Inject the ticket and use it to gain a Meterpreter shell on the domain controller.

# 16.2.3.1 Exercises
1. Enumerate the lab and validate that constrained delegation is configured. Remember to
reboot appsrv01 to ensure that no prior tickets are present.
2. Exploit the constrained delegation to obtain a privileged TGS for the MSSQL server on
CDC01.
3. Complete the compromise of CDC01 through the MSSQLSvc TGS and achieve code
execution.

# 16.2.4.1 Exercises
1. Repeat the enumeration steps detailed in this section to discover the GenericWrite access to
appsrv01.
2. Implement the attack to gain a CIFS service ticket to appsrv01 by creating a new computer
account object and use that with Rubeus. Be sure to reboot appsrv01 to clear any cached
Kerberos tickets before starting the attack
3. Leverage the CIFS TGS to get code execution on appsrv01.

# 16.3.2.1 Exercises
1. Enumerate domain trust with .NET, Win32 API, and LDAP.
2. Enumerate trusts from the corp1.com domain.
3. Enumerate groups in the corp1.com domain.
4. Find all members of the Enterprise Admins group.

# 16.4.2.1 Exercises
1. Abuse the print spool service on rdc01 and unconstrained Kerberos delegation on appsrv01
to obtain the NTLM hash of the Enterprise Admins Administrator user.
2. Complete the attack by getting code execution as the Administrator user on rdc01.

# 16.5.2.1 Exercises
1. Map out the domain and forest trust with PowerView.
2. Repeat the enumeration of membership of users from our current forest inside corp2.com.
3. Discover any groups inside our current forest that have members that originate from
corp2.com.

# 16.6.1.1 Exercises
1. Enumerate the SID history setting for corp2.com.
2. Attempt to gain code execution on dc01.corp2.com with a golden ticket.
3. Enable SID history for corp2.com and enumerate its setting again.
4. Obtain a reverse Meterpreter shell on dc01.corp2.com through the use of a golden ticket.
5. Disable SID history again with netdom.

# 16.6.2.1 Exercises
1. Repeat the enumeration of SPNs related to MSSQL along with the low privileged logins.
2. Locate the link to dc01.corp2.com and leverage it to gain code execution inside corp2.com.

# 17.1.1.1 Exercises
1. Perform enumeration against the three hosts.
2. Access the web service published by web01 and find the file upload application.

# 17.1.2.1 Exercises
1. Perform enumeration to detect the upload folder.
2. Attempt to use a generic web shell with a Meterpreter payload to obtain a reverse shell.
3. Use the AV bypass techniques to evade detection.

# 17.1.3.1 Exercises
1. Migrate the Meterpreter shell to a more stable process.
2. Perform host-based enumeration to detect security solutions in place. Think about how that
might impact us.
3. Bypass AMSI, perform AD-related enumeration, and find the constrained delegation.

# 17.2.1.1 Exercises
1. Modify the code for PrintSpooferNet to work from a shell with a logon session.
2. Transfer the required files and prepare Metasploit by launching two command prompts
along with the listener.
3. Execute the attack and elevate privileges to SYSTEM.

# 17.2.2.1 Exercises
1. Download the appropriate versions of mimidrv.sys and Invoke-Mimikatz to the Kali machine
web root.
2. Migrate the SYSTEM shell into a different SYSTEM process to ensure stability.
3. Transfer the Mimikatz driver and launch it manually with the service control manager.
4. Disable AMSI and use Invoke-Mimikatz to disable the PPL protection on LSASS.
5. Transfer and use the custom application to dump the LSASS process memory.
6. Download the dump file, transfer it to the “test” machine, and extract the NTLM hash for the
web01 machine account.

# 17.2.3.1 Exercises
1. Download the Rubeus Visual Studio solution from Github, modify the .NET version, and
compile it.
2. From the SYSTEM shell, disable AMSI and download Rubeus into memory.
Evasion Techniques and Breaching Defenses
3. Invoke Rubeus to request a TGS for the CIFS service on file01 as the administrator user.
4. Use the requested ticket to verify access to the shares on file01.

# 17.3.1.1 Exercises
1. Combine the code required to perform process injection and bypass AV detection.
2. Modify the lateral movement code and transfer all the required files to the appropriate
locations.
3. Attempt lateral movement with a Meterpreter payload directly and determine if it was caught
by AV.
4. If your Meterpreter session timed out, adapt your code to remove the AV definitions.
5. Obtain a Meterpreter shell on file01 without any Windows Defender flags.

# 17.3.2.1 Exercises
1. Use the Meterpreter shell to list all access tokens and impersonate the token belonging to
the paul user.
2. While impersonating paul, perform lateral movement to dc02 and obtain a reverse
Meterpreter shell.