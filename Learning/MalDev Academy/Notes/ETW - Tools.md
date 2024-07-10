### Introduction

The previous module introduced covered theoretical concepts surrounding ETW architecture, components and their functionality. This module will introduce several tools that allow a user to engage with ETW. Interacting with ETW provides the reader with a practical understanding of its functionality, which serves as a prerequisite for discussing security bypass techniques.

### Logman Tool

The native command-line tool for Windows, [Logman](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/logman), serves as an example of an _ETW controller_. It enables users to initiate and terminate ETW tracing sessions. These tracing sessions capture events that are then stored in files specifically designed for tracing which are typically identified by the `.etl` file extension. Executing the help command (`/?`) in Logman will result in the following output.

```
Microsoft ® Logman.exe (10.0.22621.1)

Usage:
  C:\Windows\system32\logman.exe [create|query|start|stop|delete|update|import|export] [options]

Verbs:
  create                        Create a new data collector.
  query                         Query data collector properties. If no name is given all data collectors are listed.
  start                         Start an existing data collector and set the begin time to manual.
  stop                          Stop an existing data collector and set the end time to manual.
  delete                        Delete an existing data collector.
  update                        Update an existing data collector's properties.
  import                        Import a data collector set from an XML file.
  export                        Export a data collector set to an XML file.

Adverbs:
  counter                       Create a counter data collector.
  trace                         Create a trace data collector.
  alert                         Create an alert data collector.
  cfg                           Create a configuration data collector.
  providers                     Show registered providers.

Options (counter):
  -c <path [path [...]]>        Performance counters to collect.
  -cf <filename>                File listing performance counters to collect, one per line.
  -f <bin|bincirc|csv|tsv|sql>  Specifies the log format for the data collector. For SQL database format, you must
                                use the -o option in the command line with the DNS!log option. The defaults is binary.
  -sc <value>                   Maximum number of samples to collect with a performance counter data collector.
  -si <[[hh:]mm:]ss>            Sample interval for performance counter data collectors.

Options (trace):
  -f <bin|bincirc|csv|tsv|sql>  Specifies the log format for the data collector. For SQL database format, you must
                                use the -o option in the command line with the DNS!log option. The defaults is binary.
  -mode <trace_mode>            Event Trace Session logger mode. For more information visit -
                                https://go.microsoft.com/fwlink/?LinkID=136464
  -ct <perf|system|cycle>       Specifies the clock resolution to use when logging the time stamp for each event.
                                You can use query performance counter, system time, or CPU cycle.
  -ln <logger_name>             Logger name for Event Trace Sessions.
  -ft <[[hh:]mm:]ss>            Event Trace Session flush timer.
  -[-]p <provider [flags [level]]> A single Event Trace provider to enable. The terms 'Flags' and 'Keywords' are
                                synonymous in this context.
  -pf <filename>                File listing multiple Event Trace providers to enable.
  -[-]rt                        Run the Event Trace Session in real-time mode.
  -[-]ul                        Run the Event Trace Session in user mode.
  -bs <value>                   Event Trace Session buffer size in kb.
  -nb <min max>                 Number of Event Trace Session buffers.

Options (alert):
  -[-]el                        Enable/Disable event log reporting.
  -th <threshold [threshold [...]]> Specify counters and their threshold values for and alert.
  -[-]rdcs <name>               Data collector set to start when alert fires.
  -[-]tn <task>                 Task to run when alert fires.
  -[-]targ <argument>           Task arguments.
  -si <[[hh:]mm:]ss>            Sample interval for performance counter data collectors.

Options (cfg):
  -[-]ni                        Enable/Disable network interface query.
  -reg <path [path [...]]>      Registry values to collect.
  -mgt <query [query [...]]>    WMI objects to collect.
  -ftc <path [path [...]]>      Full path to the files to collect.

Options:
  -?                            Displays context sensitive help.
  -s <computer>                 Perform the command on specified remote system.
  -config <filename>            Settings file containing command options.
  [-n] <name>                   Name of the target object.
  -pid <pid>                    Process identifier.
  -xml <filename>               Name of the XML file to import or export.
  -as                           Perform the requested operation asynchronously.
  -[-]u <user [password]>       User to Run As. Entering a * for the password produces a prompt for the password.
                                The password is not displayed when you type it at the password prompt.
  -m <[start] [stop]>           Change to manual start or stop instead of a scheduled begin or end time.
  -rf <[[hh:]mm:]ss>            Run the data collector for the specified period of time.
  -b <M/d/yyyy h:mm:ss[AM|PM]>  Begin the data collector at specified time.
  -e <M/d/yyyy h:mm:ss[AM|PM]>  End the data collector at specified time.
  -o <path|dsn!log>             Path of the output log file or the DSN and log set name in a SQL database. The
                                default path is '%systemdrive%\PerfLogs\Admin'.
  -[-]r                         Repeat the data collector daily at the specified begin and end times.
  -[-]a                         Append to an existing log file.
  -[-]ow                        Overwrite an existing log file.
  -[-]v <nnnnnn|mmddhhmm>       Attach file versioning information to the end of the log name.
  -[-]rc <task>                 Run the command specified each time the log is closed.
  -[-]max <value>               Maximum log file size in MB or number of records for SQL logs.
  -[-]cnf <[[hh:]mm:]ss>        Create a new file when the specified time has elapsed or when the max size is
                                exceeded.
  -y                            Answer yes to all questions without prompting.
  -fd                           Flushes all the active buffers of an existing Event Trace Session to disk.
  -ets                          Send commands to Event Trace Sessions directly without saving or scheduling.

Note:
  Where [-] is listed, an extra - negates the option.
  For example --u turns off the -u option.

More Information:
  Microsoft TechNet - https://go.microsoft.com/fwlink/?LinkID=136332

Examples:
  logman start perf_log
  logman update perf_log -si 10 -f csv -v mmddhhmm
  logman create counter perf_log -c "\Processor(_Total)\% Processor Time"
  logman create counter perf_log -c "\Processor(_Total)\% Processor Time" -max 10 -rf 01:00
  logman create trace trace_log -nb 16 256 -bs 64 -o c:\logfile
  logman create alert new_alert -th "\Processor(_Total)\% Processor Time>50"
  logman create cfg cfg_log -reg "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\\"
  logman create cfg cfg_log -mgt "root\cimv2:SELECT * FROM Win32_OperatingSystem"
  logman query providers
  logman query providers Microsoft-Windows-Diagnostics-Networking
  logman start process_trace -p Microsoft-Windows-Kernel-Process 0x10 win:Informational -ets
  logman start usermode_trace -p "Service Control Manager Trace" -ul -ets
  logman query usermode_trace -p "Service Control Manager Trace" -ul -ets
  logman stop usermode_trace -p "Service Control Manager Trace" -ul -ets
  logman start process_trace -p Microsoft-Windows-Kernel-Process -mode newfile -max 1 -o output%d.etl -ets
  logman start "NT Kernel Logger" -o log.etl -ets
  logman start "NT Kernel Logger" -p "Windows Kernel Trace" (process,thread) -ets
```

#### Creating A Trace Session Via Logman

To start an ETW tracing session using Logman, one must run the `logman create trace` command with Administrator privileges. The `create` parameter can be used to create other items as shown below:

- `logman create counter` - Creates a counter data collector.
    
- `logman create cfg` - Creates a configuration data collector.
    

However, for this module, the focus will be on constructing a tracing session and therefore only the `logman create trace` command will be used. When creating a tracing session several parameters are required:

1. Session name - The name of the session.
    
2. File output path - The path where the `.etl` file should be saved. This is specified using the `-o` flag.
    
3. Provider name - The name of the ETW provider which will write the events to the created session. Available ETW providers can be queried using the `logman query providers` command. This is specified using the `-p` flag.
    

```
logman create trace <Session Name> -o <Path to the .etl file to create> -p <ETW provider name>
```

Adding the `-ets` option to the command will send commands directly to the tracing session without saving or scheduling the session for future use. Below is an example of creating an ETW tracing session using the `logman` command line tool.

```
:: Session name - MALDEV_ETW_SESSION
:: Output file path - C:\Users\Admin\Desktop\Output.etl
:: Provider name - Microsoft-Windows-Kernel-Process
logman create trace MALDEV_ETW_SESSION -o C:\Users\Admin\Desktop\Output.etl -p Microsoft-Windows-Kernel-Process -ets
```

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-148232593-824bc5f8-28c4-4e0a-afbd-746330c8d187.png)

#### Inspecting Trace Files

Once the trace file from the `MALDEV_ETW_SESSION` session has been created, it can be viewed using _Event Viewer_. Event Viewer is a Windows tools that displays detailed information about logged events. The steps below outline how one can open a trace file using Event Viewer and investigate the events saved to it.

1.Open Event Viewer and go to "Action > Open Saved Log".

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-248280626-f14c2cf2-ce5f-4a14-b9b6-a47ce40690fb.png)

2.Click "Yes" when the message below appears.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-348280859-cbd8e781-be56-40fe-9efa-30b3710b3801.png)

3.Press "OK" where to keep the default settings.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-448298003-55706fbb-3e6c-43f0-9ca9-2a54a91ea35f.png)

4.Next, the `Output.etl` file's events are shown and categorized according to event IDs.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-548300833-665601bc-d202-4f67-8274-b49e04dd28fe.png)

5.Double-clicking on an event will show the event's details. For example, event ID 1 is related to process creation which shows the `Firefox.exe` process being launched.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-648301736-ba0afd36-d806-48dc-8d7e-7501f6a84475.png)

6.Different event IDs will show different types of information. For example, event ID 2 is related to process terminations.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-748302339-7759f7f1-cdd6-416a-8bf3-88394dd92199.png)

#### Stopping A Trace Session Via Logman

When a tracing session is initiated, it will continue to run and log events as long as any registered provider is present until it is manually stopped. To halt an ETW tracing session using `logman`, the following command line can be used:

```
logman stop <Session Name To Stop> -ets
```

### Querying Information Via Logman

Besides creating and stopping tracing sessions, logman can be used to query details about existing sessions. This is done using the `query` parameter, which can query the following information:

- **Query ETW providers** - Using the `logman query providers` command. Sample output is shown below (output is truncated due to its size).

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-848304218-738bd50a-554d-40dc-a050-dbcb05ded4f9.png)

- **Query information about an ETW provider** - Using the `logman query providers <Provider Name To Query>` command. This command shows the _Keywords_ of an ETW provider which are used to filter the events written to the tracing session when it's created. More information on keywords can be found [here](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/etw-event-tracing-for-windows-101).

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-948310609-8f9d53bb-b3a5-4020-821d-7f5aeb809685.png)

- **Query running ETW tracing sessions** - Using the `logman query -ets` command.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-10-248305089-0ecdf1a5-1434-47d9-a40c-e98722ca422c.png)

- **Query information about an ETW tracing session** - Using the `logman query <Session Name To Query> -ets` command.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-11-248307315-bfadc954-9ca1-404b-90cc-32450da50af0.png)

### ETWExplorer

[ETWExplorer](https://github.com/zodiacon/EtwExplorer) is an open-source tool that facilitates in-depth analysis of ETW providers, providing insights into the information reported by each provider. To examine a particular ETW provider, such as `Microsoft-Windows-Threat-Intelligence` in this example, one can follow these steps after downloading the ETWExplorer tool.

1.Click "Open Provider".

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-12-248441553-a5f25d5c-79bf-4299-bd92-dde47a238f65.png)

2.Search for the provider's name, select it, then click "OK".

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-13-248441618-ef7a6502-4d25-43f0-9c28-a3413e45a70b.png)

3.The _Events_ tab provides access to the keywords associated with an ETW provider, with each keyword representing a distinct data structure that can be examined by the ETW consumer. In the image below, the occurrence of the `KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE` event reveals the reported data structure, specifically the `KERNEL_THREATINT_TASK_PROTECTVM_V1`. This data structure includes information such as the base address and size of the remote memory that is permitted to be modified.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-14-248441649-8e6de2fb-e39b-4c3a-a484-b391d29d6ba3.png)

4.An additional example is the `KERNEL_THREATINT_TASK_WRITEVM_V1` structure, which is reported when the `KERNEL_THREATINT_KEYWORD_WRITEVM_LOCAL` event occurs. Within this structure, the ETW consumer gains access to the buffers that are written to and from.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-15-248442086-6896cac9-5298-4583-892a-cde32e7326d9.png)

The `ETWExplorer` tool provides valuable insights into how security solutions programs can work as ETW consumers and leverage the reported data. For instance, it allows security products to initiate a memory scan at the indicated base addresses when specific events are triggered. This capability enhances the effectiveness of detecting and responding to relevant events.

### Maldev Academy ETW Tools

In addition to the publicly available tools, this module will introduce two Maldev Academy ETW tools.

#### QueryEtwSessions

The `QueryEtwSessions` tool utilizes the [QueryAllTracesW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-queryalltracesw) WinAPI to list all active ETW tracing sessions and provide essential details about each session. Understanding the tool's code is not necessary and will be addressed later if required. However, it is crucial to be familiar with the [EVENT_TRACE_PROPERTIES](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties) data structure, which represents a distinct ETW tracing session and is used in most WinAPIs related to ETW tracing sessions. The image below displays the output of the `QueryEtwSessions` tool.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-16-248443612-a02aff0a-a6d6-43b5-908b-fe8bc53b5dce.png)

#### DotNetEtwConsumer

The `DotNetEtwConsumer` tool is an ETW consumer, that reads real-time events from the `Microsoft-Windows-DotNETRuntime` ETW provider, which has the `{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}` GUID. This provider reports actions related to Common Language Runtime (CLR) in .NET images such as loading and unloading them. `DotNetEtwConsumer` will print the name of the CLR .NET image loaded, the time in which it was loaded, and the PID of the process that loaded the image. The tool makes use of the following WinAPIs:

- [StartTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew) - Used to start an event tracing session. In the `DotNetEtwConsumer` tool, the session's name is `MALDEVACAD_DOT_NET_ETW`.
    
- [EnableTraceEx](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex) - Used to configure how an ETW event provider logs events to a trace session. This WinAPI is used to filter the events to record CLR loading actions only.
    
- [OpenTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew) - Opens a handle for consuming events from an ETW real-time trace session, which is the case in the `MALDEVACAD_DOT_NET_ETW` session.
    
- [ProcessTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace) - Delivers events from the ETW trace session to the ETW consumer.
    
- [StopTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-stoptracew) - Used at the end to stop a specified event tracing session. It is equivalent to the `logman stop` command.
    

The image below shows the tool in action. Note that the tool will only stop recording events when the user sends an interrupt signal (Ctrl + C).

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-tools-17-248444169-2da2e3c5-f892-41bc-af98-c96d71f3ab91.png)

Similar to the previous Maldev Academy tool, understanding the code is not crucial. However, the code has been thoroughly commented to provide ease of comprehension for those interested in reading it.

### Conclusion

In this module, several tools were presented that enable interaction with ETW. It is strongly advised for the reader to have a solid understanding of ETW before proceeding to the next module, as it dives into the topic of ETW evasion. Additionally, it is recommended to review the following blog posts before progressing to the next module.

- [Tampering with Windows Event Tracing: Background, Offense, and Defense](https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63)
    
- [Threat Hunting with ETW events and HELK](https://medium.com/threat-hunters-forge/threat-hunting-with-etw-events-and-helk-part-1-installing-silketw-6eb74815e4a0)
    
- [ETW: Event Tracing for Windows 101](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/etw-event-tracing-for-windows-101)
    
- [A Beginners All Inclusive Guide to ETW](https://bmcder.com/blog/a-begginers-all-inclusive-guide-to-etw)