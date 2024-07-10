Now that you've completed the RTO course (congrats), you're ready to attempt the exam.  The booking page can be found [here](https://training.zeropointsecurity.co.uk/pages/red-team-ops-exam) - make sure you read all the information thoroughly.  To facilitate an easier learning experience, Windows Defender is disabled on most of the machines in the RTO lab.  This is so that you can get familiar with the various attacks and techniques without that added layer of difficulty.  In contrast, Windows Defender is enabled on every machine in the exam, which can be quite a step up if you're not prepared.

The most effective way you can prepare for the exam is to go back over the TTPs covered in the RTO course and lab, but with Defender enabled.  This page will guide you through the process of how you can do that.

Defender is disabled via GPO, which you can see by opening Group Management Console (GPMC) on Domain Controller 2 (_dc-2.dev.cyberbotic.io_).  The GPO is simply called "Windows Defender" and is linked to the Domain Controllers, SQL Servers, Web Servers and Workstations OU.


![](https://files.cdn.thinkific.com/file_uploads/584845/images/1de/37a/d26/gpmc.png)

To re-enable Defender on all of these machines, right-click the GPO and select Edit.  Navigate to _Computer Configuration > Policies > Administrative Templates > Windows Components > Microsoft Defender Antivirus_.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/75f/5d1/f10/defender-policies.png)

Here, we want to change each policy to the opposite of what it's currently set to.  To change _Turn off Microsoft Defender Antivirus_ and _Turn off routine remediation_ to _Disabled_.

Slightly above, go into the "Real-time Protection" folder.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/300/565/ed0/real-time.png)

Do exactly the same here by setting _Turn off real-time protection_ to _Disabled_ and those that are already Disabled to _Enabled_.  Once your changes are made, you can either force GPO updates from directly inside GPMC by right-clicking on each OU and selecting _Group Policy Update_.  This will schedule an update with the next 10 minute window.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/3c9/22b/9cd/gpupdate.png)

Alternatively, you can log into the console of each machine and manually run `gpupdate /force` from a command prompt.

Once the updates have been applied, initiate a reboot of the entire lab from the Snap Labs dashboard.  In my experience, Defender will then be enabled on the next boot.  You may see this error message inside the Windows Security settings on some machines, but simply click _Restart now_ and everything should be fine.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/44c/eee/c3e/windows-security.png)

To test AMSI, use the AMSI Test Sample PowerShell cmdlet.

Invoke-Expression 'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'

You should see that the cmdlet gets blocked:
```powershell
At line:1 char:1
+ Invoke-Expression 'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
```

However, this error means that Defender is not running properly:

AMSI: The term 'AMSI' is not recognized as a name of a cmdlet, function, script file, or executable program.
Check the spelling of the name, or if a path was included, verify that the path is correct and try again.

To test on-disk detections, drop the EICAR test file somewhere such as the desktop.
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

![](https://files.cdn.thinkific.com/file_uploads/584845/images/f2b/a36/dfb/eicar.png)