List everything about the help topics  
`Get-Help *`

List everything which contains the word process  
`Get-Help process` 

Update the help system (v3+) 
`Update-Help`  

List full help about a topic (Get-Item cmdlet in this case)  
`Get-Help Get-Item -Full`  

List examples of how to run a cmdlet (Get-Item in this case)  
`Get-Help Get-Item -Examples`  

Execution Policy **_NOT A SECURITY LAYER_**  

```powershell
powershell -ExecutionPolicy bypass  
powershell -c  
powershell -encodedcommand  
$env:PSExecutionPolicyPreference="bypass"  
```

PowerShell Module Imports  

A module can be imported with  
`Import-Module <module path>`  

All the commands in a module can be listed with  
`Get-Command -Module <module name>`