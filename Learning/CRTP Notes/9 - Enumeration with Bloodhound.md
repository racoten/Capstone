# BloodHound

• Provides GUI for AD entities and relationships for the data collected by its ingestors.

• Uses Graph Theory for providing the capability of mapping shortest path for interesting things like Domain Admins.

`https://github.com/BloodHoundAD/BloodHound`

• There are built-in queries for frequently used actions.

• Also supports custom Cypher queries.

#### Supply data to BloodHound:
```powershell
C:\AD\Tools\BloodHound-master\Ingestors\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
```
• The generated archive can be uploaded to the BloodHound application.

#### To avoid detections like ATA 
```powershell
Invoke-BloodHound -CollectionMethod All -ExcludeDC
```

Learning Objective 6
• Setup BloodHound and identify a machine where studentx has local administrative access. 
