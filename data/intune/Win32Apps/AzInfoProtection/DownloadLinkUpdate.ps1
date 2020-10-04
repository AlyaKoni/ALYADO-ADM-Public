$pageUrl = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=53018"
$req = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*AzInfoProtection[^`"]*UL[^`"]*central[^`"]*.msi"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrl
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
