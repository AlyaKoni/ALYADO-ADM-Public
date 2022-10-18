$pageUrl = "https://www.gimp.org/downloads/"
$req = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*gimp[^`"]*setup[^`"]*.exe"
$newUrl = "https:"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrl
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
