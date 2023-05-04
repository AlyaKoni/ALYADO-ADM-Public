$pageUrl = "https://mremoteng.org/download"
$req = Invoke-WebRequest -SkipHttpErrorCheck -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"']*mRemoteNG-Installer[^`"']*.msi"
$newUrl = ([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrl
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
