$pageUrl = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=53018"
$req = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regexAuth = "[^`"]*AzInfoProtection[^`"]*CoAuthoring[^`"]*.exe"
$newUrlAuth = [regex]::Match($req.Content, $regexAuth, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrlAuth
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
