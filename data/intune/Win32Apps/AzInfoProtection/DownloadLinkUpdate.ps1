$pageUrl = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=53018"
$req = Invoke-WebRequestIndep -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regexAzp = "[^`"]*AzInfoProtection[^`"]*UL[^`"]*.exe"
$newUrlAzp = [regex]::Match($req.Content, $regexAzp, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrlAzp
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
