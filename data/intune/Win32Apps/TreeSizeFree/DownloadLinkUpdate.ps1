$pageUrl = "https://www.jam-software.de/treesize_free"
$req = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "<a\s*href=`"([^`"]*)`"\s*class=`"button`"\s*>\s*Download\s*</a>"
$matches = [regex]::Matches($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant')
$newUrl = $matches[0].Groups[1].Value
$uri = [Uri]::new($newUrl)

$req = Invoke-WebRequest -Uri $newUrl -UseBasicParsing -Method Get
[regex]$regex = "<option\s*value=`"([^`"]*)`"\s*>TreeSizeFreeSetup.*"
$matches = [regex]::Matches($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant')

$path = $uri.AbsolutePath.Replace("downloadTrial.php", "downloadTrialProcess.php")
$newUrl = $uri.Scheme+"://"+$uri.Authority+$path+"?download_x=Download&download_path="+$matches[0].Groups[1].Value
$req = Invoke-WebRequest -Uri $newUrl -UseBasicParsing -Method Post

[regex]$regex = "<a\s*href=`"([^`"]*\.exe)`"\s*>"
$matches = [regex]::Matches($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant')
$newUrl = $matches[0].Groups[1].Value

$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrl
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
