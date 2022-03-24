$version = 22
do
{
    $version--
    $pageUrl = "https://jdk.java.net/$version/"
    $check = $null
    try
    {
        $req = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -Method Get
        [regex]$regex = "<h1>.*?General-Availability Release.*?</h1>"
        $check = ([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
    } catch {}
} while (-Not $check -and $version -gt 16)

[regex]$regex = "[^`"']*openjdk-[^`"']*windows-x64_bin.zip"
$newUrl = ([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrl
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
