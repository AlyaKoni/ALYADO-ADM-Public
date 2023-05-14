$pageUrl = "https://support.apple.com/de-ch/HT210384"
$req = Invoke-WebRequestIndep -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*iTunes64Setup.exe"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value

$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $tmp = New-Item -Path $contentRoot -ItemType Directory -Force
}

Invoke-WebRequest -UseBasicParsing -Uri $newUrl -Method Get -OutFile "$contentRoot\iTunes64Setup.exe"

Push-Location "$contentRoot"
.\iTunes64Setup.exe /extract
do
{
    Start-Sleep -Milliseconds 500
    $proc = Get-Process -Name "iTunes64Setup" -ErrorAction SilentlyContinue
} while ($proc)
foreach($file in (Get-ChildItem -Path $contentRoot))
{
    if ($file.Name -ne "AppleMobileDeviceSupport64.msi" -and $file.Name -ne "iTunes64Setup.exe" -and `
        -Not $file.Name.EndsWith(".ps1") -and -Not $file.Name.EndsWith(".cmd"))
    {
        $file | Remove-Item -Force
    }
}
Pop-Location 
