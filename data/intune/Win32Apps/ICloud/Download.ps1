$pageUrl = "https://support.apple.com/de-ch/HT204283"
$req = Invoke-WebRequestIndep -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*iCloudSetup.exe"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value

$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $tmp = New-Item -Path $contentRoot -ItemType Directory -Force
}

Invoke-WebRequest -UseBasicParsing -Uri $newUrl -Method Get -OutFile "$contentRoot\iCloudSetup.exe"

Push-Location "$contentRoot"
.\iCloudSetup.exe /extract
do
{
    Start-Sleep -Milliseconds 500
    $proc = Get-Process -Name "iCloudSetup" -ErrorAction SilentlyContinue
} while ($proc)
foreach($file in (Get-ChildItem -Path $contentRoot))
{
    if ($file.Name -ne "AppleApplicationSupport64.msi" -and $file.Name -ne "iCloudSetup.exe")
    {
        $file | Remove-Item -Force
    }
}
Pop-Location 
