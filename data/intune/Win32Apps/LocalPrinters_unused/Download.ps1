$hpPclDownloadUrl = "https://ftp.hp.com/pub/softlib/software13/COL40842/ds-99374-23/upd-pcl6-x64-7.0.0.24832.exe"
$hpPsDownloadUrl = "https://ftp.hp.com/pub/softlib/software13/COL40842/ds-99376-23/upd-ps-x64-7.0.0.24832.exe"
$sharpPclDownloadUrl = "http://global.sharp/restricted/products/copier/downloads/search/files/021418/SH_D09_PCL6_PS_2005a_German_64bit.exe"
$innoextractDownloadUrl = "https://constexpr.org/innoextract/files/innoextract-1.9-windows.zip"

$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "ContentZip"

# HpPcl6
$instPath = Join-Path $contentRoot "HpPcl6"
if ((Test-Path $instPath))
{
    Remove-Item -Path $instPath -Recurse -Force
}
$tmp = New-Item -Path $instPath -ItemType Directory -Force
$unpackFile = Join-Path $contentRoot "driver.zip"
$req = Invoke-WebRequest -Uri $hpPclDownloadUrl -Method Get -OutFile $unpackFile
Expand-Archive -Path $unpackFile -DestinationPath $instPath -Force
Remove-Item -Path $unpackFile -Force

# HpPs6
$instPath = Join-Path $contentRoot "HpPs"
if ((Test-Path $instPath))
{
    Remove-Item -Path $instPath -Recurse -Force
}
$tmp = New-Item -Path $instPath -ItemType Directory -Force
$unpackFile = Join-Path $contentRoot "driver.zip"
$req = Invoke-WebRequest -Uri $hpPsDownloadUrl -Method Get -OutFile $unpackFile
Expand-Archive -Path $unpackFile -DestinationPath $instPath -Force
Remove-Item -Path $unpackFile -Force

# innoextract
$instPath = Join-Path $contentRoot "innoextract"
if ((Test-Path $instPath))
{
    Remove-Item -Path $instPath -Recurse -Force
}
$tmp = New-Item -Path $instPath -ItemType Directory -Force
$unpackFile = Join-Path $contentRoot "innoextract.zip"
$req = Invoke-WebRequest -Uri $innoextractDownloadUrl -Method Get -OutFile $unpackFile
Expand-Archive -Path $unpackFile -DestinationPath $instPath -Force
Remove-Item -Path $unpackFile -Force
$innopath = $instPath
$innoextract = Join-Path $instPath "innoextract.exe"

# SharpPcl6
$instPath = Join-Path $contentRoot "SharpPcl6"
if ((Test-Path $instPath))
{
    Remove-Item -Path $instPath -Recurse -Force
}
$tmp = New-Item -Path $instPath -ItemType Directory -Force
$unpackFile = Join-Path $contentRoot "driver.exe"
$req = Invoke-WebRequest -Uri $sharpPclDownloadUrl -Method Get -OutFile $unpackFile
Push-Location -Path $instPath
& "$innoextract" $unpackFile
Pop-Location
Remove-Item -Path $innopath -Recurse -Force
Remove-Item -Path $unpackFile -Force
