Write-Host "    Preparing version"
$packageRoot = "$PSScriptRoot"
$versionFile = Join-Path $packageRoot "version.json"
if ((Test-Path $versionFile))
{
    $versionObj = Get-Content -Path $versionFile -Raw -Encoding UTF8 | ConvertFrom-Json
}
else
{
    throw "Can't find version.json file! PrepareVersion.ps1 has to run first!"
}
Write-Host "      actual version: $($versionObj.version)"

# Checking intunewin package
Write-Host "  Checking intunewin package"
$packagePath = Join-Path $packageRoot "Package"
$package = Get-ChildItem -Path $packagePath -Filter "*.intunewin"
if (-Not $package)
{
    throw "Can't find Intune package!"
}

# Extracting package information
Write-Host "  Extracting package information"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
$entry = $zip.Entries | Where-Object { $_.Name -eq "Detection.xml" }
[System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, "$($package.FullName).Detection.xml", $true)
$zip.Dispose()
$packageInfo = [xml](Get-Content -Path "$($package.FullName).Detection.xml" -Raw -Encoding UTF8)
Remove-Item -Path "$($package.FullName).Detection.xml" -Force

if ($versionObj.version -ne $packageInfo.ApplicationInfo.MsiInfo.MsiProductVersion)
{
    throw "Something went wrong with the version info. Filename and packageInfo are different"
}

$versionObj.regPath = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($packageInfo.ApplicationInfo.MsiInfo.MsiProductCode)"
$versionObj.regValue = "DisplayVersion"

Write-Host "      regPath: $($versionObj.regPath)"
$versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Encoding UTF8 -Force
