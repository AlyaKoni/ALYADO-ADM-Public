#Requires -Version 2

<#
    Copyright (c) Alya Consulting, 2019-2023

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    Die Alya Basis Konfiguration ist eine Freie Software: Sie können sie unter den
    Bedingungen der GNU General Public License, wie von der Free Software
    Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veröffentlichten Version, weiter verteilen und/oder modifizieren.
    Die Alya Basis Konfiguration wird in der Hoffnung, dass sie nützlich sein wird,
    aber OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
    https://www.gnu.org/licenses/gpl-3.0.txt


#>

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
$packageInfo = [xml](Get-Content -Path "$($package.FullName).Detection.xml" -Raw -Encoding $AlyaUtf8Encoding)
Remove-Item -Path "$($package.FullName).Detection.xml" -Force

if ($versionObj.version -ne $packageInfo.ApplicationInfo.MsiInfo.MsiProductVersion)
{
    throw "Something went wrong with the version info. Filename and packageInfo are different"
}

$versionObj.regPath = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($packageInfo.ApplicationInfo.MsiInfo.MsiProductCode)"
$versionObj.regValue = "DisplayVersion"

Write-Host "      regPath: $($versionObj.regPath)"
$versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Encoding UTF8 -Force
