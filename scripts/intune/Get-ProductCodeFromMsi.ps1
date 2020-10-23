#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2019, 2020

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
    Alya Basis Konfiguration ist Freie Software: Sie koennen es unter den
	Bedingungen der GNU General Public License, wie von der Free Software
	Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veroeffentlichten Version, weiter verteilen und/oder modifizieren.
    Alya Basis Konfiguration wird in der Hoffnung, dass es nuetzlich sein wird,
	aber OHNE JEDE GEWAEHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewaehrleistung der MARKTFAEHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
	https://www.gnu.org/licenses/gpl-3.0.txt

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    29.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$msiPath = $null
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Get-ProductCodeFromMsi-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Get-ProductCodeFromMsi | Local" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
if (-Not $msiPath)
{
    $msiPath = Read-Host "Please specify the path to the msi file:"
}
if (-Not (Test-Path $msiPath))
{
    Write-Error "Msi file $($msiPath) does not exist" -ErrorAction Continue
}

$RepRoot = Join-Path $AlyaTools "IntuneWinAppUtil"
$tool = Join-Path (Join-Path $AlyaTools "IntuneWinAppUtil") "IntuneWinAppUtil.exe"
$temp = Join-Path $AlyaTemp "ProdCodeFromMsi"
$tempMsi = "$temp" + $msiPath.Substring($msiPath.LastIndexOf("\"))
$tempPck = $tempMsi.Replace(".msi", ".intunewin").Replace(".exe", ".intunewin")
$detection = "$temp\IntuneWinPackage\Metadata\Detection.xml"

$tmp = New-Item -Path $temp -ItemType Directory -Force
$tmp = Copy-Item -Path $msiPath -Destination $tempMsi -Force

Write-Host "Launching IntuneWinAppUtil" -ForegroundColor $CommandInfo
$Command = "& `"$tool`" -c `"$temp`" -s `"$tempMsi`" -o `"$temp`" -q"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
Start-Process PowerShell.exe -ArgumentList "-EncodedCommand $EncodedCommand" -Wait -NoNewWindow
if (-Not (Test-Path "$tempPck"))
{
    Write-Error "Intune package not created!" -ErrorAction Continue
    exit
}

Write-Host "Getting information from Detection.xml" -ForegroundColor $CommandInfo
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($tempPck)
$entry = $zip.Entries | Where-Object { $_.Name -eq "Detection.xml" }
[System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, "$temp\$($entry.Name)", $true)
$zip.Dispose()
$xml = [xml](Get-Content -Path "$temp\$($entry.Name)" -Raw -Encoding UTF8)
Write-Host "MsiProductCode:                $($xml.ApplicationInfo.MsiInfo.MsiProductCode)"
Write-Host "MsiProductVersion:             $($xml.ApplicationInfo.MsiInfo.MsiProductVersion)"
Write-Host "MsiPackageCode:                $($xml.ApplicationInfo.MsiInfo.MsiPackageCode)"
Write-Host "MsiUpgradeCode:                $($xml.ApplicationInfo.MsiInfo.MsiUpgradeCode)"
Write-Host "MsiExecutionContext:           $($xml.ApplicationInfo.MsiInfo.MsiExecutionContext)"
Write-Host "MsiRequiresLogon:              $($xml.ApplicationInfo.MsiInfo.MsiRequiresLogon)"
Write-Host "MsiRequiresReboot:             $($xml.ApplicationInfo.MsiInfo.MsiRequiresReboot)"
Write-Host "MsiIsMachineInstall:           $($xml.ApplicationInfo.MsiInfo.MsiIsMachineInstall)"
Write-Host "MsiIsUserInstall:              $($xml.ApplicationInfo.MsiInfo.MsiIsUserInstall)"
Write-Host "MsiIncludesServices:           $($xml.ApplicationInfo.MsiInfo.MsiIncludesServices)"
Write-Host "MsiIncludesODBCDataSource:     $($xml.ApplicationInfo.MsiInfo.MsiIncludesODBCDataSource)"
Write-Host "MsiContainsSystemRegistryKeys: $($xml.ApplicationInfo.MsiInfo.MsiContainsSystemRegistryKeys)"
Write-Host "MsiContainsSystemFolders:      $($xml.ApplicationInfo.MsiInfo.MsiContainsSystemFolders)"
Write-Host "MsiPublisher:                  $($xml.ApplicationInfo.MsiInfo.MsiPublisher)"

$MsiProductCode = $xml.ApplicationInfo.MsiInfo.MsiProductCode
$MsiProductVersion = $xml.ApplicationInfo.MsiInfo.MsiProductVersion
$MsiPackageCode = $xml.ApplicationInfo.MsiInfo.MsiPackageCode
$MsiUpgradeCode = $xml.ApplicationInfo.MsiInfo.MsiUpgradeCode

Remove-Item -Path $temp -Recurse -Force

#Stopping Transscript
Stop-Transcript