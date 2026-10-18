#Requires -Version 2

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    Die Alya Basis Konfiguration ist eine Freie Software: Sie können sie unter den
    Bedingungen der GNU General Public License, wie von der Free Software
    Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veröffentlichten Version, weiter verteilen und/oder modifizieren.
    Die Alya Basis Konfiguration wird in der Hoffnung, dass sie nützlich sein wird,
    aber OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
    https://www.gnu.org/licenses/gpl-3.0.txt


    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    14.10.2026 Konrad Brunner       Initial Version

#>

<#
.SYNOPSIS
Prepares and updates the version information for the Zoom Workplace package.

.DESCRIPTION
The Zoom MSI ProductVersion is 3-part (e.g. 7.2.48556) while the Zoom.exe file version used by the detection rules is 4-part (e.g. 7.2.1.48556). Therefore the version must not be taken from the MSI metadata. The reliable source is the CDN location the stable Zoom download URL redirects to: the script requests https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64 without following the redirect and extracts the 4-part version from the location header (https://cdn.zoom.us/prod/<version>/x64/ZoomInstallerFull.msi). The detected version is written to version.json in the package folder; the upload scripts prefer version.json over MSI metadata for all detection and display versions.

.INPUTS
None. The script does not take any input objects.

.OUTPUTS
Creates or updates version.json in the script's directory.

.EXAMPLE
PS> .\PrepareVersion.ps1
Requests the Zoom download URL and writes the detected 4-part version to version.json.

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
)

Write-Host "    Preparing version"
$packageRoot = "$PSScriptRoot"
$versionFile = Join-Path $packageRoot "version.json"
if ((Test-Path $versionFile))
{
    $versionObj = Get-Content -Path $versionFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $version = [Version]$versionObj.version
}
else
{
    $versionObj = @{}
    $versionObj.version = "1.0"
    $version = [Version]$versionObj.version
}
Write-Host "      actual: $version"

# The 4-part version comes from the CDN path the stable download URL redirects to.
$downloadUrl = "https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64"
$location = $null
try
{
    try { Add-Type -AssemblyName System.Net.Http } catch {}
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    $response = $client.GetAsync($downloadUrl, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
    if ($null -ne $response.Headers.Location)
    {
        $location = $response.Headers.Location.AbsoluteUri
    }
    $response.Dispose()
    $client.Dispose()
}
catch
{
    Write-Error "Could not request the Zoom download URL: $($_.Exception.Message)"
    Exit 1
}
if (-Not $location)
{
    Write-Error "The Zoom download URL did not return a redirect location. Cannot determine the version."
    Exit 1
}
Write-Host "      CDN location: $location"
[regex]$regex = "prod/(\d+\.\d+\.\d+\.\d+)/"
$versionStr = [regex]::Match($location, $regex).Groups[1].Value
if ([string]::IsNullOrEmpty($versionStr))
{
    Write-Error "Could not extract a 4-part version from the CDN location: $location"
    Exit 1
}
$version = [Version]$versionStr
Write-Host "      detected: $version"
$versionObj = @{ version = $versionStr }
$versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Force
