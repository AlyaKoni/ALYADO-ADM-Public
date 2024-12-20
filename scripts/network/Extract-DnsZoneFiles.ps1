﻿#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2024

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


    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    07.11.2024 Konrad Brunner       Initial version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\network\Extract-DnsZoneFiles-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainNetwork)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Dns"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "DNS | Extract-DnsZoneFiles | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Getting DNS zones
Write-Host "Getting DNS zones" -ForegroundColor $CommandInfo
$dnsZones = Get-AzDnsZone -ErrorAction SilentlyContinue
if (-Not $dnsZones -or $dnsZones.Count -eq 0)
{
    Write-Warning "No DNS zones found to export"
}

# Getting private DNS zones
Write-Host "Getting private DNS zones" -ForegroundColor $CommandInfo
$dnsZonesPrivate = Get-AzPrivateDnsZone -ErrorAction SilentlyContinue
if (-Not $dnsZonesPrivate -or $dnsZonesPrivate.Count -eq 0)
{
    Write-Warning "No private DNS zones found to export"
}

# Exporting all DNS zones
Write-Host "Exporting all DNS zones" -ForegroundColor $CommandInfo

$dnsExportRoot = "$($AlyaData)\network\dnsExports"
Write-Host "  to $($dnsExportRoot)" -ForegroundColor $CommandInfo
if (-Not (Test-Path -Path $dnsExportRoot -PathType Container))
{
    New-Item -Path $dnsExportRoot -ItemType Directory -Force | Out-Null
}
Push-Location -Path $dnsExportRoot

foreach($zone in $dnsZones)
{
    Write-Host "Exporting $($zone.Name)"
    try {
        if($AlyaIsPsCore)
        {
            Get-AzDnsRecordSet -ZoneName $zone.Name -ResourceGroupName $zone.ResourceGroupName | ConvertTo-Json -Depth 99 -EnumsAsStrings | Set-Content -Path "$($zone.Name)" -Encoding $AlyaUtf8Encoding -Force
        }
        else
        {
            Get-AzDnsRecordSet -ZoneName $zone.Name -ResourceGroupName $zone.ResourceGroupName | ConvertTo-Json -Depth 99 | Set-Content -Path "$($zone.Name)" -Encoding $AlyaUtf8Encoding -Force
        }
    }
    catch {
        Write-Error $_ -ErrorAction Continue
    }
}

foreach($zone in $dnsZonesPrivate)
{
    Write-Host "Exporting $($zone.Name)"
    try {
        if($AlyaIsPsCore)
        {
            Get-AzPrivateDnsRecordSet -ZoneName $zone.Name -ResourceGroupName $zone.ResourceGroupName | ConvertTo-Json -Depth 99 -EnumsAsStrings | Set-Content -Path "$($zone.Name)" -Encoding $AlyaUtf8Encoding -Force
        }
        else
        {
            Get-AzPrivateDnsRecordSet -ZoneName $zone.Name -ResourceGroupName $zone.ResourceGroupName | ConvertTo-Json -Depth 99 | Set-Content -Path "$($zone.Name)" -Encoding $AlyaUtf8Encoding -Force
        }
    }
    catch {
        Write-Error $_ -ErrorAction Continue
    }
}

#Stopping Transscript
Stop-Transcript
