#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    07.04.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aip\Configure-AIPService-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "AIPService"
    
# Logins
LoginTo-AIP

# =============================================================
# AADRM stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AIP | Configure-AIPService | AIP" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Checking AipService" -ForegroundColor $CommandInfo
$enabled = Get-AipService
if ($enabled -ne "Enabled")
{
    Write-Host "Enabling AipService"
    $tmp = Configure-AIPService
}
else
{
    Write-Host "AipService was already enabled"
}

Write-Host "Checking AipServiceIPCv3" -ForegroundColor $CommandInfo
$enabled = Get-AipServiceIPCv3
if ($enabled -ne "Enabled")
{
    Write-Host "Enabling AipServiceIPCv3"
    $tmp = Configure-AIPServiceIPCv3
}
else
{
    Write-Host "AipServiceIPCv3 was already enabled"
}

Write-Host "Checking AipServiceDevicePlatform" -ForegroundColor $CommandInfo
$enabled = Get-AipServiceDevicePlatform -All
$enabled = $enabled | where { $_.Value -eq $false }
if ($enabled)
{
    Write-Host "Enabling AipServiceDevicePlatform All"
    $tmp = Enable-AIPServiceDevicePlatform -All
}
else
{
    Write-Host "AipServiceDevicePlatform All was already enabled"
}

Write-Host "Checking AipServiceDocumentTrackingFeature" -ForegroundColor $CommandInfo
$enabled = Get-AipServiceDocumentTrackingFeature
if ($enabled -ne "Enabled")
{
    Write-Host "Enabling AipServiceDocumentTrackingFeature"
    $tmp = Enable-AIPServiceDocumentTrackingFeature -Force
}
else
{
    Write-Host "AipServiceDocumentTrackingFeature was already enabled"
}

$aipConfiguration = Get-AipServiceConfiguration
$aipConfiguration | fl

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AIP | Configure-AIPService | Exchange Online" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

LoginTo-EXO
$actConfiguration = Get-IRMConfiguration

if (-Not $actConfiguration.SimplifiedClientAccessEnabled)
{
    Write-Warning "SimplifiedClientAccessEnabled was disbled. Enabling it now."
    Set-IRMConfiguration -SimplifiedClientAccessEnabled $true
}
if (-Not $actConfiguration.LicensingLocation)
{
    Write-Warning "LicensingLocation was not configured. Configuring it now."
    Set-IRMConfiguration -LicensingLocation $aipConfiguration.LicensingIntranetDistributionPointUrl
}
else
{
    if ($actConfiguration.LicensingLocation -ne $aipConfiguration.LicensingIntranetDistributionPointUrl)
    {
        throw "LicensingLocation wrong configured. Please check."
    }
}
if (-Not $actConfiguration.InternalLicensingEnabled)
{
    Write-Warning "InternalLicensingEnabled was disbled. Enabling it now."
    if (-Not $actConfiguration.RMSOnlineKeySharingLocation)
    {
        Set-IRMConfiguration -RMSOnlineKeySharingLocation "https://sp-rms.eu.aadrm.com/TenantManagement/ServicePartner.svc"
    }
    Import-RMSTrustedPublishingDomain -RMSOnline -Name "RMS Online"
    Set-IRMConfiguration -InternalLicensingEnabled $true
}
if (-Not $actConfiguration.ExternalLicensingEnabled)
{
    Write-Warning "ExternalLicensingEnabled was disbled. Enabling it now."
    Set-IRMConfiguration -ExternalLicensingEnabled $true
}
if (-Not $actConfiguration.AzureRMSLicensingEnabled)
{
    Write-Warning "AzureRMSLicensingEnabled was disbled. Enabling it now."
    Set-IRMConfiguration -AzureRMSLicensingEnabled $true
}
if (-Not $actConfiguration.AutomaticServiceUpdateEnabled)
{
    Write-Warning "AutomaticServiceUpdateEnabled was disbled. Enabling it now."
    Set-IRMConfiguration -AutomaticServiceUpdateEnabled $true
}
#Test-IRMConfiguration -Sender first.last@domain.ch

Get-IRMConfiguration | fl
DisconnectFrom-EXOandIPPS

#Stopping Transscript
Stop-Transcript