#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

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
    04.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-AzureExternalSharingSettings-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureAdPreview"
    
# Logins
LoginTo-Ad

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-AzureExternalSharingSettings | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Configuring B2B domain policy
Write-Host "Configuring B2B domain policy" -ForegroundColor $CommandInfo
$Policy = Get-AzureADPolicy | where { $_.DisplayName -eq "B2BManagementPolicy" }
if (-Not $Policy)
{
    Write-Warning "B2B domain policy not found. Creating the B2B domain policy B2BManagementPolicy"
    $policyValue = @("{`"B2BManagementPolicy`":{`"InvitationsAllowedAndBlockedDomainsPolicy`":{`"AllowedDomains`": [],`"BlockedDomains`": []}}}")
    New-AzureADPolicy -Definition $policyValue -DisplayName "B2BManagementPolicy" -Type "B2BManagementPolicy" -IsOrganizationDefault $true
}
else
{
    $PolicyDef = $Policy.Definition
    #TODO AllowedDomains BlockedDomains
    Set-AzureADPolicy -Definition $PolicyDef -Id $Policy.Id 
}

# Configuring B2B settings
Write-Host "Configuring B2B settings" -ForegroundColor $CommandInfo
$apiToken = Get-AzAccessToken
$header = @{'Authorization'='Bearer '+$apiToken;'X-Requested-With'='XMLHttpRequest';'x-ms-client-request-id'=[guid]::NewGuid();'x-ms-correlation-id'=[guid]::NewGuid();}
$url = "https://main.iam.ad.ext.azure.com/api/Directories/B2BDirectoryProperties"
$ActualConfiguration = Invoke-RestMethod -Uri $url -Headers $header -Method GET -ErrorAction Stop

Write-Host "Actual settings"
$ActualConfiguration

$settings = @{
  restrictDirectoryAccess = $false
  allowInvitations = $true
  usersCanAddExternalUsers = $true
  limitedAccessCanAddExternalUsers = $false
}
if ($AlyaSharingPolicy -eq "AdminOnly")
{
    #TODO Check these settings
    $settings.allowInvitations = $false
    $settings.usersCanAddExternalUsers = $false
}
$body = $settings | ConvertTo-Json
$apiToken = Get-AzAccessToken
$header = @{'Authorization'='Bearer '+$apiToken;'X-Requested-With'='XMLHttpRequest';'x-ms-client-request-id'=[guid]::NewGuid();'x-ms-correlation-id'=[guid]::NewGuid();}
$tmp = Invoke-RestMethod -Uri $url -Headers $header -Method PUT -Body $body -ContentType "application/json; charset=UTF-8" -ErrorAction Stop

$ActualConfiguration = Invoke-RestMethod -Uri $url -Headers $header -Method GET -ErrorAction Stop
Write-Host "New settings"
$ActualConfiguration

#Stopping Transscript
Stop-Transcript
