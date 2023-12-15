#Requires -Version 2.0

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
    04.03.2020 Konrad Brunner       Initial Version
    27.11.2023 Konrad Brunner       Removed AzureAdPreview module

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
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
    
# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-AzureExternalSharingSettings | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Configuring B2B domain policy
Write-Host "Configuring B2B domain policy" -ForegroundColor $CommandInfo
$policyReq = Invoke-AzRestMethod -Uri "https://graph.microsoft.com/beta/legacy/policies"
$policies = ($policyReq.Content | ConvertFrom-Json).value
$b2bPolicy = $policies | Where-Object { $_.displayName -eq "B2BManagementPolicy" }
if (-Not $b2bPolicy)
{
    $policyDef = @{
        displayName = "B2BManagementPolicy"
        type = "B2BManagementPolicy"
        definition = "{`"B2BManagementPolicy`":{`"InvitationsAllowedAndBlockedDomainsPolicy`":{`"BlockedDomains`":[]},`"AutoRedeemPolicy`":{`"AdminConsentedForUsersIntoTenantIds`":[],`"NoAADConsentForUsersFromTenantsIds`":[]}}}"
    }
    $policyReq = Invoke-AzRestMethod -Method Post -Uri "https://graph.microsoft.com/beta/legacy/policies" -Payload $policyDef
}

# Configuring B2B settings
Write-Host "Configuring B2B settings" -ForegroundColor $CommandInfo
$apiToken = Get-AzAccessToken
$header = @{'Authorization'='Bearer '+$apiToken;'X-Requested-With'='XMLHttpRequest';'x-ms-client-request-id'=[guid]::NewGuid();'x-ms-correlation-id'=[guid]::NewGuid();}
$url = "https://main.iam.ad.ext.azure.com/api/Directories/B2BDirectoryProperties"
$ActualConfiguration = Invoke-RestMethod -Uri $url -Headers $header -Method GET -ErrorAction Stop

Write-Host "Actual settings"
Write-Host ($ActualConfiguration | Format-List | Out-String)

$settings = @{
  restrictDirectoryAccess = $true
  allowInvitations = $true
  usersCanAddExternalUsers = $true
  limitedAccessCanAddExternalUsers = $false
  allowExternalIdentitiesToLeave = $true
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
$null = Invoke-RestMethod -Uri $url -Headers $header -Method PUT -Body $body -ContentType "application/json; charset=UTF-8" -ErrorAction Stop

$ActualConfiguration = Invoke-RestMethod -Uri $url -Headers $header -Method GET -ErrorAction Stop
Write-Host "New settings"
Write-Host ($ActualConfiguration | Format-List | Out-String)

#Stopping Transscript
Stop-Transcript
