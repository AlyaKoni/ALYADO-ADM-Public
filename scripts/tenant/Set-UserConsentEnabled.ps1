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
    04.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-UserConsentEnabled-$($AlyaTimeString).log" | Out-Null

# Constants

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "MSOnline"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MSOL

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-UserConsentEnabled | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$MsolCompanySettings = Get-MsolCompanyInformation
if (-Not $MsolCompanySettings.UsersPermissionToUserConsentToAppEnabled)
{
    Write-Warning "UsersPermissionToUserConsentToApp was disabled. Enabling it."
    Set-MsolCompanySettings -UsersPermissionToUserConsentToAppEnabled $true
}
else
{
    Write-Host "UsersPermissionToUserConsentToApp was already enabled." -ForegroundColor $CommandSuccess
}

<#
$policy = Get-MgPolicyAuthorizationPolicy -All | where { $_.Id -eq "authorizationPolicy" }
if ($policy.AllowUserConsentForRiskyApps)
{
    Write-Warning "App consent for users was disabled. Enabling it now"
    $RolePermissions = @{}
    $RolePermissions["allowedToReadOtherUsers"] = $true
    Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId "authorizationPolicy" -DefaultUserRolePermissions @{
        "PermissionGrantPoliciesAssigned" = @("managePermissionGrantsForSelf.microsoft-user-default-low") }
}
Get-MgPolicyAuthorizationPolicy -All | where { $_.Id -eq "authorizationPolicy" } | ConvertTo-Json -Depth 5
#>
<#
$policies = Get-MgPolicyPermissionGrantPolicy -All
$policy = $policies | where { $_.DisplayName -eq "Default User Low Risk Policy" }
$policy = $policies | where { $_.DisplayName -eq "Application Admin Policy" }
$policy = $policies | where { $_.DisplayName -eq "Default User Legacy Policy" }
if ($policy.DefaultUserRolePermissions.AllowedToReadOtherUsers)
{
    Write-Warning "App consent for users was disabled. Enabling it now"
    $RolePermissions = @{}
    $RolePermissions["allowedToReadOtherUsers"] = $true
    Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId "authorizationPolicy" -DefaultUserRolePermissions $RolePermissions
}
$policy | ConvertTo-Json -Depth 5
#>

#Stopping Transscript
Stop-Transcript
