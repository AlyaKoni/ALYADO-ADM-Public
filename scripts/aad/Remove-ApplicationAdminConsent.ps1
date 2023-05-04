#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2022

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
    03.11.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$ServicePrincipalName = "Microsoft Graph PowerShell",
    [string]$ServicePrincipalId = $null,
    [string]$UserUpn = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Remove-ApplicationAdminConsent-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "AzureADPreview"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-AD

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "ENTAPPS | Remove-ApplicationAdminConsent | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Getting ServicePrincipal" -ForegroundColor $CommandInfo
$App = $null
if ($ServicePrincipalName)
{
    $App = Get-AzureADServicePrincipal -Filter "DisplayName eq '$($ServicePrincipalName)'"
    if (-Not $App)
    {
        throw "ServicePrincipal with name '$($ServicePrincipalName)' not found"
    }
}
if ($ServicePrincipalId)
{
    $App = Get-AzureADServicePrincipal -Filter "AppId eq '$($ServicePrincipalId)'"
    if (-Not $App)
    {
        throw "ServicePrincipal with id '$($ServicePrincipalId)' not found"
    }
}
if (-not $App)
{
    throw "Please provide ServicePrincipalName or ServicePrincipalId"
}

Write-Host "Getting User" -ForegroundColor $CommandInfo
$User = $null
if ($UserUpn)
{
    $User = Get-AzureADUser -ObjectId $UserUpn
    if (-Not $User)
    {
        throw "User with name '$($UserUpn)' not found"
    }
}

Write-Host "Getting Grants" -ForegroundColor $CommandInfo
$grants = Get-AzureADOAuth2PermissionGrant -All $true | Where-Object { $_.clientId -eq $App.ObjectId -and $_.PrincipalId -eq $User.ObjectId }
$grants | Format-List

Write-Host "Deleting Grants" -ForegroundColor $CommandInfo
$grants | Remove-AzureADOAuth2PermissionGrant

#Stopping Transscript
Stop-Transcript
