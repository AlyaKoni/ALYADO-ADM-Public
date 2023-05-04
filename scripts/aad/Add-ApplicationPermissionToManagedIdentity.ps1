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
    23.09.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$ServicePrincipalNameRequestingPermission = $null,
    [string]$ServicePrincipalIdRequestingPermission = $null,
    [string]$ServicePrincipalNameProvidingPermission = $null,
    [string]$ServicePrincipalIdProvidingPermission = $null,
    [string]$PermissionToAssign = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Add-ApplicationPermissionToManagedIdentity-$($AlyaTimeString).log" | Out-Null

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
Write-Host "ENTAPPS | Add-ApplicationPermissionToManagedIdentity | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Getting ServicePrincipal Requesting" -ForegroundColor $CommandInfo
$App = $null
if ($ServicePrincipalNameRequestingPermission)
{
    $App = Get-AzureADServicePrincipal -Filter "DisplayName eq '$($ServicePrincipalNameRequestingPermission)'"
    if (-Not $App)
    {
        throw "ServicePrincipal with name '$($ServicePrincipalNameRequestingPermission)' not found"
    }
}
if ($ServicePrincipalIdRequestingPermission)
{
    $App = Get-AzureADServicePrincipal -Filter "AppId eq '$($ServicePrincipalIdRequestingPermission)'"
    if (-Not $App)
    {
        throw "ServicePrincipal with id '$($ServicePrincipalIdRequestingPermission)' not found"
    }
}
if (-not $App)
{
    throw "Please provide ServicePrincipalNameRequestingPermission or ServicePrincipalIdRequestingPermission"
}

Write-Host "Getting ServicePrincipal Providing" -ForegroundColor $CommandInfo
$ToApp = $null
if ($ServicePrincipalNameProvidingPermission)
{
    $ToApp = Get-AzureADServicePrincipal -Filter "DisplayName eq '$($ServicePrincipalNameProvidingPermission)'"
    if (-Not $ToApp)
    {
        throw "ServicePrincipal with name '$($ServicePrincipalNameProvidingPermission)' not found"
    }
}
if ($ServicePrincipalIdProvidingPermission)
{
    $ToApp = Get-AzureADServicePrincipal -Filter "AppId eq '$($ServicePrincipalIdProvidingPermission)'"
    if (-Not $ToApp)
    {
        throw "ServicePrincipal with id '$($ServicePrincipalIdProvidingPermission)' not found"
    }
}
if (-not $ToApp)
{
    throw "Please provide ServicePrincipalNameProvidingPermission or ServicePrincipalIdProvidingPermission"
}

Write-Host "Getting Role" -ForegroundColor $CommandInfo
$AppRole = $ToApp.AppRoles | Where-Object {$_.Value -eq $PermissionToAssign -and $_.AllowedMemberTypes -contains "Application"}
if (-not $AppRole)
{
    throw "App role $PermissionToAssign not found on $($ToApp.DisplayName) with id $($ToApp.AppId)"
}

Write-Host "Checking assignment" -ForegroundColor $CommandInfo
$Assignments = Get-AzureADServiceAppRoleAssignedTo -ObjectId $App.ObjectId -All $true
$Assignment = $Assignments | Where-Object { $_.Id -eq $AppRole.Id -and $_.PrincipalId -eq $App.ObjectId -and $_.ResourceId -eq $ToApp.ObjectId  }
if (-not $Assignment)
{
    Write-Warning "Assignment not found. Creating it now"
    New-AzureAdServiceAppRoleAssignment -ObjectId $App.ObjectId -PrincipalId $App.ObjectId -ResourceId $ToApp.ObjectId -Id $AppRole.Id
}
else
{
    Write-Host "Assignment already exists"
}

#Stopping Transscript
Stop-Transcript
