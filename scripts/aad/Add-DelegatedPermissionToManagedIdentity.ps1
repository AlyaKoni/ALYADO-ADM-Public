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
    23.09.2022 Konrad Brunner       Initial Version
    31.05.2023 Konrad Brunner       Switched to MsGraph

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
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Add-DelegatedPermissionToManagedIdentity-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Applications"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Directory.Read.All","DelegatedPermissionGrant.ReadWrite.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "ENTAPPS | Add-DelegatedPermissionToManagedIdentity | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Getting ServicePrincipal Requesting" -ForegroundColor $CommandInfo
$App = $null
if ($ServicePrincipalNameRequestingPermission)
{
    $App = Get-MgBetaServicePrincipal -Filter "DisplayName eq '$($ServicePrincipalNameRequestingPermission)'"
    if (-Not $App)
    {
        throw "ServicePrincipal with name '$($ServicePrincipalNameRequestingPermission)' not found"
    }
}
if ($ServicePrincipalIdRequestingPermission)
{
    $App = Get-MgBetaServicePrincipal -Filter "AppId eq '$($ServicePrincipalIdRequestingPermission)'"
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
    $ToApp = Get-MgBetaServicePrincipal -Filter "DisplayName eq '$($ServicePrincipalNameProvidingPermission)'" -Property "*"
    if (-Not $ToApp)
    {
        throw "ServicePrincipal with name '$($ServicePrincipalNameProvidingPermission)' not found"
    }
}
if ($ServicePrincipalIdProvidingPermission)
{
    $ToApp = Get-MgBetaServicePrincipal -Filter "AppId eq '$($ServicePrincipalIdProvidingPermission)'" -Property "*"
    if (-Not $ToApp)
    {
        throw "ServicePrincipal with id '$($ServicePrincipalIdProvidingPermission)' not found"
    }
}
if (-not $ToApp)
{
    throw "Please provide ServicePrincipalNameProvidingPermission or ServicePrincipalIdProvidingPermission"
}

Write-Host "Getting delegated permission" -ForegroundColor $CommandInfo
$DelPerm = $ToApp.PublishedPermissionScopes | Where-Object {$_.Value -eq $PermissionToAssign -and $_.Type -eq "User"}
if (-not $DelPerm)
{
    throw "App role $PermissionToAssign not found on $($ToApp.DisplayName) with id $($ToApp.AppId)"
}

Write-Host "Checking assignment" -ForegroundColor $CommandInfo
$Assignments = Get-MgBetaServicePrincipalOauth2PermissionGrant -ServicePrincipalId $App.Id -All
if ($null -eq ($Assignments | Where-Object { $_.ConsentType -eq "AllPrincipals" -and $_.ClientId -eq $App.Id -and $_.ResourceId -eq $ToApp.Id -and $_.Scope -like "*$PermissionToAssign*" }))
{
    $params = @{
        ClientId = $App.Id
        ConsentType = "AllPrincipals"
        ResourceId = $ToApp.Id
        Scope = $PermissionToAssign
        StartTime = [DateTime]::MinValue
        ExpiryTime = [DateTime]::MaxValue
    }
    New-MgBetaOauth2PermissionGrant -BodyParameter $params
}
else
{
    Write-Host "Assignment already exists"
}

#Stopping Transscript
Stop-Transcript
