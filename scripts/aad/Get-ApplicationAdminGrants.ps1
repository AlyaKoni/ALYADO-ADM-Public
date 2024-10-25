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
    20.09.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$ServicePrincipalName = "PnP Management Shell",
    [string]$ServicePrincipalId = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Get-ApplicationAdminGrants-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Applications"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Directory.Read.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "ENTAPPS | Get-ApplicationAdminGrants | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Getting ServicePrincipal" -ForegroundColor $CommandInfo
$App = $null
if ($ServicePrincipalName)
{
    $App = Get-MgBetaServicePrincipal -Filter "DisplayName eq '$($ServicePrincipalName)'"
    if (-Not $App)
    {
        throw "ServicePrincipal with name '$($ServicePrincipalName)' not found"
    }
}
if ($ServicePrincipalId)
{
    $App = Get-MgBetaServicePrincipal -Filter "AppId eq '$($ServicePrincipalId)'"
    if (-Not $App)
    {
        throw "ServicePrincipal with id '$($ServicePrincipalId)' not found"
    }
}
if (-not $App)
{
    throw "Please provide ServicePrincipalName or ServicePrincipalId"
}

Write-Host "Getting Grants" -ForegroundColor $CommandInfo
$grants = Get-MgBetaServicePrincipalOauth2PermissionGrant -ServicePrincipalId $App.Id -All | Where-Object { $_.ConsentType -eq "AllPrincipals" }

foreach($grant in $grants)
{
    #$grant = $grants[0]
    $gApp = Get-MgBetaServicePrincipal -ServicePrincipalId $grant.ResourceId
    if ($gApp)
    {
        Write-Host "App: $($gApp.DisplayName) AppID: $($gApp.AppId)"
        $scopes = $grant.Scope.Split()
        foreach($scope in $scopes)
        {
            $scps = @($scope)
            if ($scope -eq "AllSites.FullControl") { $scps += "Sites.FullControl.All" }
            $appRole = $gApp.AppRoles | Where-Object {$_.Value -in $scps -and $_.AllowedMemberTypes -contains "Application"}
            if ($appRole)
            {
                Write-Host "  Scope: $scope ID: $($appRole.Id)"
            }
            else
            {
                Write-Warning "AppRole '$scope' not found on application"
            }
        }
    }
    else
    {
        Write-Warning "ServicePrincipal with id '$($grant.ResourceId)' not found"
    }
    ""
}

#Stopping Transscript
Stop-Transcript
