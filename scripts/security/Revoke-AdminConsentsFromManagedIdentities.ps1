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
    10.04.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string[]]$revokeAdminConsentFromApps = @() # "Microsoft Graph PowerShell","Graph Explorer","PnP Management Shell","Microsoft Intune PowerShell","MSFT Power Platform - Azure AD"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Revoke-AdminConsentsFromManagedIdentities-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Applications"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Directory.Read.All","AppRoleAssignment.ReadWrite.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "ENTAPPS | Revoke-AdminConsentsFromManagedIdentities | GRAPH" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Checking assignments" -ForegroundColor $CommandInfo
$assignedRoles = @()
foreach($revokeAdminConsentFromApp in $revokeAdminConsentFromApps)
{
    Write-Host "App: $revokeAdminConsentFromApp" -ForegroundColor $CommandInfo
    $App = Get-MgBetaServicePrincipal -Filter "DisplayName eq '$($revokeAdminConsentFromApp)'"
    if (-Not $App)
    {
        Write-Warning "Not found!"
        continue
    }
    $Assignments = Get-MgBetaServicePrincipalOauth2PermissionGrant -ServicePrincipalId $App.Id -All
    foreach($Assignment in $Assignments)
    {
        if ($Assignment.ConsentType -ne "AllPrincipals") { continue }
        $ToApp = Get-MgBetaServicePrincipal -ServicePrincipalId $Assignment.ResourceId
        $scopes = $Assignment.Scope.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
        foreach($scope in $scopes)
        {
            $AppRole = $ToApp.PublishedPermissionScopes | Where-Object { $_.Value -eq $scope }
            $assignedRoles += @{
                Type = $Assignment.ConsentType
                App = $App.DisplayName
                ToApp = $ToApp.DisplayName
                Role = $scope
            }
        }
        Remove-MgBetaOauth2PermissionGrant -OAuth2PermissionGrantId $Assignment.Id
    }
}

Write-Host "Removed assignments" -ForegroundColor $CommandInfo
$assignedRoles.GetEnumerator() | Select-Object -Property Type, App, ToApp, Role | Format-Table

#Stopping Transscript
Stop-Transcript
