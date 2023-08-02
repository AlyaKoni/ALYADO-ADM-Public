#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2023

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
    12.07.2020 Konrad Brunner       Initial Version
    21.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
    [bool]$configurePIM = $true
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Get-AssignedRoles-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Enrolment"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Applications"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "Directory.Read.All"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Get-AssignedRoles | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting all built in roles
Write-Host "Getting all built in roles" -ForegroundColor $CommandInfo
$roleDefinitions = Get-MgBetaRoleManagementDirectoryRoleDefinition -All

# Getting  permanent role members
Write-Host "Getting  permanent role members" -ForegroundColor $CommandInfo
$assignedRoles = Get-MgBetaRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal
foreach ($roleDefinition in $roleDefinitions)
{
    $actMembs = $assignedRoles | Where-Object { $_.RoleDefinitionId -eq $roleDefinition.Id }
    if ($actMembs -and $actMembs.Count -gt 0)
    {
        Write-Host "Role: $($roleDefinition.DisplayName)"
        foreach ($actMemb in $actMembs)
        {
            $memberName = $actMemb.PrincipalId
            switch ($actMemb.Principal.AdditionalProperties.'@odata.type')
            {
                "#Microsoft.Graph.user" {
                    $memberName = "USR:"+$actMemb.Principal.AdditionalProperties.userPrincipalName
                }
                "#Microsoft.Graph.servicePrincipal" {
                    $app = Get-MgBetaServicePrincipal -Filter "AppId eq '$($actMemb.Principal.AdditionalProperties.appId)'"
                    $memberName = "APP:"+$app.Id+":"+$app.DisplayName
                }
                "#Microsoft.Graph.group" {
                    $grp = Get-MgBetaGroup -GroupId $memberName
                    $memberName = "GRP:"+$grp.Id+":"+$grp.DisplayName
                }
                default {
                    $memberName = "???:"+$memberName
                }
            }
            Write-Host "  $memberName"
        }
    }
}

if ($configurePIM)
{

    # Getting  eligable role members
    Write-Host "Getting eligable role members" -ForegroundColor $CommandInfo
    $assignedRoles = @()
    try {
        $assignedRoles = Get-MgBetaRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty Principal
    }
    catch {}
    foreach ($roleDefinition in $roleDefinitions)
    {
        $actMembs = $assignedRoles | Where-Object { $_.RoleDefinitionId -eq $roleDefinition.Id }
        if ($actMembs -and $actMembs.Count -gt 0)
        {
            Write-Host "Role: $($roleDefinition.DisplayName)"
            foreach ($actMemb in $actMembs)
            {
                $memberName = $actMemb.PrincipalId
                switch ($actMemb.Principal.AdditionalProperties.'@odata.type')
                {
                    "#Microsoft.Graph.Beta.user" {
                        $memberName = "USR:"+$actMemb.Principal.AdditionalProperties.userPrincipalName
                    }
                    "#Microsoft.Graph.Beta.servicePrincipal" {
                        $memberName = "APP:"+$actMemb.Principal.AdditionalProperties.appId
                    }
                    "#Microsoft.Graph.Beta.group" {
                        $memberName = "GRP:"+$memberName
                    }
                }
                Write-Host "  Member: $memberName"
            }
        }
    }

}

#Stopping Transscript
Stop-Transcript
