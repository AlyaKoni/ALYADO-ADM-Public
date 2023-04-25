#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2023

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
$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All

# Getting  permanent role members
Write-Host "Getting  permanent role members" -ForegroundColor $CommandInfo
$assignedRoles = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal
foreach ($roleDefinition in $roleDefinitions)
{
    $actMembs = $assignedRoles | where { $_.RoleDefinitionId -eq $roleDefinition.Id }
    if ($actMembs -and $actMembs.Count -gt 0)
    {
        Write-Host "Role: $($roleDefinition.DisplayName)"
        foreach ($actMemb in $actMembs)
        {
            $memberName = $actMemb.PrincipalId
            switch ($actMemb.Principal.AdditionalProperties.'@odata.type')
            {
                "#microsoft.graph.user" {
                    $memberName = "USR:"+$actMemb.Principal.AdditionalProperties.userPrincipalName
                }
                "#microsoft.graph.servicePrincipal" {
                    $memberName = "APP:"+$actMemb.Principal.AdditionalProperties.appId
                }
                "#microsoft.graph.group" {
                    $memberName = "GRP:"+$memberName
                }
            }
            Write-Host "  Member: $memberName"
        }
    }
}

if ($configurePIM)
{

    # Getting  eligable role members
    Write-Host "Getting eligable role members" -ForegroundColor $CommandInfo
    $assignedRoles = @()
    try {
        $assignedRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty Principal
    }
    catch {}
    foreach ($roleDefinition in $roleDefinitions)
    {
        $actMembs = $assignedRoles | where { $_.RoleDefinitionId -eq $roleDefinition.Id }
        if ($actMembs -and $actMembs.Count -gt 0)
        {
            Write-Host "Role: $($roleDefinition.DisplayName)"
            foreach ($actMemb in $actMembs)
            {
                $memberName = $actMemb.PrincipalId
                switch ($actMemb.Principal.AdditionalProperties.'@odata.type')
                {
                    "#microsoft.graph.user" {
                        $memberName = "USR:"+$actMemb.Principal.AdditionalProperties.userPrincipalName
                    }
                    "#microsoft.graph.servicePrincipal" {
                        $memberName = "APP:"+$actMemb.Principal.AdditionalProperties.appId
                    }
                    "#microsoft.graph.group" {
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
