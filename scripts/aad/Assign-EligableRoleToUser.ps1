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
    15.05.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$userPrincipalName,
    [Parameter(Mandatory = $true)]
    [string]$roleName,
    [int]$durationInMinutes = 120
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Assign-EligableRoleToUser-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.DeviceManagement.Enrolment"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Directory.ReadWrite.All","RoleAssignmentSchedule.ReadWrite.Directory")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Assign-EligableRoleToUser | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking  license
Write-Host "Checking  license" -ForegroundColor $CommandInfo
try
{
    $actMembs = Get-MgBetaRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty Principal
}
catch
{
    if ($_.Exception.ToString() -like "*AadPremiumLicenseRequired*" -or $_.Exception.ToString() -like "*AAD Premium 2*")
    {
        throw "No P2 license available! Can't configure PIM roles."
    }
    else
    {
        throw $_.Exception
    }
}

# Getting user
Write-Host "Getting user" -ForegroundColor $CommandInfo
$user = Get-MgBetaUser -UserId $userPrincipalName
if (-Not $user)
{
    throw "User $userPrincipalName not found!"
}

# Getting all built in roles
Write-Host "Getting all built in roles" -ForegroundColor $CommandInfo
$roleDefinitions = Get-MgBetaRoleManagementDirectoryRoleDefinition -All

# Getting  eligable role assignments
Write-Host "Getting eligable role assignments" -ForegroundColor $CommandInfo
$assignedRoles = Get-MgBetaRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($user.Id)'"
$role = $roleDefinitions | Where-Object { $_.DisplayName -eq $roleName }
if (-Not $role)
{
    throw "Role '$roleName' not found"
}
$assigned = $assignedRoles | Where-Object { $_.RoleDefinitionId -eq $role.Id }
if (-Not $role)
{
    throw "User $userPrincipalName does not have role '$roleName' eligable assigned"
}

# Activating  eligable role assignments
Write-Host "Activating eligable role assignments" -ForegroundColor $CommandInfo
$from = Get-Date
$to = $from.AddMinutes($durationInMinutes)
$params = @{
	Action = "adminAssign"
	Justification = "Assignment from Alya PowerShell script"
	RoleDefinitionId = "$($assigned.RoleDefinitionId)"
	DirectoryScopeId = "/"
	PrincipalId = "$($user.Id)"
	ScheduleInfo = @{
		StartDateTime = $from
		Expiration = @{
			Type = "afterDateTime"
			EndDateTime = $to
		}
	}
}
New-MgBetaRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params

#Stopping Transscript
Stop-Transcript
