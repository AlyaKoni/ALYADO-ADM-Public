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
    [string]$roleName,
    [int]$durationInMinutes = 120
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Activate-MyEligableRole-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Enrolment"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Directory.Read.All","RoleEligibilitySchedule.Read.Directory","RoleAssignmentSchedule.ReadWrite.Directory")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Activate-MyEligableRole | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Write warning
Write-Host "WARNING:" -ForegroundColor $CommandWarning
Write-Host "If you are not able to activate your role," -ForegroundColor $CommandWarning
Write-Host "you need to run this script once with already activated Global Administrator" -ForegroundColor $CommandWarning
Write-Host "to get required consents." -ForegroundColor $CommandWarning

# Getting user
Write-Host "Getting user" -ForegroundColor $CommandInfo
$actUser = (Get-MgContext).Account
$user = Get-MgUser -UserId $actUser
if (-Not $user)
{
    throw "User $userPrincipalName not found!"
}

# Getting all built in roles
Write-Host "Getting all built in roles" -ForegroundColor $CommandInfo
$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All

# Getting  eligable role assignment
Write-Host "Getting eligable role assignment" -ForegroundColor $CommandInfo
$assignedRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($user.Id)'"
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

# Activating  eligable role assignment
Write-Host "Activating eligable role assignment" -ForegroundColor $CommandInfo
$from = Get-Date
$to = $from.AddMinutes($durationInMinutes)
$params = @{
	Action = "SelfActivate"
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
New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params

#Stopping Transscript
Stop-Transcript
