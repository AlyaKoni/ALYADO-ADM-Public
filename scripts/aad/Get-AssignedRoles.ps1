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
    12.07.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Get-AssignedRoles-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "AzureADPreview"
Install-ModuleIfNotInstalled "MSOnline"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad
LoginTo-Msol

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Get-AssignedRoles | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting all built in roles
Write-Host "Getting all built in roles" -ForegroundColor $CommandInfo
$allBuiltInPIMRoles = Get-AzureADMSRoleDefinition
$allBuiltinMsolRoles = Get-MsolRole

# Getting msol role members
Write-Host "Getting msol role members" -ForegroundColor $CommandInfo
foreach ($role in $allBuiltinMsolRoles)
{
    $actMembs = Get-MsolRoleMember -RoleObjectId $role.ObjectId
    if ($actMembs -and $actMembs.Count -gt 0)
    {
        Write-Host "Role: $($role.Name)"
        foreach ($actMemb in $actMembs)
        {
            $user = Get-AzureADUser -ObjectId $actMemb.ObjectId
            Write-Host "  Member: $($user.UserPrincipalName)"
        }
    }
}

# Getting pim permanent role members
Write-Host "Getting pim permanent role members" -ForegroundColor $CommandInfo
foreach ($role in $allBuiltInPIMRoles)
{
    try
    {
        $actMembs = Get-AzureADMSRoleAssignment -Filter "RoleDefinitionId eq '$($role.Id)'"
        if ($actMembs -and $actMembs.Count -gt 0)
        {
            Write-Host "Role: $($role.DisplayName)"
            foreach ($actMemb in $actMembs)
            {
                $user = Get-AzureADUser -ObjectId $actMemb.PrincipalId
                Write-Host "  Member: $($user.UserPrincipalName)"
            }
        }
    } catch {}
}

# Getting pim eligable role members
Write-Host "Getting pim eligable role members" -ForegroundColor $CommandInfo
foreach ($role in $allBuiltInPIMRoles)
{
    try
    {
        $role = Get-AzureADMSPrivilegedRoleDefinition -ProviderId "aadRoles" -ResourceId $AlyaTenantId -Filter "DisplayName eq '$($role.DisplayName)'"
    }
    catch
    {
        break
    }
    $actMembs = Get-AzureADMSPrivilegedRoleAssignment -ProviderId "aadRoles" -ResourceId $AlyaTenantId -Filter "RoleDefinitionId eq '$($role.Id)' and AssignmentState eq 'Eligible'"
    if ($actMembs -and $actMembs.Count -gt 0)
    {
        Write-Host "Role: $($role.DisplayName)"
        foreach ($actMemb in $actMembs)
        {
            $user = Get-AzureADUser -ObjectId $actMemb.PrincipalId
            Write-Host "  Member: $($user.UserPrincipalName)"
        }
    }
}

#Stopping Transscript
Stop-Transcript
