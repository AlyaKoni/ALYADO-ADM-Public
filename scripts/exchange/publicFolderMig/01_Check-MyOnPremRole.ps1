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
    24.10.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

. $PSScriptRoot\00_Configuration.ps1

$allRoles = Get-ManagementRoleAssignment -GetEffectiveUsers | Where-Object {$_.EffectiveUserName -eq $migAdminUserName } | select-object Role -Unique
$allAssignees = Get-ManagementRoleAssignment -GetEffectiveUsers | Where-Object {$_.EffectiveUserName -eq $migAdminUserName } | select-object RoleAssigneeName -Unique
$orgRole = $allAssignees | Where-Object { $_.RoleAssigneeName -eq "Organization Management" }
if (-Not $orgRole)
{
    $orgRole = $allRoles | Where-Object { $_.Role.Name -eq "Organization Management" }
}
$srvRole = $allAssignees | Where-Object { $_.RoleAssigneeName -eq "Server Management" }
if (-Not $srvRole)
{
    $srvRole = $allRoles | Where-Object { $_.Role.Name -eq "Organization Management" }
}

if (-Not $orgRole -and -Not $srvRole)
{
    Write-Warning "You do not have the right roles assigned! Required one of:"
    Write-Warning " - Organization Management"
    Write-Warning " - Server Management"
}
else
{
    if ($orgRole)
    {
        Write-Host "You have the Organization Management role assigned"
    }
    else
    {
        Write-Host "You have the Server Management role assigned"
    }
}
