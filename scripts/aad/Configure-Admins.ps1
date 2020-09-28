#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This file is part of the Alya Base Configuration.
    The Alya Base Configuration is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
	Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
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
    28.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Configure-Admins-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
#Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "MSOnline"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
#LoginTo-Ad
LoginTo-MSOL

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Admins | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking Company Administrator role
Write-Host "Checking Company Administrator role:" -ForegroundColor $CommandInfo
$gaRole = Get-MsolRole -RoleName "Company Administrator"
$gaRoleMembs = Get-MsolRoleMember -RoleObjectId $gaRole.ObjectId
Write-Host "Actual Company Administrators:"
$gaRoleMembs
if ($gaRoleMembs.Count -gt 1)
{
    Write-Warning "We suggest to have only one single Company Administrator"
}
if ($globalAdmin.EmailAddress -like "admin@*" -or $globalAdmin.EmailAddress -like "administrator@*" -or `
    $globalAdmin.EmailAddress -like "globaladmin@*")
{
    $name = -Join ([System.Security.Cryptography.HashAlgorithm]::Create("MD5").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($AlyaDomainName)) | % { $_.ToString("x2") } )
    $AlyaGlobalAdmin = "$name@$($AlyaDomainName)"
    Write-Warning "We suggest strong names for Company Administrators"
    Write-Warning "Example: $AlyaGlobalAdmin"
}

# Checking Privileged Role Administrator role
Write-Host "Checking Privileged Role Administrator role:" -ForegroundColor $CommandInfo
$paRole = Get-MsolRole -RoleName "Privileged Role Administrator"
$privilegedAdmins = Get-MsolRoleMember -RoleObjectId $paRole.ObjectId
Write-Host "Actual Privileged Role Administrators:"
$privilegedAdmins
if ($privilegedAdmins.Count -eq 0)
{
    Write-Warning "We suggest to specify at least one Privileged Role Administrator"
    Write-Warning "He will be able to solve Global Administrator rights if something goes wrong"
}

#Stopping Transscript
Stop-Transcript