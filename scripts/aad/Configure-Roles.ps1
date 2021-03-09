#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

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
    28.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$inputFile = $null #Defaults to "$AlyaData\aad\Rollen.xlsx"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Configure-Roles-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $inputFile)
{
    $inputFile = "$AlyaData\aad\Rollen.xlsx"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MSOnline"
Install-ModuleIfNotInstalled "ImportExcel"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MSOL

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Roles | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Reading input file
Write-Host "Reading input file from '$inputFile'" -ForegroundColor $CommandInfo
if (-Not (Test-Path $inputFile))
{
    throw "Input file not found!"
}
$roleDefs = Import-Excel $inputFile -ErrorAction Stop

# Configured roles
Write-Host "Configured roles:" -ForegroundColor $CommandInfo
$lastRole = $null
$ownRoles = @{}
$builtinRoles = @{}
$mode = 0
foreach ($roleDef in $roleDefs)
{
    if ([string]::IsNullOrEmpty($roleDef.Role) -and [string]::IsNullOrEmpty($roleDef.UserOrOwnRole))
    {
        continue
    }

    $roleName = $roleDef.Role
    if ([string]::IsNullOrEmpty($roleName))
    {
        $roleName = $lastRole
    }
    $lastRole = $roleName

    if ($roleName -eq "Own Roles")
    {
        $mode = 1
        continue
    }
    if ($roleName -eq "Builtin Roles")
    {
        $mode = 2
        continue
    }

    if ($mode -eq 1)
    {
        if ($ownRoles.ContainsKey($roleName))
        {
            $ownRoles.$roleName += $roleDef.UserOrOwnRole
        }
        else
        {
            $ownRoles.$roleName = @($roleDef.UserOrOwnRole)
        }
    }
    else
    {
        if ($builtinRoles.ContainsKey($roleName))
        {
            if ($ownRoles.ContainsKey($roleDef.UserOrOwnRole))
            {
                foreach($user in $ownRoles[$roleDef.UserOrOwnRole])
                {
                    if (-Not $builtinRoles.$roleName -contains $user)
                    {
                        $builtinRoles.$roleName += $user
                    }
                }
            }
            else
            {
                $builtinRoles.$roleName += $roleDef.UserOrOwnRole
            }
        }
        else
        {
            if ($ownRoles.ContainsKey($roleDef.UserOrOwnRole))
            {
                $builtinRoles.$roleName = $ownRoles[$roleDef.UserOrOwnRole]
            }
            else
            {
                $builtinRoles.$roleName = @($roleDef.UserOrOwnRole)
            }
        }
    }
}

Write-Host "Own roles:"
foreach($key in $ownRoles.Keys) { Write-Host "  $key" }
Write-Host "BuiltIn roles:"
foreach($key in $builtinRoles.Keys) { Write-Host "  $key" }

# Checking built in roles
Write-Host "Checking built in roles:" -ForegroundColor $CommandInfo
$allBuiltinRoles = Get-MsolRole
$missFound = $false
foreach($role in $allBuiltinRoles)
{
    if (-Not $builtinRoles.ContainsKey($role.Name))
    {
        Write-Warning "The role '$($role.Name)' is not present in the excel sheet. Please update it!"
        $missFound = $true
    }
}
if (-Not $missFound)
{
    Write-Host "No missing role found"
}

# Configuring roles
Write-Host "Configuring roles:" -ForegroundColor $CommandInfo
foreach($roleName in ($builtinRoles.Keys | Sort-Object))
{
    Write-Host "  role '$($roleName)'"
    $newUsers = $builtinRoles[$roleName]

    if ($newUsers -and $newUsers[0] -like "##*") {
        continue
    }

    $role = Get-MsolRole -RoleName $roleName
    $actMembs = Get-MsolRoleMember -RoleObjectId $role.ObjectId

    #Removing inactivated members
    $actMembs | foreach {
        $actMemb = $_
        if ($actMemb.EmailAddress -And ((-Not $newUsers) -or ($newUsers -notcontains $actMemb.EmailAddress)))
        {
            Write-Host "    removing user $($actMemb.EmailAddress)" -ForegroundColor $CommandError
            Remove-MsolRoleMember -RoleObjectId $role.ObjectId -RoleMemberObjectId $actMemb.ObjectId
        }
    }

    #Adding new members
    $newUsers | foreach {
        $newMemb = $_
        if ($newMemb)
        {
            $found = $false
            $actMembs | foreach {
                $actMemb = $_
                if ($newMemb -eq $actMemb.EmailAddress -or $newMemb -eq $actMemb.ObjectId)
                {
                    $found = $true
                    #break
                }
            }
            if (-Not $found)
            {
                Write-Host "    adding user $($newMemb)" -ForegroundColor $CommandWarning
                Add-MsolRoleMember -RoleObjectId $role.ObjectId -RoleMemberEmailAddress $newMemb
            }
        }
    }
}

#Stopping Transscript
Stop-Transcript