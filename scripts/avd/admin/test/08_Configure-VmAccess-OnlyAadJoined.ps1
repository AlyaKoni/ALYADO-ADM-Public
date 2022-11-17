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
    16.11.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\test\Configure-VmAccess-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdAvdSessionHostsResGrp)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionNameTest

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AVD | Configure-VmAccess | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    throw "Ressource Group not found. Please create the Ressource Group $ResourceGroupName"
}

# Checking role assignment Virtual Machine User Login
Write-Host "Checking role assignment Virtual Machine User Login" -ForegroundColor $CommandInfo
$groups = @( $AlyaAllInternals, $AlyaAllExternals )
foreach($group in $groups)
{
    $obj = Get-AzADGroup -DisplayName $group
    if (-Not $obj)
    {
        throw "Group not found: $group"
    }
    $ra = Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName -RoleDefinitionName "Virtual Machine User Login" -ObjectId $obj.Id -ErrorAction SilentlyContinue
    if (-Not $ra)
    {
        Write-Warning "  Role assigment on $($ResourceGroupName) not found. Adding it now..."
        $ra = New-AzRoleAssignment -RoleDefinitionName "Virtual Machine User Login" -ObjectId $obj.Id -ResourceGroupName $ResourceGroupName
    }
}

# Checking role assignment Virtual Machine Administrator Login
Write-Host "Checking role assignment Virtual Machine Administrator Login" -ForegroundColor $CommandInfo
$obj = Get-AzADUser -UserPrincipalName $Context.Account.Id
$ra = Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName -RoleDefinitionName "Virtual Machine Administrator Login" -ObjectId $obj.Id -ErrorAction SilentlyContinue
if (-Not $ra)
{
    Write-Warning "  Role assigment on $($ResourceGroupName) not found. Adding it now..."
    $ra = New-AzRoleAssignment -RoleDefinitionName "Virtual Machine Administrator Login" -ObjectId $obj.Id -ResourceGroupName $ResourceGroupName
}

#Stopping Transscript
Stop-Transcript
