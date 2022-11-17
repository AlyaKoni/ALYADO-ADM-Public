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
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\prod\Configure-AutoStartRole-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdSessionHostsResGrp)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AVD | Configure-AutoStartRole | AZURE" -ForegroundColor $CommandInfo
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

# Checking custom role
Write-Host "Checking custom role" -ForegroundColor $CommandInfo
$scope = "/subscriptions/$($Context.Subscription.Id)"
$role = Get-AzRoleDefinition -Name "$($AlyaCompanyNameShortM365)StartVMOnConnect" -Scope $scope -ErrorAction SilentlyContinue
if (-Not $Role)
{
    $roleDef = @"
{
  "Name": "$($AlyaCompanyNameShortM365)StartVMOnConnect",
  "IsCustom": true,
  "Description": "Start VM on connect with AVD (Custom)",
  "Actions": [
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/virtualMachines/instanceView/read"
  ],
  "NotActions": [],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": [
    "$scope"
  ]
}
"@
    $temp = New-TemporaryFile
    $roleDef | Set-Content -Path $temp -Encoding UTF8 -Force
    New-AzRoleDefinition -InputFile $temp.FullName
    Remove-Item -Path $temp -Force
    do
    {
        Start-Sleep -Seconds 10
        $role = Get-AzRoleDefinition -Name "$($AlyaCompanyNameShortM365)StartVMOnConnect" -Scope $scope -ErrorAction SilentlyContinue
    }
    while (-Not $role)
}

# Checking role assignment
Write-Host "Checking role assignment" -ForegroundColor $CommandInfo
$objs = Get-AzADServicePrincipal -DisplayName "Windows Virtual Desktop"
foreach($obj in $objs)
{
    $ra = Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName -RoleDefinitionName "$($AlyaCompanyNameShortM365)StartVMOnConnect" -ObjectId $obj.Id -ErrorAction SilentlyContinue
    if (-Not $ra)
    {
        Write-Warning "  Role assigment on $($ResourceGroupName) not found. Adding it now..."
        $ra = New-AzRoleAssignment -RoleDefinitionName "$($AlyaCompanyNameShortM365)StartVMOnConnect" -ObjectId $obj.Id -ResourceGroupName $ResourceGroupName
    }
}

$objs = Get-AzADServicePrincipal -DisplayName "Azure Virtual Desktop"
foreach($obj in $objs)
{
    $ra = Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName -RoleDefinitionName "$($AlyaCompanyNameShortM365)StartVMOnConnect" -ObjectId $obj.Id -ErrorAction SilentlyContinue
    if (-Not $ra)
    {
        Write-Warning "  Role assigment on $($ResourceGroupName) not found. Adding it now..."
        $ra = New-AzRoleAssignment -RoleDefinitionName "$($AlyaCompanyNameShortM365)StartVMOnConnect" -ObjectId $obj.Id -ResourceGroupName $ResourceGroupName
    }
}

#Stopping Transscript
Stop-Transcript
