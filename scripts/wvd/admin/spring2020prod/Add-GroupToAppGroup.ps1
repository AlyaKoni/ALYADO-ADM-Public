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
    06.08.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$ResourceGroupName = "alyapinfresg040",
    [string]$AppGroupName = "alyapinfavda001",
    [string]$AdGroupName = "AVDAPPGRP_DataSience"
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\spring2020prod\Add-GroupToAppGroup-$($AlyaTimeString).log" | Out-Null

# Constants

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.DesktopVirtualization"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | Add-GroupToAppGroup | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking app group
Write-Host "Checking app group" -ForegroundColor $CommandInfo
$AppGrp = Get-AzWvdApplicationGroup -Name $AppGroupName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $AppGrp)
{
    throw "App group not found. Please create the app group $AppGroupName with the script Create-AppGroup.ps1"
}

# Checking ad group
Write-Host "Checking ad group" -ForegroundColor $CommandInfo
$AdGrp = Get-AzADGroup -DisplayName $AdGroupName
if (-Not $AdGrp)
{
    throw "AD group not found. Please create the ad group $AdGroupName"
}

# Checking ad group role assignment
Write-Host "Checking ad group role assignment" -ForegroundColor $CommandInfo
$Assgnmnt = Get-AzRoleAssignment -ObjectId $AdGrp.Id -RoleDefinitionName "Desktop Virtualization User" -ResourceName $AppGroupName -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.DesktopVirtualization/applicationGroups"
if (-Not $Assgnmnt)
{
    Write-Warning "AD group role assignment not found. Creating the ad group role assignment"
    $Assgnmnt = New-AzRoleAssignment -ObjectId $AdGrp.Id -RoleDefinitionName "Desktop Virtualization User" -ResourceName $AppGroupName -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.DesktopVirtualization/applicationGroups"
}

#Stopping Transscript
Stop-Transcript
