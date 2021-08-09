#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2021

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
    06.08.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$ResourceGroupName = "alyapinfresg040",
    [string]$HostPoolName = "alyapinfavdh001",
    [string]$WorkspaceName = "alyapinfavdw001",
    [string]$AppGroupName = "alyapinfavda001",
    [string]$AppGroupDescription = "Stellt den Data Sience Desktop zur Verfügung",
    [string]$AppGroupFriendlyName = "ALYA Data Sience Desktop",
    [string]$AppGroupType = "Desktop"
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\spring2020prod\Create-AppGroup-$($AlyaTimeString).log" | Out-Null

# Constants

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | Create-AppGroup | AZURE" -ForegroundColor $CommandInfo
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
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ResourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $ResourceGroupName -Location $AlyaLocation -Tag @{displayName="WVD Management";ownerEmail=$Context.Account.Id}
}

# Checking HostPool
Write-Host "Checking HostPool" -ForegroundColor $CommandInfo
$HstPl = Get-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $HstPl)
{
    throw "HostPool not found. Please create the HostPool $HostPoolName with the script Create-HostPool.ps1"
}

# Checking workspace
Write-Host "Checking workspace" -ForegroundColor $CommandInfo
$WrkSpc = Get-AzWvdWorkspace -Name $WorkspaceName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $WrkSpc)
{
    throw "Workspace not found. Please create the workspace $WorkspaceName with the script Create-Workspace.ps1"
}

# Checking app group
Write-Host "Checking app group" -ForegroundColor $CommandInfo
$AppGrp = Get-AzWvdApplicationGroup -Name $AppGroupName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $AppGrp)
{
    Write-Warning "App group not found. Creating the app group $AppGroupName"
    $AppGrp = New-AzWvdApplicationGroup -Name $AppGroupName -ResourceGroupName $ResourceGroupName `
        -Description $AppGroupDescription -FriendlyName $AppGroupFriendlyName -Location $AlyaLocation `
        -HostPoolArmPath $HstPl.Id -ApplicationGroupType $AppGroupType `
        -Tag @{displayName=$AppGroupFriendlyName;ownerEmail=$Context.Account.Id}
}
if ($WrkSpc.ApplicationGroupReference -notcontains $AppGrp.Id)
{
    $ref = @()
    if ($WrkSpc.ApplicationGroupReference) { $ref = $WrkSpc.ApplicationGroupReference }
    $ref += $AppGrp.Id
    Update-AzWvdWorkspace -Name $WorkspaceName -ResourceGroupName $ResourceGroupName -ApplicationGroupReference $ref
}
if ($AppGroupType -eq "Desktop")
{
    $app = Get-AzWvdDesktop -ApplicationGroupName $AppGroupName -ResourceGroupName $ResourceGroupName
    if ($app.FriendlyName -ne $AppGroupFriendlyName)
    {
        $appName = $app.Name.Split("/") | Select -Last 1
        Update-AzWvdDesktop -ApplicationGroupName $AppGroupName -ResourceGroupName $ResourceGroupName -Name $appName -FriendlyName $AppGroupFriendlyName
    }
}

#Stopping Transscript
Stop-Transcript