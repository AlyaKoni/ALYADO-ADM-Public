﻿#Requires -Version 2.0

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
    16.11.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\prod\Create-HostPool-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdManagementResGrp)"
$HostPoolName = "$($AlyaNamingPrefix)avdh$($AlyaResIdAvdHostpool)"
$HostPoolType = "Pooled"
$HostPoolDescription = "Stellt Desktops zur Verfï¿½gung"
$HostPoolFriendlyName = "$($AlyaCompanyNameShortM365) Desktop"
$HostPoolLoadBalancerType = "DepthFirst" #"BreathFirst", "DepthFirst"
$HostPoolPreferedAppGroupType = "Desktop" #"Desktop", "RailApplications"
$HostPoolDesktopAppGroupName = $HostPoolName + "ag1" #Not used if HostPoolPreferedAppGroupType="Desktop"
$WorkspaceName = "$($AlyaNamingPrefix)avdw$($AlyaResIdAvdWorkspace)" #Not used if HostPoolPreferedAppGroupType="Desktop"
$HostPoolMaxSessionLimit = $AlyaAvdMaxSessions
$IsTestHostPool = $false
$AvdLocation = $AlyaLocation
if ($AlyaLocation -eq "switzerlandnorth") { $AvdLocation = "westeurope" }

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
Write-Host "AVD | Create-HostPool | AZURE" -ForegroundColor $CommandInfo
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
    $ResGrp = New-AzResourceGroup -Name $ResourceGroupName -Location $AvdLocation -Tag @{displayName="AVD Management";ownerEmail=$Context.Account.Id}
}

# Checking HostPool
Write-Host "Checking HostPool" -ForegroundColor $CommandInfo
$HstPl = Get-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $HstPl)
{
    Write-Warning "HostPool not found. Creating the HostPool $HostPoolName"

    if ($HostPoolPreferedAppGroupType -eq "Desktop")
    {

        $HstPl = New-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -Location $AvdLocation `
            -HostPoolType $HostPoolType -LoadBalancerType $HostPoolLoadBalancerType -PreferredAppGroupType $HostPoolPreferedAppGroupType `
            -MaxSessionLimit $HostPoolMaxSessionLimit -FriendlyName $HostPoolFriendlyName -Description $HostPoolDescription `
            -StartVMOnConnect:$true -Tag @{displayName=$HostPoolFriendlyName;ownerEmail=$Context.Account.Id}

    }
    else
    {

        $HstPl = New-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -Location $AvdLocation `
            -WorkspaceName $WorkspaceName -HostPoolType $HostPoolType -LoadBalancerType $HostPoolLoadBalancerType `
            -DesktopAppGroupName $HostPoolDesktopAppGroupName -PreferredAppGroupType $HostPoolPreferedAppGroupType `
            -MaxSessionLimit $HostPoolMaxSessionLimit -FriendlyName $HostPoolFriendlyName -Description $HostPoolDescription `
            -StartVMOnConnect:$true -Tag @{displayName=$HostPoolFriendlyName;ownerEmail=$Context.Account.Id}

    }
}

if ($IsTestHostPool)
{
    Update-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -ValidationEnvironment:$true
}

# Checking HostPool RegistrationInfo
Write-Host "Checking HostPool RegistrationInfo" -ForegroundColor $CommandInfo
$HstPlRegInf = Get-AzWvdRegistrationInfo -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if ((-Not $HstPlRegInf) -or (-Not $HstPlRegInf.Token))
{
    Write-Warning "HostPool RegistrationInfo not found. Creating the HostPool RegistrationInfo"
    $HstPlRegInf = New-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
        -ExpirationTime $((get-date).ToUniversalTime().AddDays(1).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))
}

#Stopping Transscript
Stop-Transcript
