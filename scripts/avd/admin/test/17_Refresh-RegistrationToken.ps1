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
    06.03.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\prod\Refresh-RegistrationToken-$($AlyaTimeString).log" | Out-Null

# Constants
$ShResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdAvdSessionHostsResGrp)"
$ResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdAvdManagementResGrp)"
$HostPoolName = "$($AlyaNamingPrefixTest)avdh$($AlyaResIdAvdHostpool)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.DesktopVirtualization"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionNameTest

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AVD | Refresh-RegistrationToken | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking Management Ressource Group
Write-Host "Checking Management Ressource Group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    throw "Management Ressource Group not found. Please create the Management Ressource Group $ResourceGroupName"
}

# Checking HostPool
Write-Host "Checking HostPool" -ForegroundColor $CommandInfo
$HstPl = Get-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $HstPl)
{
    throw "HostPool not found. Please create the HostPool $HostPoolName with the script Create-HostPool.ps1"
}

# Checking avd agent registration token
Write-Host "Checking avd agent registration token"
$HstPlRegInf = Get-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName
if ($HstPlRegInf.ExpirationTime -lt (Get-Date).AddHours(1))
{
    Write-Warning "Registration token has expired. Creating a new one."
    $HstPlRegInf = New-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
        -ExpirationTime $((get-date).ToUniversalTime().AddDays(1).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))
}

# Removing session hosts
<#
Write-Host "Removing session hosts" -ForegroundColor $CommandInfo
$sessionHosts = Get-AzVM -ResourceGroupName $ShResourceGroupName
foreach($sessionHost in $sessionHosts)
{
    $VMName = $sessionHost.Name
    Write-Host "Removing session host $VMName" -ForegroundColor $CommandInfo
    $shost = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName | Where-Object { $_.Name -like "*$VMName*"}
    if ($shost)
    {
        $sHostName = $shost.Name.Replace($HostPoolName, "").Trim("/")
        Remove-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -Name $sHostName -SubscriptionId $Context.Subscription.Id -Force
    }
}
#>

# Refresh registration on VMs
Write-Host "Refresh registration on VMs" -ForegroundColor $CommandSuccess
Write-Host " - Launch regedit as admin" -ForegroundColor $CommandSuccess
Write-Host " - Go to HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent" -ForegroundColor $CommandSuccess
Write-Host "   - IsRegistered = 0" -ForegroundColor $CommandSuccess
Write-Host "   - RegistrationToken = " -ForegroundColor $CommandSuccess -NoNewline
Write-Host "$($HstPlRegInf.Token)" -ForegroundColor $CommandWarning
Write-Host " - Launch powershell as admin" -ForegroundColor $CommandSuccess
Write-Host "   - Restart-Service RDAgentBootLoader" -ForegroundColor $CommandSuccess
#Write-Host "   - Restart-Computer" -ForegroundColor $CommandSuccess

#Stopping Transscript
Stop-Transcript
