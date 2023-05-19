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
    02.04.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$ResourceGroupName = "alyainfpresg053",
    [Parameter(Mandatory=$false)]
    [string]$NewSku = "Standard_D8s_v3"
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019prod\51_resizeHostpoolVmSku-$($AlyaTimeString).log" | Out-Null

# Constants
$ErrorActionPreference = "Stop"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Compute"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 51_resizeHostpoolVmSku | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

#Main
Write-Host "Stopping all VMs" -ForegroundColor $CommandInfo
$jobs = @()
foreach($vm in (Get-AzVM -ResourceGroupName $ResourceGroupName))
{
   $job = Start-Job -scriptblock {
     param($vmname, $resGrp)
     Get-AzVM -ResourceGroupName $resGrp -Name $vmname | Stop-AzVM -Force
     } -argumentlist @($vm.Name, $ResourceGroupName)
   $jobs += $job
}
if($jobs -ne @())
{
    Write-Host "  Waiting until all VMs have stopped state..."
    Wait-Job -Job $jobs
    Get-Job | Receive-Job
}

Write-Host "Changing VM sizes" -ForegroundColor $CommandInfo
$jobs = @()
foreach($vm in (Get-AzVM -ResourceGroupName $ResourceGroupName))
{
   $job = Start-Job -scriptblock {
     param($vmname, $resGrp, $sku)
     $vm = Get-AzVM -ResourceGroupName $resGrp -Name $vmname
     $vm.HardwareProfile.VmSize = $sku
     $vm | Update-AzVM
     } -argumentlist @($vm.Name, $ResourceGroupName, $NewSku)
   $jobs += $job
}
if($jobs -ne @())
{
    Write-Host "  Waiting until all VMs have the new size..."
    Wait-Job -Job $jobs
    Get-Job | Receive-Job
}

foreach($vm in (Get-AzVM -ResourceGroupName $ResourceGroupName))
{
   if ($vm.HardwareProfile.VmSize -ne $NewSku)
   {
        Write-Error "Was not able to change size on vm $($vm.Name) to $($NewSku). Is still $($vm.HardwareProfile.VmSize)." -ErrorAction Continue
   }
}

#Stopping Transscript
Stop-Transcript
