#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This unpublished material is proprietary to Alya Consulting.
    All rights reserved. The methods and techniques described
    herein are considered trade secrets and/or confidential. 
    Reproduction or distribution, in whole or in part, is 
    forbidden except by express written permission of Alya Consulting.

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
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\prod\51_resizeHostpoolVmSku-$($AlyaTimeString).log" | Out-Null

# Constants
$ErrorActionPreference = "Stop"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

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
    Write-Error -Message "Can't get Az context! Not logged in?"
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
        Write-Error "Was not able to change size on vm $($vm.Name) to $($NewSku). Is still $($vm.HardwareProfile.VmSize)."
   }
}

#Stopping Transscript
Stop-Transcript