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
    02.02.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    [Parameter(Mandatory=$true)]
    [string]$VmName,
    [Parameter(Mandatory=$true)]
    [string]$FromNicName,
    [Parameter(Mandatory=$true)]
    [string]$ToNicName,
    #[Parameter(Mandatory=$true)]
    #[string]$VmAdminPassword,
    #[Parameter(Mandatory=$true)]
    #[SecureString]$VmAdminPasswordSec = $null,
    $DiagnosticResourceGroupName = $null,
    $DiagnosticStorageName = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\network\Change-NicOnVm-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Compute"
Install-ModuleIfNotInstalled "Az.Network"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Network | Change-NicOnVm | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking ressource group
Write-Host "Checking vm ressource group '$ResourceGroupName'" -ForegroundColor $CommandInfo
$ResGrpVm = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrpVm)
{
    throw "Ressource Group not found."
}

# Checking locks on resource group
Write-Host "Checking locks on resource group '$($ResourceGroupName)'" -ForegroundColor $CommandInfo
$actLocks = Get-AzResourceLock -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
foreach($actLock in $actLocks)
{
    if ($actLock.Properties.level -eq "CanNotDelete")
    {
        throw "Ressource Group has a delete lock."
    }
}

# Checking the source vm
Write-Host "Checking the source vm '$VmName'" -ForegroundColor $CommandInfo
$Vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName -ErrorAction SilentlyContinue
$vmFromFile = $false
if (-Not $Vm)
{
    if (Test-Path "$AlyaData\azure\virtualMachineDefinitions\$($AlyaSubscriptionName)-$($ResourceGroupName)-$($VmName).json")
    {
        #TODO ask to get from file
        $vm = Get-Content -Path "$AlyaData\azure\virtualMachineDefinitions\$($AlyaSubscriptionName)-$($ResourceGroupName)-$($VmName).json" | ConvertFrom-Json
        $vmFromFile = $true
    }
    else {
        throw "VM not found."
    }
}
else
{
    if (-Not (Test-Path "$AlyaData\azure\virtualMachineDefinitions")) { New-Item -Path "$AlyaData\azure\virtualMachineDefinitions" -ItemType Directory}
    $null = $vm | ConvertTo-Json -Depth 20 | Set-Content -Path "$AlyaData\azure\virtualMachineDefinitions\$($AlyaSubscriptionName)-$($ResourceGroupName)-$($VmName).json"
}
if ($vm.DiagnosticsProfile.BootDiagnostics.Enabled)
{
    $StorageName = $vm.DiagnosticsProfile.BootDiagnostics.StorageUri.Split("/.".ToCharArray())[2]
    $DiagnosticResourceGroup = $ResourceGroupName
    $storage = Get-AzStorageAccount -Name $StorageName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if ($null -eq $storage -and -Not [string]::IsNullOrEmpty($DiagnosticResourceGroupName)) {
        $DiagnosticResourceGroup = $DiagnosticResourceGroupName
        $storage = Get-AzStorageAccount -Name $StorageName -ResourceGroupName $DiagnosticResourceGroupName -ErrorAction SilentlyContinue
    } 
    if ($null -eq $storage){
        throw "Parameter DiagnosticResourceGroupName is required"
    }
}

# Diabling attached resource deletion
Write-Host "Diabling attached resource deletion on vm '$VmName'" -ForegroundColor $CommandInfo
$dirty = $false
foreach($nic in $vm.NetworkProfile.NetworkInterfaces)
{
    if ($nic.DeleteOption -eq "Delete")
    {
        $nic.DeleteOption = "Detach"
        $dirty = $true
    }
}
if ($vm.StorageProfile.OsDisk.DeleteOption -eq "Delete")
{
    $vm.StorageProfile.OsDisk.DeleteOption = "Detach"
    $dirty = $true
}
foreach($disk in $vm.StorageProfile.DataDisks)
{
    if ($disk.DeleteOption -eq "Delete")
    {
        $disk.DeleteOption = "Detach"
        $dirty = $true
    }
}
if (-Not $vmFromFile -and $dirty) {
    $null = $Vm | Update-AzVM
    $Vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName -ErrorAction SilentlyContinue
}

# Checking the from nic
Write-Host "Checking the from nic '$FromNicName'" -ForegroundColor $CommandInfo
$fromNic = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $FromNicName
if (-Not $fromNic)
{
    throw "From nic not found."
}

# Checking the to nic
Write-Host "Checking the to nic '$ToNicName'" -ForegroundColor $CommandInfo
$toNic = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $ToNicName
if (-Not $toNic)
{
    throw "To nic not found."
}

# Stopping the source vm
if (-Not $vmFromFile) {
    Write-Host "Stopping the source vm '$VmName'" -ForegroundColor $CommandInfo
    Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName -Force
}

# Creating new VM Disk Snapshots
if (-Not $vmFromFile) {
    $SnapshotName = $VmName + "-snapshot-$($Vm.StorageProfile.OsDisk.Name)"
    Write-Host "Creating new VM Disk Snapshot '$SnapshotName'" -ForegroundColor $CommandInfo
    $Snapshot = Get-AzSnapshot -SnapshotName $SnapshotName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if ($Snapshot)
    {
        Write-Warning "Deleting existing snapshot $SnapshotName"
        Remove-AzSnapshot -SnapshotName $SnapshotName -ResourceGroupName $ResourceGroupName -Force
    }
    $SnapshotConfig = New-AzSnapshotConfig -SourceUri $Vm.StorageProfile.OsDisk.ManagedDisk.Id -Location $Vm.Location -CreateOption "Copy"
    $Snapshot = New-AzSnapshot -Snapshot $SnapshotConfig -SnapshotName $SnapshotName -ResourceGroupName $ResourceGroupName
    foreach($disk in $vm.StorageProfile.DataDisks)
    {
        $SnapshotName = $VmName + "-snapshot-$($disk.Name)"
        Write-Host "Creating new VM Disk Snapshot '$SnapshotName'" -ForegroundColor $CommandInfo
        $Snapshot = Get-AzSnapshot -SnapshotName $SnapshotName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        if ($Snapshot)
        {
            Write-Warning "Deleting existing snapshot $SnapshotName"
            Remove-AzSnapshot -SnapshotName $SnapshotName -ResourceGroupName $ResourceGroupName -Force
        }
        $SnapshotConfig = New-AzSnapshotConfig -SourceUri $disk.ManagedDisk.Id -Location $Vm.Location -CreateOption "Copy"
        $Snapshot = New-AzSnapshot -Snapshot $SnapshotConfig -SnapshotName $SnapshotName -ResourceGroupName $ResourceGroupName
    }
}

# Getting extensions
if (-Not $vmFromFile) {
    Write-Host "Getting extensions" -ForegroundColor $CommandInfo
    $VmExtensions = Get-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VmName -ErrorAction SilentlyContinue
    $null = $VmExtensions | ConvertTo-Json -Depth 20 | Set-Content -Path "$AlyaData\azure\virtualMachineDefinitions\$($AlyaSubscriptionName)-$($ResourceGroupName)-$($VmName)-Extensions.json"
}

# Deleting source vm
if (-Not $vmFromFile) {
    Write-Host "Deleting source vm '$($VmName)'" -ForegroundColor $CommandInfo
    Remove-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName -ForceDeletion $false -Force
}

# Recreating source vm
Write-Host "Recreating source vm '$($VmName)'" -ForegroundColor $CommandInfo
if ($Vm.AvailabilitySetReference)
{
    #TODO -LicenseType $AlyaVmLicenseType if server and hybrid benefit
    $VmConfig = New-AzVMConfig -AvailabilitySetId $Vm.AvailabilitySetReference.Id -VMName $VmName -VMSize $Vm.HardwareProfile.VmSize
}
else
{
    #TODO -LicenseType $AlyaVmLicenseType if server and hybrid benefit
    $VmConfig = New-AzVMConfig -VMName $VmName -VMSize $Vm.HardwareProfile.VmSize
}

# if (-Not $VmAdminPasswordSec)
# {
#     $VmAdminPasswordSec = ConvertTo-SecureString -String $VmAdminPassword -AsPlainText -Force
# }
# $userName = $vm.OSProfile.AdminUsername
# if ([string]::IsNullOrEmpty($userName)) {
#     $userName = "$($VmName)Admin"
# }
# $VMCredential = New-Object System.Management.Automation.PSCredential ($userName, $VmAdminPasswordSec)
# if ($vm.OSProfile.WindowsConfiguration) {
#     Set-AzVMOperatingSystem -VM $VmConfig -Windows -ComputerName $VmName -Credential $VMCredential
# } else {
#     Set-AzVMOperatingSystem -VM $VmConfig -Linux -ComputerName $VmName -Credential $VMCredential
# }

foreach($nic in $Vm.NetworkProfile.NetworkInterfaces)
{
    $netIfaceName = $nic.Id.Substring($nic.Id.LastIndexOf("/") + 1)
    if ($netIfaceName -eq $FromNicName) { $netIfaceName = $ToNicName }
    $netIface = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $netIfaceName
    Add-AzVMNetworkInterface -VM $VmConfig -Id $netIface.Id | Out-Null
}

if ($vm.DiagnosticsProfile.BootDiagnostics.Enabled)
{
    Set-AzVMBootDiagnostic -VM $VmConfig -Enable -ResourceGroupName $DiagnosticResourceGroup -StorageAccountName $StorageName | Out-Null
}

$osDisk = Get-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $Vm.StorageProfile.OsDisk.Name
if ($Vm.StorageProfile.OsDisk.OsType -eq "Windows") {
    Set-AzVMOSDisk -VM $VmConfig -Windows -Name $Vm.StorageProfile.OsDisk.Name -ManagedDiskId $osDisk.Id -CreateOption "Attach"
} else {
    Set-AzVMOSDisk -VM $VmConfig -Linux -Name $Vm.StorageProfile.OsDisk.Name -ManagedDiskId $osDisk.Id -CreateOption "Attach"
}
foreach($disk in $Vm.StorageProfile.DataDisks)
{
    $dDisk = Get-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $disk.Name
    if ($disk.OsType -eq "Windows") {
        Set-AzVMOSDisk -VM $VmConfig -Windows -Name $disk.Name -ManagedDiskId $dDisk.Id -CreateOption "Attach" `
            -Caching $disk.Caching -Lun $disk.Lun -DiskSizeInGB $disk.DiskSizeGB
    } else {
        Set-AzVMOSDisk -VM $VmConfig -Linux -Name $disk.Name -ManagedDiskId $dDisk.Id -CreateOption "Attach" `
            -Caching $disk.Caching -Lun $disk.Lun -DiskSizeInGB $disk.DiskSizeGB
    }
}

if ($Vm.UefiProfile)
{
    Write-Warning "Please check code"
    pause
    Set-AzVMUefi -VM $VmConfig -EnableSecureBoot $Vm.UefiProfile.EnableSecureBoot -EnableVtpm $Vm.UefiProfile.EnableVtpm
}
if ($Vm.SecurityProfile)
{
    Set-AzVMSecurityProfile -VM $VmConfig -SecurityType $Vm.SecurityProfile.SecurityType
}
if ($Vm.Plan)
{
    if ($Vm.Plan.PromotionCode) {
        Set-AzVMPlan -VM $VmConfig -Name $Vm.Plan.Name -Product $Vm.Plan.Product -Publisher $Vm.Plan.Publisher -PromotionCode $Vm.Plan.PromotionCode
    } else {
        Set-AzVMPlan -VM $VmConfig -Name $Vm.Plan.Name -Product $Vm.Plan.Product -Publisher $Vm.Plan.Publisher
    }
}
$newVm = New-AzVM -ResourceGroupName $ResourceGroupName -Location $Vm.Location -VM $VmConfig -DisableBginfoExtension
$newVm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName

# Setting tags
Write-Host "Setting tags" -ForegroundColor $CommandInfo
if (-Not $vmFromFile) {
    Update-AzTag -ResourceId $newVm.Id -Tag $Vm.Tags -Operation "Replace"
} else {
    $hashtable = @{}
    $Vm.Tags.psobject.properties | ForEach-Object { $hashtable[$_.Name] = $_.Value }
    $null = Update-AzTag -ResourceId $newVm.Id -Tag $hashtable -Operation "Replace"
}

# Stopping VM
Write-Host "Stopping VM" -ForegroundColor $CommandInfo
Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName -Force

#Stopping Transscript
Stop-Transcript
