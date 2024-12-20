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
    13.03.2020 Konrad Brunner       Initial Version
    07.03.2022 Konrad Brunner       AVD Version
    16.11.2022 Konrad Brunner       Customer merges

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\image\Prepare-ImageServer-$($AlyaTimeString).log" | Out-Null

# Constants
$VmToImage = "$($AlyaNamingPrefix)avdi$($AlyaResIdAvdImageServer)"
$VmResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdImageResGrp)"
$ImageName = "$($VmToImage)_ImageServer"
$ImageResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdImageResGrp)"
$DiagnosticResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$DiagnosticStorageName = "$($AlyaNamingPrefix)strg$($AlyaResIdDiagnosticStorage)"
$KeyVaultResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$DateString = (Get-Date -Format "_yyyyMMdd_HHmmss")
$VMDiskName = "$($VmToImage)osdisk"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Compute"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "ImageHost | Prepare-ImageServer | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking ressource group
Write-Host "Checking vm ressource group" -ForegroundColor $CommandInfo
$ResGrpVm = Get-AzResourceGroup -Name $VmResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrpVm)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $VmResourceGroupName"
    $ResGrpVm = New-AzResourceGroup -Name $VmResourceGroupName -Location $AlyaLocation -Tag @{displayName="Image Host";ownerEmail=$Context.Account.Id}
}

# Checking ressource group
Write-Host "Checking image ressource group" -ForegroundColor $CommandInfo
$ResGrpImage = Get-AzResourceGroup -Name $ImageResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrpImage)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ImageResourceGroupName"
    $ResGrpImage = New-AzResourceGroup -Name $ImageResourceGroupName -Location $AlyaLocation -Tag @{displayName="Image";ownerEmail=$Context.Account.Id}
}

# Checking locks on resource group
Write-Host "Checking locks on resource group '$($VmResourceGroupName)'" -ForegroundColor $CommandInfo
$actLocks = Get-AzResourceLock -ResourceGroupName $VmResourceGroupName -ErrorAction SilentlyContinue
foreach($actLock in $actLocks)
{
    if ($actLock.Properties.level -eq "CanNotDelete")
    {
        Write-Host "Removing lock $($actLock.Name)"
        $null = $actLock | Remove-AzResourceLock -Force
    }
}

# Checking the source vm
Write-Host "Checking the source vm '$VmToImage'" -ForegroundColor $CommandInfo
$Vm = Get-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -ErrorAction SilentlyContinue
if (-Not $Vm)
{
    throw "VM not found. Please create the VM $VmToImage"
}
$Vm | Export-CliXml -Path "$AlyaData\avd\image\$VmToImage.cliXml" -Depth 20 -Force -Encoding $AlyaUtf8Encoding

# Stopping the source vm
Write-Host "Stopping the source vm '$VmToImage'" -ForegroundColor $CommandInfo
Stop-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Force

# Creating new VM Disk Snapshot
Write-Host "Creating new VM Disk Snapshot" -ForegroundColor $CommandInfo
$SnapshotName = $VmToImage + "-snapshot"
$Snapshot = Get-AzSnapshot -SnapshotName $SnapshotName -ResourceGroupName $VmResourceGroupName -ErrorAction SilentlyContinue
if ($Snapshot)
{
    Write-Warning "Deleting existing snapshot $SnapshotName"
    Remove-AzSnapshot -SnapshotName $SnapshotName -ResourceGroupName $VmResourceGroupName -Force
}
$SnapshotConfig = New-AzSnapshotConfig -SourceUri $Vm.StorageProfile.OsDisk.ManagedDisk.Id -Location $AlyaLocation -CreateOption "Copy"
$Snapshot = New-AzSnapshot -Snapshot $SnapshotConfig -SnapshotName $SnapshotName -ResourceGroupName $VmResourceGroupName

# Starting the source vm
Write-Host "Starting the source vm '$VmToImage'" -ForegroundColor $CommandInfo
Start-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage

# Preparing the source vm
Write-Host "Please prepare now the source host ($VmToImage):"
Write-Host '  - Start a PowerShell as Administrator'
Write-Host '  - Run commands:'
Write-Host '      sfc.exe /scannow'
Write-Host '      pause'
Write-Host '      Set-TimeZone -Id "UTC"'
#Write-Host '      Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation -Name RealTimeIsUniversal -Value 1 -Type DWord -Force'
#Write-Host '      Set-Service -Name w32time -StartupType Automatic'
#Write-Host '      Remove-Item -Path C:\Windows\Panther -Recurse -Force'
Write-Host '      $state = (Get-ItemProperty -Path HKLM:\SYSTEM\Setup\Status\SysprepStatus -Name GeneralizationState).GeneralizationState'
Write-Host '      if ($state -ne 7) { throw "wrong GeneralizationState" }'
Write-Host '      for ($i=0; $i -le 2; $i++) {'
Write-Host '      Get-AppxPackage -AllUser | where {$_.PackageFullName -like "Microsoft.LanguageExperiencePack*"} | Remove-AppxPackage -ErrorAction Continue'
Write-Host '      Get-AppxPackage -AllUser | where {$_.PackageFullName -like "AdobeNotificationClient_*"} | Remove-AppxPackage -ErrorAction Continue'
Write-Host '      Get-AppxPackage -AllUser | where {$_.PackageFullName -like "Adobe.CC.XD_*"} | Remove-AppxPackage -ErrorAction Continue'
Write-Host '      Get-AppxPackage -AllUser | where {$_.PackageFullName -like "Adobe.Fresco_*" } | Remove-AppxPackage -ErrorAction Continue'
Write-Host '      Get-AppxPackage -AllUser | where {$_.PackageFullName -like "InputApp_*" } | Remove-AppxPackage -ErrorAction Continue'
Write-Host '      Get-AppxPackage -AllUser | where {$_.PackageFullName -like "Microsoft.PPIProjection_*" } | Remove-AppxPackage -ErrorAction Continue'
Write-Host '      Get-AppxProvisionedPackage -Online | where {$_.PackageName -like "Microsoft.LanguageExperiencePack*"} | Remove-AppxProvisionedPackage -Online -ErrorAction Continue'
Write-Host '      Get-AppxProvisionedPackage -Online | where {$_.PackageName -like "AdobeNotificationClient_*"} | Remove-AppxProvisionedPackage -Online -ErrorAction Continue'
Write-Host '      Get-AppxProvisionedPackage -Online | where {$_.PackageName -like "Adobe.CC.XD_*"} | Remove-AppxProvisionedPackage -Online -ErrorAction Continue'
Write-Host '      Get-AppxProvisionedPackage -Online | where {$_.PackageName -like "Adobe.Fresco_*" } | Remove-AppxProvisionedPackage -Online -ErrorAction Continue'
Write-Host '      Get-AppxProvisionedPackage -Online | where {$_.PackageName -like "InputApp_*" } | Remove-AppxProvisionedPackage -Online -ErrorAction Continue'
Write-Host '      Get-AppxProvisionedPackage -Online | where {$_.PackageName -like "Microsoft.PPIProjection_*" } | Remove-AppxProvisionedPackage -Online -ErrorAction Continue'
Write-Host '      }'
Write-Host '      & "$Env:SystemRoot\system32\sysprep\sysprep.exe" /generalize /oobe /shutdown'
Write-Host '  - Wait until the vm has stopped state'
Write-Host '  - In case of troubles, follow this guide: https://learn.microsoft.com/en-us/azure/virtual-machines/windows/prepare-for-upload-vhd-image'
<#
Bei Fehler Logdatei untersuchen:
%WINDIR%\System32\Sysprep\Panther\setupact.log
Unter Umständen müssen Packages entfernt werden. Siehe hierzu cleanImage.ps1
#>
pause

# Checking if source vm is stopped
Write-Host "Checking if source vm $($VmToImage) is stopped" -ForegroundColor $CommandInfo
$isStopped = $false
while (-Not $isStopped)
{
    $Vm = Get-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Status -ErrorAction SilentlyContinue
    foreach ($VmStat in $Vm.Statuses)
    { 
        if($VmStat.Code -eq "PowerState/stopped" -or $VmStat.Code -eq "PowerState/deallocated")
        {
            $isStopped = $true
            break
        }
    }
    if (-Not $isStopped)
    {
        Write-Host "Please stop the VM $($VmToImage)"
        Start-Sleep -Seconds 15
    }
}

# Preparing the source vm
Write-Host "Preparing the source vm '$($VmToImage)'" -ForegroundColor $CommandInfo
Stop-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Force
Set-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Generalized  

# Deleting existing image (for update)
Write-Host "Deleting existing image if present" -ForegroundColor $CommandInfo
$image = Get-AzImage -ResourceGroupName $VmResourceGroupName -ImageName $ImageName -ErrorAction SilentlyContinue
if ($image)
{
    Write-Warning "Deleting existing image $ImageName"
    Remove-AzImage -ResourceGroupName $VmResourceGroupName -ImageName $ImageName -Force
}

# Saving the source vm as image
Write-Host "Saving the source vm '$($VmToImage)' as template to $($ImageName)" -ForegroundColor $CommandInfo
$Vm = Get-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage
$tags = (Get-AzResource -ResourceGroupName $VmResourceGroupName -Name $VmToImage -ResourceType "Microsoft.Compute/virtualMachines" -ErrorAction SilentlyContinue).Tags
$image = New-AzImageConfig -Location $AlyaLocation -SourceVirtualMachineId $Vm.ID -HyperVGeneration $AlyaAvdHypervisorVersion
New-AzImage -Image $image -ImageName $ImageName -ResourceGroupName $ImageResourceGroupName -ErrorAction Stop

# Checking key vault
Write-Host "Checking key vault" -ForegroundColor $CommandInfo
$KeyVault = Get-AzKeyVault -ResourceGroupName $KeyVaultResourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue
if (-Not $KeyVault)
{
    Write-Warning "Key Vault not found. Creating the Key Vault $KeyVaultName"
    $KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -Sku Standard -Tag @{displayName="Main Infrastructure Keyvault"}
    if (-Not $KeyVault)
    {
        Write-Error "Key Vault $KeyVaultName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$CompName = Make-PascalCase($AlyaCompanyNameShort)
$ImageHostCredentialAssetName = "$($VmToImage)AdminCredential"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ImageHostCredentialAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    Write-Warning "Key Vault secret not found. Creating the secret $ImageHostCredentialAssetName"
    $VMPassword = "$" + [Guid]::NewGuid().ToString() + "!"
    $VMPasswordSec = ConvertTo-SecureString $VMPassword -AsPlainText -Force
    $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ImageHostCredentialAssetName -SecretValue $VMPasswordSec
}
else
{
    $VMPasswordSec = $AzureKeyVaultSecret.SecretValue
}
Clear-Variable -Name VMPassword -Force -ErrorAction SilentlyContinue
Clear-Variable -Name AzureKeyVaultSecret -Force -ErrorAction SilentlyContinue

# Deleting source vm
Write-Host "Deleting source vm '$($VmToImage)'" -ForegroundColor $CommandInfo
Remove-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Force
Remove-AzDisk -ResourceGroupName $VmResourceGroupName -DiskName $Vm.StorageProfile.OsDisk.Name -Force
#$Vm = Import-CliXml -Path "$AlyaData\avd\image\$VmToImage.cliXml"

# Recreating source vm
Write-Host "Recreating source vm '$($VmToImage)'" -ForegroundColor $CommandInfo
$VMCredential = New-Object System.Management.Automation.PSCredential ("$($VmToImage)admin", $VMPasswordSec)
$netIfaceName = $Vm.NetworkProfile.NetworkInterfaces[0].Id.Substring($Vm.NetworkProfile.NetworkInterfaces[0].Id.LastIndexOf("/") + 1)
$netIface = Get-AzNetworkInterface -ResourceGroupName $VmResourceGroupName -Name $netIfaceName
if ($Vm.AvailabilitySetReference)
{
    #TODO -LicenseType $AlyaVmLicenseType if server and hybrid benefit
    $VmConfig = New-AzVMConfig -AvailabilitySetId $Vm.AvailabilitySetReference.Id -VMName $VmToImage -VMSize $Vm.HardwareProfile.VmSize
    $VmConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VmToImage -Credential $VMCredential
}
else
{
    #TODO -LicenseType $AlyaVmLicenseType if server and hybrid benefit
    $VmConfig = New-AzVMConfig -VMName $VmToImage -VMSize $Vm.HardwareProfile.VmSize
    $VmConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VmToImage -Credential $VMCredential
}
$image = Get-AzImage -ImageName $ImageName -ResourceGroupName $ImageResourceGroupName
$VmConfig | Set-AzVMSourceImage -Id $image.Id | Out-Null
$VmConfig | Add-AzVMNetworkInterface -Id $netIface.Id | Out-Null
$VmConfig | Set-AzVMBootDiagnostic -Enable -ResourceGroupName $DiagnosticResourceGroupName -StorageAccountName $DiagnosticStorageName | Out-Null
$VmConfig | Set-AzVMOSDisk -Name $VMDiskName -CreateOption FromImage -Caching ReadWrite -DiskSizeInGB $Vm.StorageProfile.OsDisk.DiskSizeGB | Out-Null
$newVm = New-AzVM -ResourceGroupName $VmResourceGroupName -Location $Vm.Location -VM $VmConfig -DisableBginfoExtension

# Setting tags
Write-Host "Setting tags" -ForegroundColor $CommandInfo
if (-Not $tags) { $tags = @{} }
if (-Not $tags.ContainsKey("displayName"))
{
    $tags["displayName"] = "AVD Server Image"
}
if (-Not $tags.ContainsKey("stopTime"))
{
    $tags["stopTime"] = $AlyaAvdStopTime
}
if (-Not $tags.ContainsKey("ownerEmail"))
{
    $tags["ownerEmail"] = $Context.Account.Id
}
Set-AzResource -ResourceGroupName $VmResourceGroupName -Name $VmToImage -ResourceType "Microsoft.Compute/VirtualMachines" -Tag $tags -Force

$tags = (Get-AzResource -ResourceGroupName $ImageResourceGroupName -Name $ImageName -ResourceType "Microsoft.Compute/images" -ErrorAction SilentlyContinue).Tags
if (-Not $tags) { $tags = @{} }
if (-Not $tags.ContainsKey("displayName"))
{
    $tags["displayName"] = "AVD Server Image"
}
if (-Not $tags.ContainsKey("ownerEmail"))
{
    $tags["ownerEmail"] = $Context.Account.Id
}
Set-AzResource -ResourceGroupName $ImageResourceGroupName -Name $ImageName -ResourceType "Microsoft.Compute/images" -Tag $tags -Force

# Stopping VM
Write-Host "Stopping VM" -ForegroundColor $CommandInfo
Stop-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Force

# Restoring locks on resource group
Write-Host "Restoring locks on resource group '$($VmResourceGroupName)'" -ForegroundColor $CommandInfo
foreach($actLock in $actLocks)
{
    if ($actLock.Properties.level -eq "CanNotDelete")
    {
        Write-Host "Adding lock $($actLock.Name)"
        $null = Set-AzResourceLock -ResourceGroupName $VmResourceGroupName -LockName $actLock.Name -LockLevel CanNotDelete -LockNotes $actLock.Properties.notes -Force
    }
}

<# In case, the image was not generalized, delete the VM and recreate it with:

$failedVmDisk = Get-AzDisk -ResourceGroupName $VmResourceGroupName -Name $Vm.StorageProfile.OsDisk.Name
$VmConfig = New-AzVMConfig -AvailabilitySetId $Vm.AvailabilitySetReference.Id -VMName $VmToImage -VMSize $Vm.HardwareProfile.VmSize -LicenseType "Windows_Server"
$VmConfig = Set-AzVMOSDisk -VM $VmConfig -ManagedDiskId $failedVmDisk.Id -CreateOption Attach -Windows
$VmConfig = Add-AzVMNetworkInterface -VM $VmConfig -Id $netIface.Id
$newVm = New-AzVM -ResourceGroupName $VmResourceGroupName -Location $Vm.Location -VM $VmConfig

#> 

#Stopping Transscript
Stop-Transcript
