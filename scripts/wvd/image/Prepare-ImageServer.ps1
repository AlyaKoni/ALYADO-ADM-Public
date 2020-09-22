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
    13.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\image\Prepare-ImageServer-$($AlyaTimeString).log" | Out-Null

# Constants
$VmToImage = ($AlyaNamingPrefix + "serv041")
$VmResourceGroupName = ($AlyaNamingPrefix + "resg040")
$ImageName = ($VmToImage + "_ImageServer")
$ImageResourceGroupName = ($AlyaNamingPrefix + "resg040")
$DiagnosticRessourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$DiagnosticStorageName = "$($AlyaNamingPrefix)strg$($AlyaResIdDiagnosticStorage)"
$KeyVaultRessourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$DateString = (Get-Date -Format "_yyyyMMdd_HHmmss")
$VMDiskName = "$($AlyaNamingPrefix)serv041osdisk"

Write-Host "Please prepare first the source host ($VmToImage) like described in PrepareVmImage.pdf"
Write-Host '  - Start a PowerShell as Administrator'
Write-Host '  - Run command: & "$Env:SystemRoot\system32\sysprep\sysprep.exe" /generalize /oobe /shutdown'
Write-Host '  - Wait until the vm has stopped state'
<#
Bei Fehler Logdatei untersuchen:
%WINDIR%\System32\Sysprep\Panther\setupact.log
Unter Umständen müssen Packages entfernt werden. Siehe hierzu cleanImage.ps1
#>
pause

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

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
    Write-Error -Message "Can't get Az context! Not logged in?"
    Exit 1
}

# Checking ressource group
Write-Host "Checking vm ressource group" -ForegroundColor $CommandInfo
$ResGrpVm = Get-AzResourceGroup -Name $VmResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrpVm)
{
    Write-Warning -Message "Ressource Group not found. Creating the Ressource Group $VmResourceGroupName"
    $ResGrpVm = New-AzResourceGroup -Name $VmResourceGroupName -Location $AlyaLocation -Tag @{displayName="Image Host";ownerEmail=$Context.Account.Id}
}

# Checking ressource group
Write-Host "Checking image ressource group" -ForegroundColor $CommandInfo
$ResGrpImage = Get-AzResourceGroup -Name $ImageResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrpImage)
{
    Write-Warning -Message "Ressource Group not found. Creating the Ressource Group $ImageResourceGroupName"
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
        $tmp = $actLock | Remove-AzResourceLock -Force
    }
}

# Checking if source vm is stopped
Write-Host "Checking if source vm is stopped" -ForegroundColor $CommandInfo
$Vm = Get-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Status -ErrorAction SilentlyContinue
if (-Not $Vm)
{
    throw "VM not found. Please create the VM $VmToImage"
}
$isStopped = $false
foreach ($VmStat in $Vm.Statuses)
{ 
    if($VmStat.Code -eq "PowerState/stopped" -or $VmStat.Code -eq "PowerState/deallocated")
    {
        $isStopped = $true
        break
    }
}
if (-not $isStopped)
{
    throw "Vm is not in stopped state!"
}

# Preparing the source vm
Write-Host "Preparing the source vm '$($VmToImage)'" -ForegroundColor $CommandInfo
Stop-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Force
Set-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Generalized  

# TODO delete existing image (for update)
Write-Host "Deleting existing image if present" -ForegroundColor $CommandInfo
$image = Get-AzImage -ResourceGroupName $VmResourceGroupName -ImageName $ImageName -ErrorAction SilentlyContinue
if ($image)
{
    Write-Warning -Message "Deleting existing image $ImageName"
    Remove-AzImage -ResourceGroupName $VmResourceGroupName -ImageName $ImageName -Force
}

# Saving the source vm as image
Write-Host "Saving the source vm '$($VmToImage)' as template to $($ImageName)" -ForegroundColor $CommandInfo
$Vm = Get-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage
$tags = (Get-AzResource -ResourceGroupName $VmResourceGroupName -Name $VmToImage -ErrorAction SilentlyContinue).Tags
$image = New-AzImageConfig -Location $AlyaLocation -SourceVirtualMachineId $Vm.ID
New-AzImage -Image $image -ImageName $ImageName -ResourceGroupName $ImageResourceGroupName -ErrorAction Stop
New-AzImage -Image $image -ImageName ($ImageName+$DateString) -ResourceGroupName $ImageResourceGroupName -ErrorAction Stop

# Checking key vault
Write-Host "Checking key vault" -ForegroundColor $CommandInfo
$KeyVault = Get-AzKeyVault -ResourceGroupName $KeyVaultRessourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue
if (-Not $KeyVault)
{
    Write-Warning -Message "Key Vault not found. Creating the Key Vault $KeyVaultName"
    $KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $RessourceGroupName -Location $AlyaLocation -Sku Standard -Tag @{displayName="Main Infrastructure Keyvault"}
    if (-Not $KeyVault)
    {
        Write-Error -Message "Key Vault $KeyVaultName creation failed. Please fix and start over again"
        Exit 1
    }
}

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$CompName = Make-PascalCase($AlyaCompanyNameShort)
$ImageHostCredentialAssetName = "$($CompName)ImageHostAdminCredential"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ImageHostCredentialAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    Write-Warning -Message "Key Vault secret not found. Creating the secret $ImageHostCredentialAssetName"
    $VMPassword = "$" + [Guid]::NewGuid().ToString() + "!"
    $VMPasswordSec = ConvertTo-SecureString $VMPassword -AsPlainText -Force
    $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ImageHostCredentialAssetName -SecretValue $VMPasswordSec
}
else
{
    $VMPassword = $AzureKeyVaultSecret.SecretValueText
    $VMPasswordSec = ConvertTo-SecureString $VMPassword -AsPlainText -Force
}

# Deleting source vm
Write-Host "Deleting source vm '$($VmToImage)'" -ForegroundColor $CommandInfo
Remove-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Force
Remove-AzDisk -ResourceGroupName $VmResourceGroupName -DiskName $Vm.StorageProfile.OsDisk.Name -Force

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
$VmConfig | Set-AzVMBootDiagnostic -Enable -ResourceGroupName $DiagnosticRessourceGroupName -StorageAccountName $DiagnosticStorageName | Out-Null
$VmConfig | Set-AzVMOSDisk -Name $VMDiskName -CreateOption FromImage -Caching ReadWrite -DiskSizeInGB 127 | Out-Null
$newVm = New-AzVM -ResourceGroupName $VmResourceGroupName -Location $Vm.Location -VM $VmConfig -DisableBginfoExtension

# Setting tags
Write-Host "Setting tags" -ForegroundColor $CommandInfo
if (-Not $tags)
{
    $tags += @{displayName="Image Host"}
    $tags += @{stopTime=$AlyaWvdStopTime}
    $tags += @{ownerEmail=$Context.Account.Id}
}
Set-AzResource -ResourceGroupName $VmResourceGroupName -Name $VmToImage -ResourceType "Microsoft.Compute/VirtualMachines" -Tag $tags -Force

$tags = (Get-AzResource -ResourceGroupName $ImageResourceGroupName -Name $ImageName -ErrorAction SilentlyContinue).Tags
$tags += @{displayName="WVD Image"}
$tags += @{ownerEmail=$Context.Account.Id}
Set-AzResource -ResourceGroupName $ImageResourceGroupName -Name $ImageName -ResourceType "Microsoft.Compute/images" -Tag $tags -Force
Set-AzResource -ResourceGroupName $ImageResourceGroupName -Name ($ImageName+$DateString) -ResourceType "Microsoft.Compute/images" -Tag $tags -Force

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
        $tmp = Set-AzResourceLock -ResourceGroupName $VmResourceGroupName -LockName $actLock.Name -LockLevel CanNotDelete -LockNotes $actLock.Properties.notes -Force
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