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
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\bkp\image\Recreate-ImageClient-$($AlyaTimeString).log" | Out-Null

# Constants
$VmToImage = "$($AlyaNamingPrefix)avdi$($AlyaResIdAvdImageClient)"
$VmResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdImageResGrp)"
$ImageName = "$($VmToImage)_ImageClient"
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

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "ImageHost | Recreate-ImageClient | AZURE" -ForegroundColor $CommandInfo
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
        $tmp = $actLock | Remove-AzResourceLock -Force
    }
}

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

# Getting Image
Write-Host "Getting Image" -ForegroundColor $CommandInfo
$image = Get-AzImage -ResourceGroupName $VmResourceGroupName -ImageName $ImageName -ErrorAction SilentlyContinue
if (-Not $image)
{
    throw "Image not found"
}

# Recreating vm
$Vm = Get-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -ErrorAction SilentlyContinue
if ($vm)
{
    # Deleting source vm
    Write-Host "Deleting source vm '$($VmToImage)'" -ForegroundColor $CommandInfo
    $tags = (Get-AzResource -ResourceGroupName $VmResourceGroupName -Name $VmToImage -ErrorAction SilentlyContinue).Tags
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
        $VmConfig = New-AzVMConfig -AvailabilitySetId $Vm.AvailabilitySetReference.Id -VmName $VmToImage -VMSize $Vm.HardwareProfile.VmSize
        $VmConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VmToImage -Credential $VMCredential -ProvisionVMAgent
    }
    else
    {
        #TODO -LicenseType $AlyaVmLicenseType if server and hybrid benefit
        $VmConfig = New-AzVMConfig -VmName $VmToImage -VMSize $Vm.HardwareProfile.VmSize
        $VmConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VmToImage -Credential $VMCredential -ProvisionVMAgent
    }
    $image = Get-AzImage -ImageName $ImageName -ResourceGroupName $ImageResourceGroupName
    $VmConfig | Set-AzVMSourceImage -Id $image.Id | Out-Null
    $VmConfig | Add-AzVMNetworkInterface -Id $netIface.Id | Out-Null
    $VmConfig | Set-AzVMOSDisk -Name $VMDiskName -CreateOption FromImage -Caching ReadWrite -DiskSizeInGB $Vm.StorageProfile.OsDisk.DiskSizeGB
    $VmConfig | Set-AzVMBootDiagnostic -Enable -ResourceGroupName $DiagnosticResourceGroupName -StorageAccountName $DiagnosticStorageName
    $newVm = New-AzVM -ResourceGroupName $VmResourceGroupName -Location $Vm.Location -VM $VmConfig -DisableBginfoExtension

    # Setting tags
    Write-Host "Setting tags" -ForegroundColor $CommandInfo
    if (-Not $tags) { $tags = @{} }
    if (-Not $tags.ContainsKey("displayName"))
    {
        $tags["displayName"] = "AVD Client Image"
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
        $tags["displayName"] = "AVD Client Image"
    }
    if (-Not $tags.ContainsKey("ownerEmail"))
    {
        $tags["ownerEmail"] = $Context.Account.Id
    }
    Set-AzResource -ResourceGroupName $ImageResourceGroupName -Name $ImageName -ResourceType "Microsoft.Compute/images" -Tag $tags -Force
    #Set-AzResource -ResourceGroupName $ImageResourceGroupName -Name ($ImageName+$DateString) -ResourceType "Microsoft.Compute/images" -Tag $tags -Force
}
else
{
    $VMNicName = "$($VmToImage)nic1"
    $VMDiskName = "$($VmToImage)osdisk"

    # Checking vm nic
    Write-Host "Checking vm nic" -ForegroundColor $CommandInfo
    $VMNic = Get-AzNetworkInterface -ResourceGroupName $VmResourceGroupName -Name $VMNicName -ErrorAction SilentlyContinue
    if (-Not $VMNic)
    {
        throw "Not yet implemented"
        Write-Warning "VM nic not found. Creating the vm nic $VMNicName"
        $VMNic = New-AzNetworkInterface -ResourceGroupName $VmResourceGroupName -Name $VMNicName -Location $AlyaLocation -SubnetId $Subnet.Id -EnableAcceleratedNetworking:$false 
        Set-AzNetworkInterface -NetworkInterface $VMNic
    }
    #$VMNic.EnableAcceleratedNetworking = $false
    #Set-AzNetworkInterface -NetworkInterface $VMNic

    Write-Host "Recreating source vm '$($VmToImage)'" -ForegroundColor $CommandInfo
    $VMCredential = New-Object System.Management.Automation.PSCredential ("$($VmToImage)admin", $VMPasswordSec)
    $VMConfig = New-AzVMConfig -VmName $VmToImage -VMSize "Standard_D4s_v3" #-LicenseType PAYG
    $VMConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VmToImage -Credential $VMCredential -ProvisionVMAgent
    $image = Get-AzImage -ImageName $ImageName -ResourceGroupName $ImageResourceGroupName
    $VmConfig | Set-AzVMSourceImage -Id $image.Id
    $VMConfig | Add-AzVMNetworkInterface -Id $VMNic.Id
    $VMConfig | Set-AzVMOSDisk -Name $VMDiskName -CreateOption FromImage -Caching ReadWrite -DiskSizeInGB 128
    $VMConfig | Set-AzVMBootDiagnostic -Enable -ResourceGroupName $DiagnosticResourceGroupName -StorageAccountName $DiagnosticStorageName
    $tmp = New-AzVM -ResourceGroupName $VmResourceGroupName -Location $AlyaLocation -VM $VMConfig -DisableBginfoExtension
}

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

#Stopping Transscript
Stop-Transcript
