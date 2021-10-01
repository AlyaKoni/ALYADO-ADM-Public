#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    03.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Create-AdVms-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAdResGrp)"
$AvSetName = "$($AlyaNamingPrefix)avst001serv$($AlyaResIdAdSrv1)serv$($AlyaResIdAdSrv2)"
$VMName1 = "$($AlyaNamingPrefix)serv$($AlyaResIdAdSrv1)"
$VMName2 = "$($AlyaNamingPrefix)serv$($AlyaResIdAdSrv2)"
$VMNicName1 = "$($AlyaNamingPrefix)serv$($AlyaResIdAdSrv1)nic1"
$VMNicName2 = "$($AlyaNamingPrefix)serv$($AlyaResIdAdSrv2)nic1"
$VMDiskName1 = "$($AlyaNamingPrefix)serv$($AlyaResIdAdSrv1)osdisk"
$VMDiskName2 = "$($AlyaNamingPrefix)serv$($AlyaResIdAdSrv2)osdisk"
$DiagnosticResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$DiagnosticStorageName = "$($AlyaNamingPrefix)strg$($AlyaResIdDiagnosticStorage)"
$NetworkResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainNetwork)"
$VirtualNetworkName = "$($AlyaNamingPrefix)vnet$($AlyaResIdVirtualNetwork)"
$VMSubnetName = "$($VirtualNetworkName)snet$($AlyaResIdAdSNet)"
$KeyVaultResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$RecoveryVaultName = "$($AlyaNamingPrefix)recv$($AlyaResIdRecoveryVault)"
$BackupPolicyName = "NightlyPolicy"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Create-AdVms | AZURE" -ForegroundColor $CommandInfo
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
    $ResGrp = New-AzResourceGroup -Name $ResourceGroupName -Location $AlyaLocation -Tag @{displayName="Active Directory and DNS";ownerEmail=$Context.Account.Id}
}

# Checking ressource group vnet
Write-Host "Checking ressource group vnet" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $NetworkResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    throw "Ressource Group not found. Pleas ecreate the Ressource Group $NetworkResourceGroupName"
}

# Checking virtual network
Write-Host "Checking virtual network" -ForegroundColor $CommandInfo
$VNet = Get-AzVirtualNetwork -ResourceGroupName $NetworkResourceGroupName -Name $VirtualNetworkName -ErrorAction SilentlyContinue
if (-Not $VNet)
{
    throw "Virtual network not found. Please create the virtual network $VirtualNetworkName"
}

# Checking network subnets
Write-Host "Checking network subnets" -ForegroundColor $CommandInfo
$Subnet = $VNet.Subnets | where { $_.Name -eq $VMSubnetName }
if (-Not $Subnet)
{
    throw "Virtual network subnet not found. Please create the virtual network subnet $VMSubnetName"
}
$Subnet = Get-AzVirtualNetworkSubnetConfig -Name $VMSubnetName -VirtualNetwork $VNet

# Checking storage account
Write-Host "Checking diag storage account" -ForegroundColor $CommandInfo
$StrgAccount = Get-AzStorageAccount -ResourceGroupName $DiagnosticResourceGroupName -Name $DiagnosticStorageName -ErrorAction SilentlyContinue
if (-Not $StrgAccount)
{
    throw "Storage account not found. Please create the diag storage account $StorageAccountName"
}

# Checking vm nic1
Write-Host "Checking vm nic1" -ForegroundColor $CommandInfo
$VMNic1 = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $VMNicName1 -ErrorAction SilentlyContinue
if (-Not $VMNic1)
{
    Write-Warning "VM nic not found. Creating the vm nic $VMNicName1"
    $VMNic1 = New-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $VMNicName1 -Location $AlyaLocation -SubnetId $Subnet.Id -EnableAcceleratedNetworking:$false 
    $VMNic1.IpConfigurations[0].PrivateIpAllocationMethod = "Static"
    Set-AzNetworkInterface -NetworkInterface $VMNic1
}

# Checking vm nic2
Write-Host "Checking vm nic2" -ForegroundColor $CommandInfo
$VMNic2 = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $VMNicName2 -ErrorAction SilentlyContinue
if (-Not $VMNic2)
{
    Write-Warning "VM nic not found. Creating the vm nic $VMNicName2"
    $VMNic2 = New-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $VMNicName2 -Location $AlyaLocation -SubnetId $Subnet.Id -EnableAcceleratedNetworking:$false 
    $VMNic2.IpConfigurations[0].PrivateIpAllocationMethod = "Static"
    Set-AzNetworkInterface -NetworkInterface $VMNic2
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
$AdCredentialAssetName = "$($CompName)AdAdminCredential"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AdCredentialAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    Write-Warning "Key Vault secret not found. Creating the secret $AdCredentialAssetName"
    $VMPassword = "$" + [Guid]::NewGuid().ToString() + "!"
    $VMPasswordSec = ConvertTo-SecureString $VMPassword -AsPlainText -Force
    $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AdCredentialAssetName -SecretValue $VMPasswordSec
}
else
{
    $VMPasswordSec = $AzureKeyVaultSecret.SecretValue
}
Clear-Variable -Name VMPassword -Force -ErrorAction SilentlyContinue
Clear-Variable -Name AzureKeyVaultSecret -Force -ErrorAction SilentlyContinue

# Checking recovery vault
Write-Host "Checking recovery vault" -ForegroundColor $CommandInfo
$RecVault = Get-AzRecoveryServicesVault -ResourceGroupName $KeyVaultResourceGroupName -Name $RecoveryVaultName -ErrorAction SilentlyContinue
if (-Not $RecVault)
{
    throw "Recovery vault not found. Please create the recovery vault $RecoveryVaultName"
}

# Checking backup policy
Write-Host "Checking backup policy" -ForegroundColor $CommandInfo
$BkpPol = Get-AzRecoveryServicesBackupProtectionPolicy -VaultId $RecVault.ID -Name $BackupPolicyName -ErrorAction SilentlyContinue
if (-Not $BkpPol)
{
    throw "Backup policy not found. Please create the backup policy $BackupPolicyName"
}

# Checking availability set
Write-Host "Checking availability set" -ForegroundColor $CommandInfo
$AvSet = Get-AzAvailabilitySet -ResourceGroupName $ResourceGroupName -Name $AvSetName -ErrorAction SilentlyContinue
if (-Not $AvSet)
{
    Write-Warning "Availability set not found. Creating the availability set $AvSetName"
    $AvSet = New-AzAvailabilitySet -ResourceGroupName $ResourceGroupName -Name $AvSetName -Location $AlyaLocation -PlatformFaultDomainCount 2 -PlatformUpdateDomainCount 2 -Sku Aligned
}

# Checking ad vm 1
Write-Host "Checking ad vm 1" -ForegroundColor $CommandInfo
$AdVm1 = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName1 -ErrorAction SilentlyContinue
if (-Not $AdVm1)
{
    Write-Warning "AD vm not found. Creating the ad vm $VMName1"
    #Get-AzVMSize -Location $AlyaLocation | where { $_.Name -like "Standard_A*" }
    #Get-AzVMImagePublisher -Location $AlyaLocation
    #Get-AzVMImageOffer -Location $AlyaLocation -PublisherName "MicrosoftWindowsServer"
    $VMCredential = New-Object System.Management.Automation.PSCredential ("$($VMName1)admin", $VMPasswordSec)
    #TODO -LicenseType $AlyaVmLicenseType if server and hybrid benefit
    $VMConfig = New-AzVMConfig -VMName $VMName1 -VMSize "Standard_A1_v2" -AvailabilitySetId $AvSet.Id #-LicenseType PAYG
    $VMConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VMName1 -Credential $VMCredential -ProvisionVMAgent -EnableAutoUpdate -TimeZone $AlyaTimeZone | Out-Null
    $VMConfig | Set-AzVMSourceImage -PublisherName "MicrosoftWindowsServer" -Offer "WindowsServer" -Skus "2019-Datacenter" -Version latest | Out-Null
    $VMConfig | Add-AzVMNetworkInterface -Id $VMNic1.Id | Out-Null
    $VMConfig | Set-AzVMOSDisk -Name $VMDiskName1 -CreateOption FromImage -Caching ReadWrite -DiskSizeInGB 127 | Out-Null
    $VMConfig | Set-AzVMBootDiagnostic -Enable -ResourceGroupName $DiagnosticResourceGroupName -StorageAccountName $DiagnosticStorageName | Out-Null
    $tmp = New-AzVM -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -VM $VMConfig
    $AdVm1 = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName1
    $tmp = Set-AzResource -ResourceId $AdVm1.Id -Tag @{displayName="Active Directory First";ownerEmail=$Context.Account.Id} -Force
}

# Checking ad vm 2
Write-Host "Checking ad vm 2" -ForegroundColor $CommandInfo
$AdVm2 = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName2 -ErrorAction SilentlyContinue
if (-Not $AdVm2)
{
    Write-Warning "AD vm not found. Creating the ad vm $VMName2"
    #Get-AzVMSize -Location $AlyaLocation | where { $_.Name -like "Standard_A*" }
    #Get-AzVMImagePublisher -Location $AlyaLocation
    #Get-AzVMImageOffer -Location $AlyaLocation -PublisherName "MicrosoftWindowsServer"
    $VMCredential = New-Object System.Management.Automation.PSCredential ("$($VMName2)admin", $VMPasswordSec)
    #TODO -LicenseType $AlyaVmLicenseType if server and hybrid benefit
    $VMConfig = New-AzVMConfig -VMName $VMName2 -VMSize "Standard_A1_v2" -AvailabilitySetId $AvSet.Id #-LicenseType PAYG
    $VMConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VMName2 -Credential $VMCredential -ProvisionVMAgent -EnableAutoUpdate -TimeZone $AlyaTimeZone | Out-Null
    $VMConfig | Set-AzVMSourceImage -PublisherName "MicrosoftWindowsServer" -Offer "WindowsServer" -Skus "2019-Datacenter" -Version latest | Out-Null
    $VMConfig | Add-AzVMNetworkInterface -Id $VMNic2.Id | Out-Null
    $VMConfig | Set-AzVMOSDisk -Name $VMDiskName2 -CreateOption FromImage -Caching ReadWrite -DiskSizeInGB 127 | Out-Null
    $VMConfig | Set-AzVMBootDiagnostic -Enable -ResourceGroupName $DiagnosticResourceGroupName -StorageAccountName $DiagnosticStorageName | Out-Null
    $tmp = New-AzVM -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -VM $VMConfig
    $AdVm2 = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName2
    $tmp = Set-AzResource -ResourceId $AdVm2.Id -Tag @{displayName="Active Directory Second";ownerEmail=$Context.Account.Id} -Force
}

# Checking anti malware vm 1 extension
Write-Host "Checking anti malware vm 1 extension" -ForegroundColor $CommandInfo
$VmExtName1 = "$($VMName1)AntiMalware"
$VmExt1 = Get-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName1 -Name $VmExtName1 -ErrorAction SilentlyContinue
if (-Not $VmExt1)
{
    Write-Warning "AntiMalware extension on vm 1 not found. Installing AntiMalware on ad vm $VMName1"
    #Get-AzVmImagePublisher -Location $AlyaLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select Type, Version
    #Get-Command Set-Az*Extension* -Module Az.Compute     
    #$Extension = Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | select -last 1
    $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | %{ new-object System.Version ($_.Version) } | Sort | Select -Last 1).ToString()
    $typeHandlerVerMjandMn = $typeHandlerVer.split(".")
    $typeHandlerVerMjandMn = $typeHandlerVerMjandMn[0] + "." + $typeHandlerVerMjandMn[1]
    $amsettings = @'
        {
            "AntimalwareEnabled": true,
            "RealtimeProtectionEnabled": true,
            "ScheduledScanSettings": {
                "isEnabled": true,
                "day": 7,
                "time": 120,
                "scanType": "Quick"
            },
            "Exclusions": {
                "Extensions": ".log;.ldf",   
                "Paths": "D:\\IISlogs;D:\\DatabaseLogs",
                "Processes": "mssence.svc"
            }
        }
'@
    $VmExt1 = Set-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName1 -Location $AlyaLocation `
        -Publisher "Microsoft.Azure.Security" -ExtensionType "IaaSAntimalware" -Name $VmExtName1 `
        -SettingString $amsettings -TypeHandlerVersion $typeHandlerVerMjandMn
}

# Checking anti malware vm 2 extension
Write-Host "Checking anti malware vm 2 extension" -ForegroundColor $CommandInfo
$VmExtName2 = "$($VMName2)AntiMalware"
$VmExt2 = Get-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName2 -Name $VmExtName2 -ErrorAction SilentlyContinue
if (-Not $VmExt2)
{
    Write-Warning "AntiMalware extension on vm 2 not found. Installing AntiMalware on ad vm $VMName2"
    #Get-AzVmImagePublisher -Location $AlyaLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select Type, Version
    #Get-Command Set-Az*Extension* -Module Az.Compute     
    #$Extension = Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | select -last 1
    $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | %{ new-object System.Version ($_.Version) } | Sort | Select -Last 1).ToString()
    $typeHandlerVerMjandMn = $typeHandlerVer.split(".")
    $typeHandlerVerMjandMn = $typeHandlerVerMjandMn[0] + "." + $typeHandlerVerMjandMn[1]
    $amsettings = @'
        {
            "AntimalwareEnabled": true,
            "RealtimeProtectionEnabled": true,
            "ScheduledScanSettings": {
                "isEnabled": true,
                "day": 7,
                "time": 120,
                "scanType": "Quick"
            },
            "Exclusions": {
                "Extensions": ".log;.ldf",   
                "Paths": "D:\\IISlogs;D:\\DatabaseLogs",
                "Processes": "mssence.svc"
            }
        }
'@
    $VmExt2 = Set-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName2 -Location $AlyaLocation `
        -Publisher "Microsoft.Azure.Security" -ExtensionType "IaaSAntimalware" -Name $VmExtName2 `
        -SettingString $amsettings -TypeHandlerVersion $typeHandlerVerMjandMn
}

# Checking vm 1 backup
Write-Host "Checking vm 1 backup" -ForegroundColor $CommandInfo
$VmBkpItemContainer1 = Get-AzRecoveryServicesBackupContainer -VaultId $RecVault.ID -ContainerType "AzureVM" -Status "Registered" -FriendlyName $VMName1 -ErrorAction SilentlyContinue
if (-Not $VmBkpItemContainer1)
{
    Write-Warning "VM 1 backup not yet enabled. Eanbling backup on ad vm $VMName1"
    $VmBkpItemContainer1 = Enable-AzRecoveryServicesBackupProtection -ResourceGroupName $ResourceGroupName -Name $VMName1 -Policy $BkpPol -VaultId $RecVault.ID
}
else
{
    $BkpItem1 = Get-AzRecoveryServicesBackupItem -Container $VmBkpItemContainer1 -WorkloadType "AzureVM"
    if ($BkpItem1.DeleteState -eq "ToBeDeleted" -or $BkpItem1.ProtectionState -eq "ProtectionStopped")
    {
        Write-Warning "Please resume backup in portal with $($BkpPol.Name) policy!"
    }
}

# Checking vm 2 backup
Write-Host "Checking vm 2 backup" -ForegroundColor $CommandInfo
$VmBkpItemContainer2 = Get-AzRecoveryServicesBackupContainer -VaultId $RecVault.ID -ContainerType "AzureVM" -Status "Registered" -FriendlyName $VMName2 -ErrorAction SilentlyContinue
if (-Not $VmBkpItemContainer2)
{
    Write-Warning "VM 2 backup not yet enabled. Eanbling backup on ad vm $VMName2"
    $VmBkpItemContainer2 = Enable-AzRecoveryServicesBackupProtection -ResourceGroupName $ResourceGroupName -Name $VMName2 -Policy $BkpPol -VaultId $RecVault.ID
}
else
{
    $BkpItem2 = Get-AzRecoveryServicesBackupItem -Container $VmBkpItemContainer2 -WorkloadType "AzureVM"
    if ($BkpItem2.DeleteState -eq "ToBeDeleted" -or $BkpItem2.ProtectionState -eq "ProtectionStopped")
    {
        Write-Warning "Please resume backup in portal with $($BkpPol.Name) policy!"
    }
}

#Stopping Transscript
Stop-Transcript