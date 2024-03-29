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
    02.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Create-JumpHost-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdJumpHostResGrp)"
$VMName = "$($AlyaNamingPrefix)serv$($AlyaResIdJumpHost)"
$VMPublicIpName = "$($AlyaNamingPrefix)serv$($AlyaResIdJumpHost)pip1"
$VMNicName = "$($AlyaNamingPrefix)serv$($AlyaResIdJumpHost)nic1"
$VMDiskName = "$($AlyaNamingPrefix)serv$($AlyaResIdJumpHost)osdisk"
$DiagnosticResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$DiagnosticStorageName = "$($AlyaNamingPrefix)strg$($AlyaResIdDiagnosticStorage)"
$NetworkResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainNetwork)"
$VirtualNetworkName = "$($AlyaNamingPrefix)vnet$($AlyaResIdVirtualNetwork)"
$VMSubnetName = "$($VirtualNetworkName)snet$($AlyaResIdJumpHostSNet)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdJumpHostResGrp)"
$RecoveryVaultName = "$($AlyaNamingPrefix)recv$($AlyaResIdRecoveryVault)"
$RecoveryVaultResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$BackupPolicyName = $AlyaJumpHostBackupPolicy

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Network"
Install-ModuleIfNotInstalled "Az.Storage"
Install-ModuleIfNotInstalled "Az.KeyVault"
Install-ModuleIfNotInstalled "Az.RecoveryServices"
Install-ModuleIfNotInstalled "Az.Compute"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "JumpHost | Create-JumpHost | AZURE" -ForegroundColor $CommandInfo
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
    $ResGrp = New-AzResourceGroup -Name $ResourceGroupName -Location $AlyaLocation -Tag @{displayName="Jump Host";ownerEmail=$Context.Account.Id}
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
$Subnet = $VNet.Subnets | Where-Object { $_.Name -eq $VMSubnetName }
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

# Checking public ip
Write-Host "Checking public ip" -ForegroundColor $CommandInfo
$PublicIp = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $VMPublicIpName -ErrorAction SilentlyContinue
if (-Not $PublicIp)
{
    Write-Warning "Public ip not found. Creating the public ip $VMPublicIpName"
    $PublicIp = New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $VMPublicIpName -Location $AlyaLocation -DomainNameLabel $VMName -Sku Basic -AllocationMethod Dynamic -IpAddressVersion IPv4
}

# Checking vm nic
Write-Host "Checking vm nic" -ForegroundColor $CommandInfo
$VMNic = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $VMNicName -ErrorAction SilentlyContinue
if (-Not $VMNic)
{
    Write-Warning "VM nic not found. Creating the vm nic $VMNicName"
    $VMNic = New-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $VMNicName -Location $AlyaLocation -SubnetId $Subnet.Id -PublicIpAddressId $PublicIp.Id -EnableAcceleratedNetworking:$AlyaJumpHostAcceleratedNetworking
    $VMNic.IpConfigurations[0].PrivateIpAllocationMethod = "Static"
    Set-AzNetworkInterface -NetworkInterface $VMNic
}

# Checking key vault
Write-Host "Checking key vault" -ForegroundColor $CommandInfo
$KeyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue
if (-Not $KeyVault)
{
    Write-Warning "Key Vault not found. Creating the Key Vault $KeyVaultName"
    $KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -Sku Standard
    if (-Not $KeyVault)
    {
        Write-Error "Key Vault $KeyVaultName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Setting own key vault access
Write-Host "Setting own key vault access" -ForegroundColor $CommandInfo
$user = Get-AzAdUser -UserPrincipalName $Context.Account.Id
Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $user.Id -PermissionsToCertificates "All" -PermissionsToSecrets "All" -PermissionsToKeys "All" -PermissionsToStorage "All"

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$JumpHostCredentialAssetName = "$($VMName)adminCredentials"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $JumpHostCredentialAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    Write-Warning "Key Vault secret not found. Creating the secret $JumpHostCredentialAssetName"
    $VMPassword = "$" + [Guid]::NewGuid().ToString() + "!"
    $VMPasswordSec = ConvertTo-SecureString $VMPassword -AsPlainText -Force
    $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $JumpHostCredentialAssetName -SecretValue $VMPasswordSec
}
else
{
    $VMPasswordSec = $AzureKeyVaultSecret.SecretValue
}
Clear-Variable -Name VMPassword -Force -ErrorAction SilentlyContinue
Clear-Variable -Name AzureKeyVaultSecret -Force -ErrorAction SilentlyContinue

# Checking recovery vault
if ($AlyaJumpHostBackupEnabled)
{
    Write-Host "Checking recovery vault" -ForegroundColor $CommandInfo
    $RecVault = Get-AzRecoveryServicesVault -ResourceGroupName $RecoveryVaultResourceGroupName -Name $RecoveryVaultName -ErrorAction SilentlyContinue
    if (-Not $RecVault)
    {
        throw "Recovery vault not found. Please create the recovery vault $RecoveryVaultName"
    }
}

# Checking backup policy
if ($AlyaJumpHostBackupEnabled)
{
    Write-Host "Checking backup policy" -ForegroundColor $CommandInfo
    $BkpPol = Get-AzRecoveryServicesBackupProtectionPolicy -VaultId $RecVault.ID -Name $BackupPolicyName -ErrorAction SilentlyContinue
    if (-Not $BkpPol)
    {
        throw "Backup policy not found. Please create the backup policy $BackupPolicyName"
    }
}

# Checking jump host vm
Write-Host "Checking jump host vm" -ForegroundColor $CommandInfo
$JumpHostVm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction SilentlyContinue
if (-Not $JumpHostVm)
{
    Write-Warning "Jump host vm not found. Creating the jump host vm $VMName"
    #Get-AzVMSize -Location $AlyaLocation | Where-Object { $_.Name -like "Standard_D4s*" }
    #Get-AzVMImagePublisher -Location $AlyaLocation
    #Get-AzVMImageOffer -Location $AlyaLocation -PublisherName "MicrosoftWindowsServer"
    $VMCredential = New-Object System.Management.Automation.PSCredential ("$($VMName)admin", $VMPasswordSec)
    $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $AlyaJumpHostSKU -LicenseType $AlyaVMLicenseTypeServer
    $VMConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VMName -Credential $VMCredential -ProvisionVMAgent -EnableAutoUpdate -TimeZone $AlyaTimeZone | Out-Null
    $VMConfig | Set-AzVMSourceImage -PublisherName "MicrosoftWindowsServer" -Offer "WindowsServer" -Skus $AlyaJumpHostEdition -Version latest | Out-Null
    $VMConfig | Add-AzVMNetworkInterface -Id $VMNic.Id | Out-Null
    $VMConfig | Set-AzVMOSDisk -Name $VMDiskName -CreateOption FromImage -Caching ReadWrite -DiskSizeInGB 127 | Out-Null
    $VMConfig | Set-AzVMBootDiagnostic -Enable -ResourceGroupName $DiagnosticResourceGroupName -StorageAccountName $DiagnosticStorageName | Out-Null
    $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -VM $VMConfig
    $JumpHostVm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
    $null = Set-AzResource -ResourceId $JumpHostVm.Id -Tag @{displayName="Jump Host";ownerEmail=$Context.Account.Id} -ApiVersion "2022-03-01" -Force
}

# Checking anti malware vm extension
Write-Host "Checking anti malware vm extension" -ForegroundColor $CommandInfo
$VmExtName = "$($VMName)AntiMalware"
$VmExt = Get-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name $VmExtName -ErrorAction SilentlyContinue
if (-Not $VmExt)
{
    Write-Warning "AntiMalware extension on vm not found. Installing AntiMalware on jump host vm $VMName"
    #Get-AzVmImagePublisher -Location $AlyaLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select-Object Type, Version
    #$Extension = Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | Select-Object -last 1
    $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | %{ new-object System.Version ($_.Version) } | Sort | Select-Object -Last 1).ToString()
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
    $VmExt = Set-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Location $AlyaLocation `
        -Publisher "Microsoft.Azure.Security" -ExtensionType "IaaSAntimalware" -Name $VmExtName `
        -SettingString $amsettings -TypeHandlerVersion $typeHandlerVerMjandMn
}

# Checking vm backup
if ($AlyaJumpHostBackupEnabled)
{
    Write-Host "Checking vm backup" -ForegroundColor $CommandInfo
    $VmBkpItemContainer = Get-AzRecoveryServicesBackupContainer -VaultId $RecVault.ID -ContainerType "AzureVM" -Status "Registered" -FriendlyName $VMName -ErrorAction SilentlyContinue
    if (-Not $VmBkpItemContainer)
    {
        Write-Warning "VM backup not yet enabled. Eanbling backup on jump host vm $VMName"
        $VmBkpItemContainer = Enable-AzRecoveryServicesBackupProtection -ResourceGroupName $ResourceGroupName -Name $VMName -Policy $BkpPol -VaultId $RecVault.ID
    }
    else
    {
        $BkpItem = Get-AzRecoveryServicesBackupItem -Container $VmBkpItemContainer -WorkloadType "AzureVM"
        if ($BkpItem.DeleteState -eq "ToBeDeleted" -or $BkpItem.ProtectionState -eq "ProtectionStopped")
        {
            Write-Warning "Please resume backup in portal with $($BkpPol.Name) policy!"
        }
    }
}

Write-Host "Setting tags on vm" -ForegroundColor $CommandInfo
$vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
$tags = @{}
$tags += @{displayName="Jump Host"}
if (-Not [string]::IsNullOrEmpty($AlyaJumpHostStartTime))
{
    $tags += @{startTime=$AlyaJumpHostStartTime}
}
if (-Not [string]::IsNullOrEmpty($AlyaJumpHostStopTime))
{
    $tags += @{stopTime=$AlyaJumpHostStopTime}
}
$tags += @{ownerEmail=$Context.Account.Id}
$null = Set-AzResource -ResourceId $vm.Id -Tag $tags -ApiVersion "2022-03-01" -Force

#TODO Domain Join

#Stopping Transscript
Stop-Transcript
