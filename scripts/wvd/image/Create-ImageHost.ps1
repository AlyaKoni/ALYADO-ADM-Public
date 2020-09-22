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
    11.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Create-ImageHost-$($AlyaTimeString).log" | Out-Null

# Constants
$RessourceGroupName = "$($AlyaNamingPrefix)resg040"
$VMName = "$($AlyaNamingPrefix)serv040"
$VMNicName = "$($AlyaNamingPrefix)serv040nic1"
$VMDiskName = "$($AlyaNamingPrefix)serv040osdisk"
$DiagnosticRessourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$DiagnosticStorageName = "$($AlyaNamingPrefix)strg$($AlyaResIdDiagnosticStorage)"
$NetworkRessourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainNetwork)"
$VirtualNetworkName = "$($AlyaNamingPrefix)vnet$($AlyaResIdVirtualNetwork)"
$VMSubnetName = "$($VirtualNetworkName)snet05"
$KeyVaultRessourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "ImageHost | Create-ImageHost | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error -Message "Can't get Az context! Not logged in?"
    Exit 1
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $RessourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning -Message "Ressource Group not found. Creating the Ressource Group $RessourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $RessourceGroupName -Location $AlyaLocation -Tag @{displayName="Image Host";ownerEmail=$Context.Account.Id}
}

# Checking virtual network
Write-Host "Checking virtual network" -ForegroundColor $CommandInfo
$VNet = Get-AzVirtualNetwork -ResourceGroupName $NetworkRessourceGroupName -Name $VirtualNetworkName -ErrorAction SilentlyContinue
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
$StrgAccount = Get-AzStorageAccount -ResourceGroupName $DiagnosticRessourceGroupName -Name $DiagnosticStorageName -ErrorAction SilentlyContinue
if (-Not $StrgAccount)
{
    throw "Storage account not found. Please create the diag storage account $StorageAccountName"
}

# Checking vm nic
Write-Host "Checking vm nic" -ForegroundColor $CommandInfo
$VMNic = Get-AzNetworkInterface -ResourceGroupName $RessourceGroupName -Name $VMNicName -ErrorAction SilentlyContinue
if (-Not $VMNic)
{
    Write-Warning -Message "VM nic not found. Creating the vm nic $VMNicName"
    $VMNic = New-AzNetworkInterface -ResourceGroupName $RessourceGroupName -Name $VMNicName -Location $AlyaLocation -SubnetId $Subnet.Id -EnableAcceleratedNetworking:$false 
    Set-AzNetworkInterface -NetworkInterface $VMNic
}
#$VMNic.EnableAcceleratedNetworking = $false
#Set-AzNetworkInterface -NetworkInterface $VMNic

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

# Checking image host vm
Write-Host "Checking image host vm" -ForegroundColor $CommandInfo
$ImageHostVm = Get-AzVM -ResourceGroupName $RessourceGroupName -Name $VMName -ErrorAction SilentlyContinue
if (-Not $ImageHostVm)
{
    Write-Warning -Message "Image host vm not found. Creating the image host vm $VMName"
    #Get-AzVMSize -Location $AlyaLocation | where { $_.Name -like "Standard_D4s*" }
    #Get-AzVMImagePublisher -Location $AlyaLocation
    #Get-AzVMImageOffer -Location $AlyaLocation -PublisherName "MicrosoftWindowsServer"
    $VMCredential = New-Object System.Management.Automation.PSCredential ("$($VMName)admin", $VMPasswordSec)
    #TODO -LicenseType $AlyaVmLicenseType if server and hybrid benefit
    $VMConfig = New-AzVMConfig -VMName $VMName -VMSize "Standard_D4s_v3" #-LicenseType PAYG
    $VMConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VMName -Credential $VMCredential -ProvisionVMAgent -EnableAutoUpdate -TimeZone $AlyaTimeZone | Out-Null
    $VMConfig | Set-AzVMSourceImage -PublisherName "MicrosoftWindowsDesktop" -Offer "Windows-10" -Skus "19h2-evd" -Version latest | Out-Null
    $VMConfig | Add-AzVMNetworkInterface -Id $VMNic.Id | Out-Null
    $VMConfig | Set-AzVMOSDisk -Name $VMDiskName -CreateOption FromImage -Caching ReadWrite -DiskSizeInGB 127 | Out-Null
    $VMConfig | Set-AzVMBootDiagnostic -Enable -ResourceGroupName $DiagnosticRessourceGroupName -StorageAccountName $DiagnosticStorageName | Out-Null
    $tmp = New-AzVM -ResourceGroupName $RessourceGroupName -Location $AlyaLocation -VM $VMConfig -DisableBginfoExtension
    $ImageHostVm = Get-AzVM -ResourceGroupName $RessourceGroupName -Name $VMName
    $tmp = Set-AzResource -ResourceId $ImageHostVm.Id -Tag @{displayName="Image Host";ownerEmail=$Context.Account.Id;stopTime=$AlyaWvdStopTime} -Force
}

# Checking anti malware vm extension
<#
Write-Host "Checking anti malware vm extension" -ForegroundColor $CommandInfo
$VmExtName = "$($VMName)AntiMalware"
$VmExt = Get-AzVMExtension -ResourceGroupName $RessourceGroupName -VMName $VMName -Name $VmExtName -ErrorAction SilentlyContinue
if (-Not $VmExt)
{
    Write-Warning -Message "AntiMalware extension on vm not found. Installing AntiMalware on Image host vm $VMName"
    #Get-AzVmImagePublisher -Location $AlyaLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select Type, Version
    #Get-Command Set-Az*Extension* -Module Az.Compute     
    #$Extension = Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | select -last 1
    $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | select -last 1).Version
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
    $VmExt = Set-AzVMExtension -ResourceGroupName $RessourceGroupName -VMName $VMName -Location $AlyaLocation `
        -Publisher "Microsoft.Azure.Security" -ExtensionType "IaaSAntimalware" -Name $VmExtName `
        -SettingString $amsettings -TypeHandlerVersion $typeHandlerVerMjandMn
}
#>

#Stopping Transscript
Stop-Transcript