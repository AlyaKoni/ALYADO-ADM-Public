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
    09.08.2021 Konrad Brunner       Initial Version
	16.08.2021 Konrad Brunner		Added provider registration

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Create-DnsForwarder-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAdResGrp)"
$NetworkResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainNetwork)"
$VirtualNetworkName = "$($AlyaNamingPrefix)vnet$($AlyaResIdVirtualNetwork)"
$VMSubnetName = "$($VirtualNetworkName)snet$($AlyaResIdAdSNet)"
$DiagnosticResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$DiagnosticStorageName = "$($AlyaNamingPrefix)strg$($AlyaResIdDiagnosticStorage)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdAdResGrp)"

$VMName = "$($AlyaNamingPrefix)serv$($AlyaResIdForwarderSrv)"
$VMSize = "Standard_A1_v2"
$VMAcceleratedNetworking = $false
$VMOsDiskSize = 32
$VMOsDiskType = "StandardSSD_LRS"
$VMPublisher = "cloud-infrastructure-services"
$VMOffer = "servercore-2019"
$VMSku = "servercore-2019"
$VMPlan = "servercore-2019"
$VMNicName = "$($VMName)nic1"
$VMDiskName = "$($VMName)osdisk"
#Get-AzVMSize -Location $AlyaLocation | Where-Object { $_.Name -like "Standard_A1_v2" }
#Get-AzVMImagePublisher -Location $AlyaLocation | Where-Object { $_.PublisherName -like "cloud-infrastructure-services" }
#Get-AzVMImageOffer -Location $AlyaLocation -PublisherName "cloud-infrastructure-services" | Format-List
#Get-AzVMImageSku -Location $AlyaLocation -PublisherName "cloud-infrastructure-services" -Offer "servercore-2019" | Format-List
$DomJoinName = $AlyaLocalDomainName
$DomJoinOUPath = $AlyaServerOuProd
$DomJoinOption = 0x00000003

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Compute"
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Network"
Install-ModuleIfNotInstalled "Az.Storage"
Install-ModuleIfNotInstalled "Az.KeyVault"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Infrastructure | Create-DnsForwarder | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking resource provider registration
Write-Host "Checking resource provider registration Microsoft.Storage" -ForegroundColor $CommandInfo
$resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Storage" -Location $AlyaLocation
if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
{
    Write-Warning "Resource provider Microsoft.Storage not registered. Registering now resource provider Microsoft.Storage"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Storage" | Out-Null
    do
    {
        Start-Sleep -Seconds 5
        $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Storage" -Location $AlyaLocation
    } while ($resProv[0].RegistrationState -ne "Registered")
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
    throw "Virtual network not found. Please create virtual network $VirtualNetworkName"
}

# Checking subnet
Write-Host "Checking subnet" -ForegroundColor $CommandInfo
$Subnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $VNet -Name $VMSubnetName -ErrorAction SilentlyContinue
if (-Not $Subnet)
{
    throw "Subnet not found. Please create the subnet $VMSubnetName"
}

# Checking ressource group diag
Write-Host "Checking ressource group diag" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $DiagnosticResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    throw "Ressource Group not found. Pleas ecreate the Ressource Group $DiagnosticResourceGroupName"
}

# Checking diag storage account
Write-Host "Checking diag storage account" -ForegroundColor $CommandInfo
$StrgAccountDiag = Get-AzStorageAccount -ResourceGroupName $DiagnosticResourceGroupName -Name $DiagnosticStorageName -ErrorAction SilentlyContinue
if (-Not $StrgAccountDiag)
{
    Write-Warning "Diag storage account not found. Creating the diag storage account $DiagnosticStorageName"
    $StrgAccountDiag = New-AzStorageAccount -Name $DiagnosticStorageName -ResourceGroupName $DiagnosticResourceGroupName -Location $AlyaLocation -SkuName "Standard_LRS" -Kind StorageV2 -AccessTier Cool -Tag @{displayName="Diagnostic storage";ownerEmail=$Context.Account.Id}
    if (-Not $StrgAccountDiag)
    {
        Write-Error "Diag storage account $DiagnosticStorageName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
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
$VMCredentialAssetName = "$($VMName)adminCredentials"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $VMCredentialAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    Write-Warning "Key Vault secret not found. Creating the secret $VMCredentialAssetName"
    $VMPassword = "!" + [Guid]::NewGuid().ToString() + "+"
    $VMPasswordSec = ConvertTo-SecureString $VMPassword -AsPlainText -Force
    $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $VMCredentialAssetName -SecretValue $VMPasswordSec
}
else
{
    $VMPasswordSec = $AzureKeyVaultSecret.SecretValue
}
Clear-Variable -Name VMPassword -Force -ErrorAction SilentlyContinue
Clear-Variable -Name AzureKeyVaultSecret -Force -ErrorAction SilentlyContinue

# Checking vm nic
Write-Host "Checking vm nic" -ForegroundColor $CommandInfo
$VMNic = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $VMNicName -ErrorAction SilentlyContinue
if (-Not $VMNic)
{
    Write-Warning "VM nic not found. Creating the vm nic $VMNicName"
    $VMNic = New-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $VMNicName -Location $AlyaLocation -SubnetId $Subnet.Id -EnableAcceleratedNetworking:$VMAcceleratedNetworking
    $VMNic.IpConfigurations[0].PrivateIpAllocationMethod = "Static"
    Set-AzNetworkInterface -NetworkInterface $VMNic
}

# Checking vm
Write-Host "Checking vm" -ForegroundColor $CommandInfo
$Vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status -ErrorAction SilentlyContinue
$VMCredential = New-Object System.Management.Automation.PSCredential ("$($VMName)admin", $VMPasswordSec)
if (-Not $Vm)
{
    Write-Warning "VM not found. Creating the VM $VMName"
    $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -LicenseType $AlyaVMLicenseTypeClient
    $VMConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VMName -Credential $VMCredential -ProvisionVMAgent -EnableAutoUpdate -TimeZone $AlyaTimeZone | Out-Null
    $VMConfig | Set-AzVMSourceImage -PublisherName $VMPublisher -Offer $VMOffer -Skus $VMSku -Version latest | Out-Null
    $VMConfig | Set-AzVMPlan -Name $VMSku -Product $VMOffer -Publisher $VMPublisher
    $VMConfig | Add-AzVMNetworkInterface -Id $VMNic.Id | Out-Null
    $VMConfig | Set-AzVMOSDisk -Name $VMDiskName -CreateOption FromImage -Caching ReadWrite -DiskSizeInGB $VMOsDiskSize -StorageAccountType $VMOsDiskType | Out-Null
    $VMConfig | Set-AzVMBootDiagnostic -Enable -ResourceGroupName $DiagnosticResourceGroupName -StorageAccountName $DiagnosticStorageName | Out-Null
    $tmp = New-AzVM -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -VM $VMConfig -Tag @{displayName="DNS forwarder";ownerEmail=$Context.Account.Id} -DisableBginfoExtension
    $Vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status
}
if (-Not ($VM.Statuses | Where-Object { $_.Code -eq "PowerState/running"}))
{
    Write-Warning "Starting VM $VMName"
    Start-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
}

# Checking anti malware vm extension
Write-Host "Checking anti malware vm extension" -ForegroundColor $CommandInfo
$VmExtName = "$($VMName)AntiMalware"
$VmExt = Get-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name $VmExtName -ErrorAction SilentlyContinue
if (-Not $VmExt)
{
    Write-Warning "AntiMalware extension on vm not found. Installing AntiMalware on vm $VMName"
    #Get-AzVmImagePublisher -Location $AlyaLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select-Object Type, Version
    #$Extension = Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | Select-Object -last 1
    $amsettings = @"
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
                "Extensions": "",   
                "Paths": "",
                "Processes": ""
            }
        }
"@
    $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | %{ new-object System.Version ($_.Version) } | Sort | Select-Object -Last 1).ToString()
    $typeHandlerVerMjandMn = $typeHandlerVer.split(".")
    $typeHandlerVerMjandMn = $typeHandlerVerMjandMn[0] + "." + $typeHandlerVerMjandMn[1]
    $VmExt = Set-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Location $AlyaLocation `
        -Publisher "Microsoft.Azure.Security" -ExtensionType "IaaSAntimalware" -Name $VmExtName `
        -SettingString $amsettings -TypeHandlerVersion $typeHandlerVerMjandMn
}

# Checking domain join vm extension
Write-Host "Checking domain join vm extension" -ForegroundColor $CommandInfo
$VmDomainJoinExtName = "$($VMName)DomainJoin"
$VmDomainJoinExt = Get-AzVMADDomainExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name $VmDomainJoinExtName -ErrorAction SilentlyContinue
if (-Not $VmDomainJoinExt)
{
    Write-Warning "Domain join extension on vm not found. Setting domain join on vm $VMName"
    $DomJoinCredential = Get-Credential -Message "Account to join domain"
    $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Compute" -Type "JsonADDomainExtension" | %{ new-object System.Version ($_.Version) } | Sort | Select-Object -Last 1).ToString()
    $typeHandlerVerMjandMn = $typeHandlerVer.split(".")
    $typeHandlerVerMjandMn = $typeHandlerVerMjandMn[0] + "." + $typeHandlerVerMjandMn[1]
    Set-AzVMADDomainExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Location $AlyaLocation `
        -Name $VmDomainJoinExtName -DomainName $DomJoinName -OUPath $DomJoinOUPath -JoinOption $DomJoinOption -Credential $DomJoinCredential -Restart `
        -TypeHandlerVersion $typeHandlerVerMjandMn 
}
Clear-Variable -Name "DomJoinCredential" -Force -ErrorAction SilentlyContinue

<#

For CLoud Shell:

# Enable PowerShell Remoting on the VM
Write-Host "Enabling PowerShell Remoting on virtual machine" -ForegroundColor Green
Enable-AzVMPSRemoting -Name $VMName -ResourceGroupName $ResourceGroupName

# Checking DnsForwarder on vm
Write-Host "Checking DnsForwarder on vm" -ForegroundColor $CommandInfo
$checkDnsForwarderOnVMLiteral =
@'
$logPath = Join-Path (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "Azure@HH") "ConfigDnsForwarder.log"
Start-Transcript -Path $logPath -Force
$cmd = Get-Command -Name "Install-WindowsFeature" -ErrorAction SilentlyContinue
if (-Not $cmd)
{
    Write-Error "Can't find cmdlt Install-WindowsFeature" -ErrorAction SilentlyContinue
    return 1
}
$cmd = Get-Command -Name "Get-WindowsFeature" -ErrorAction SilentlyContinue
if (-Not $cmd)
{
    Write-Error "Can't find cmdlt Get-WindowsFeature" -ErrorAction SilentlyContinue
    return 1
}
$ftr = Get-WindowsFeature -Name DNS
if (-Not $ftr.Installed)
{
    Install-WindowsFeature -Name DNS -IncludeManagementTools
    Add-DnsServerForwarder -IPAddress 168.63.129.16 -PassThru
}
Stop-Transcript
return 0
'@
$checkDnsForwarderOnVMScriptBlock = [ScriptBlock]::Create($checkDnsForwarderOnVMLiteral)
$scriptResult = Invoke-AzVMCommand -Name $VMName -ResourceGroupName $ResourceGroupName -ScriptBlock $checkDnsForwarderOnVMScriptBlock -Credential $VMCredential
if ($scriptResult -ne 0)
{
    Write-Error "Error installing DNS forwarder on VM. Please check local log in %CommonApplicationData%\Azure@HH"
}

#>

# Checking ConfigDnsForwarder vm extension
Write-Host "Checking ConfigDnsForwarder vm extension" -ForegroundColor $CommandInfo
$VmScriptExtName = "$($VMName)ConfigDnsForwarder"
$VmScriptExt = Get-AzVMCustomScriptExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name $VmScriptExtName -ErrorAction SilentlyContinue
if (-Not $VmScriptExt)
{
    Write-Warning "$VmScriptExtName extension on vm not found. Installing $VmScriptExtName on vm $VMName"
    $ctx = $StrgAccountDiag.Context
    $container = Get-AzStorageContainer -Context $ctx -Name "scripts" -ErrorAction SilentlyContinue
    if (-Not $container)
    {
        $container = New-AzStorageContainer -Context $ctx -Name "scripts" -Permission Blob
    }
    $FilePath = Join-Path $env:TEMP "$VmScriptExtName.ps1"
    @'
$logPath = Join-Path (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "Azure@HH") "ConfigDnsForwarder.log"
Start-Transcript -Path $logPath -Force
$cmd = Get-Command -Name "Install-WindowsFeature" -ErrorAction SilentlyContinue
if (-Not $cmd)
{
    Write-Error "Can't find cmdlt Install-WindowsFeature" -ErrorAction SilentlyContinue
    return 1
}
$cmd = Get-Command -Name "Get-WindowsFeature" -ErrorAction SilentlyContinue
if (-Not $cmd)
{
    Write-Error "Can't find cmdlt Get-WindowsFeature" -ErrorAction SilentlyContinue
    return 1
}
$ftr = Get-WindowsFeature -Name DNS
if (-Not $ftr.Installed)
{
    Install-WindowsFeature -Name DNS -IncludeManagementTools
    Add-DnsServerForwarder -IPAddress 168.63.129.16 -PassThru
}
Stop-Transcript
'@ | Set-Content -Path $FilePath -Encoding UTF8 -Force
    $blob = Get-AzStorageBlob -Context $ctx -Container "scripts" -Blob "$VmScriptExtName.ps1" -ErrorAction SilentlyContinue
    if (-Not $blob -or -Not $blob.ICloudBlob.Exists())
    {
        Set-AzStorageBlobContent -Context $ctx -Container "scripts" -Blob "$VmScriptExtName.ps1" -File $FilePath -BlobType Block -Force
    }
    else
    {
        $blob | Set-AzStorageBlobContent -File $FilePath -Force
    }
    Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
    $StrgKeys = Get-AzStorageAccountKey -ResourceGroupName $DiagnosticResourceGroupName -Name $DiagnosticStorageName
    $StrgKey = $StrgKeys.GetValue(0).Value
    #Get-AzVmImagePublisher -Location $AlyaLocation | Where-Object { $_.PublisherName -like "Microsoft.*" }
    #(Get-AzVMExtensionImageType -Location $AlyaLocation -PublisherName "Microsoft.Compute").Type
    #Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Compute" -Type CustomScriptExtension
    $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Compute" -Type "CustomScriptExtension" | %{ new-object System.Version ($_.Version) } | Sort | Select-Object -Last 1).ToString()
    $typeHandlerVerMjandMn = $typeHandlerVer.split(".")
    $typeHandlerVerMjandMn = $typeHandlerVerMjandMn[0] + "." + $typeHandlerVerMjandMn[1]
    $VmScriptExt = Set-AzVMCustomScriptExtension -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -VMName $VMName -Name $VmScriptExtName -StorageAccountName $DiagnosticStorageName -StorageAccountKey $StrgKey -ContainerName "scripts" -FileName "$VmScriptExtName.ps1" -Run "$VmScriptExtName.ps1" -SecureExecution -TypeHandlerVersion $typeHandlerVerMjandMn
}

#Stopping Transscript
Stop-Transcript
