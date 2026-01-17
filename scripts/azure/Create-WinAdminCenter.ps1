#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2025

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
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Create-WinAdminCenter-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAdResGrp)"
$NetworkResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainNetwork)"
$VirtualNetworkName = "$($AlyaNamingPrefix)vnet$($AlyaResIdVirtualNetwork)"
$VMSubnetName = "$($VirtualNetworkName)snet$($AlyaResIdAdSNet)"
$DiagnosticResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$DiagnosticStorageName = "$($AlyaNamingPrefix)strg$($AlyaResIdDiagnosticStorage)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdAdResGrp)"

$VMName = "$($AlyaNamingPrefix)serv$($AlyaResIdAdminCenterSrv)"
$VMSize = "Standard_A2_v2"
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
Write-Host "Infrastructure | Create-WinAdminCenter | AZURE" -ForegroundColor $CommandInfo
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
    $StrgAccountDiag = New-AzStorageAccount -Name $DiagnosticStorageName -ResourceGroupName $DiagnosticResourceGroupName -Location $AlyaLocation -SkuName "Standard_LRS" -Kind StorageV2 -MinimumTlsVersion "TLS1_2" -AccessTier Cool -Tag @{DisplayName="Diagnostic storage";Service="Logging"}
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
        Exit 2
    }
}
if (-Not $KeyVault.EnabledForDeployment)
{
    Write-Warning "Key Vault not enabled for deployments. Enabling it now"
    Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName -EnabledForDeployment
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
if (-Not $Vm)
{
    Write-Warning "VM not found. Creating the VM $VMName"
    $VMCredential = New-Object System.Management.Automation.PSCredential ("$($VMName)admin", $VMPasswordSec)
    $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -LicenseType $AlyaVMLicenseTypeClient
    $VMConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VMName -Credential $VMCredential -ProvisionVMAgent -EnableAutoUpdate -TimeZone $AlyaTimeZone | Out-Null
    $VMConfig | Set-AzVMSourceImage -PublisherName $VMPublisher -Offer $VMOffer -Skus $VMSku -Version latest | Out-Null
    $VMConfig | Set-AzVMPlan -Name $VMSku -Product $VMOffer -Publisher $VMPublisher
    $VMConfig | Add-AzVMNetworkInterface -Id $VMNic.Id | Out-Null
    $VMConfig | Set-AzVMOSDisk -Name $VMDiskName -CreateOption FromImage -Caching ReadWrite -DiskSizeInGB $VMOsDiskSize -StorageAccountType $VMOsDiskType | Out-Null
    $VMConfig | Set-AzVMBootDiagnostic -Enable -ResourceGroupName $DiagnosticResourceGroupName -StorageAccountName $DiagnosticStorageName | Out-Null
    $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -VM $VMConfig -Tag @{DisplayName="DNS forwarder"} -DisableBginfoExtension
    $Vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status
}
if (-Not ($VM.Statuses | Where-Object { $_.Code -eq "PowerState/running"}))
{
    Write-Warning "Starting VM $VMName"
    Start-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
}
$Vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction SilentlyContinue

# Checking anti malware vm extension
Write-Host "Checking anti malware vm extension" -ForegroundColor $CommandInfo
$VmExtName = "$($VMName)AntiMalware"
$VmExt = Get-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name $VmExtName -ErrorAction SilentlyContinue
if (-Not $VmExt)
{
    Write-Warning "AntiMalware extension on vm not found. Installing AntiMalware on vm $VMName"
    #$exts = Get-AzVmImagePublisher -Location $AlyaLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select-Object PublisherName, Type, Version ; $exts | Format-Table
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

# Checking azure key vault certificate
Write-Host "Checking azure key vault certificate" -ForegroundColor $CommandInfo
$AzureCertificateName = "$($VMName)SelfSignedCertificate"
$AzureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultCertificate)
{
    Write-Warning "SelfSignedCertificate not found. Creating the certificate $AzureCertificateName"
    $NoOfMonthsUntilExpired = 24
    $AzureCertSubjectName = "CN=" + $VMName
    $AzurePolicy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $AzureCertSubjectName  -IssuerName "Self" -ValidityInMonths $NoOfMonthsUntilExpired -ReuseKeyOnRenewal
    $AzureKeyVaultCertificateProgress = Add-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName -CertificatePolicy $AzurePolicy
    While ($AzureKeyVaultCertificateProgress.Status -eq "inProgress")
    {
        Start-Sleep -s 10
        $AzureKeyVaultCertificateProgress = Get-AzKeyVaultCertificateOperation -VaultName $KeyVaultName -Name $AzureCertificateName
    }
    if ($AzureKeyVaultCertificateProgress.Status -ne "completed")
    {
        Write-Error "Key vault cert creation is not sucessfull and its status is: $(KeyVaultCertificateProgress.Status)" -ErrorAction Continue 
        Exit 3
    }
}
$AzureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName

# Adding certificate to VM
Write-Host "Adding certificate to VM" -ForegroundColor $CommandInfo
Start-Sleep -Seconds 60 # Wait for cert deployment
$certURL = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AzureCertificateName).id
if ($certURL -notlike "*$AzureCertificateName*")
{
    Write-Error "Wrong secret url!" -ErrorAction Continue 
    Exit 3
}
$Vm = Add-AzVMSecret -VM $Vm -SourceVaultId $KeyVault.ResourceId -CertificateStore "My" -CertificateUrl $certURL
$result = Update-AzVM -ResourceGroupName $ResourceGroupName -VM $Vm
if (-not $result.IsSuccessStatusCode)
{
    Write-Error "We couldn't add the given certificate to virtual machine $VMName" -ErrorAction Continue
    Exit 4
}

# Enabling PowerShell remoting
Write-Host "Enabling PowerShell Remoting" -ForegroundColor $CommandInfo
$VmScriptPsRemExtName = "$($VMName)EnablingPowerShellRemoting"
$VmScriptPsRemExt = Get-AzVMCustomScriptExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name $VmScriptPsRemExtName -ErrorAction SilentlyContinue
if (-Not $VmScriptPsRemExt)
{
    Write-Warning "$VmScriptPsRemExtName extension on vm not found. Installing $VmScriptPsRemExtName on vm $VMName"
    $ctx = $StrgAccountDiag.Context
    $container = Get-AzStorageContainer -Context $ctx -Name "scripts" -ErrorAction SilentlyContinue
    if (-Not $container)
    {
        $container = New-AzStorageContainer -Context $ctx -Name "scripts" -Permission Blob
    }
    $FilePath = Join-Path $env:TEMP "$VmScriptPsRemExtName.ps1"
    $installScript = @'
$logPath = Join-Path (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "Azure@HH") "ConfigPowerShellRemoting.log"
Start-Transcript -Path $logPath -Force

Write-Host "Configuring PowerShell Remoting"
Add-LocalGroupMember -Group "Administrators" -Member "<userName>" -ErrorAction SilentlyContinue
$serv = Get-Service "WinRM"
if ($serv.StartType -ne "Automatic")
{
    Write-Warning "WinRM StartType was not Automatic. Setting it now."
    Set-Service WinRM -StartMode "Automatic"
}
if ($serv.Status -ne "Running")
{
    Write-Warning "WinRM Status was not Running. Starting it now."
    Start-Service WinRM
}
$val = Get-Item WSMan:\localhost\Client\TrustedHosts
if ([string]::IsNullOrEmpty($val.Value))
{
    Write-Warning "Trusted hosts not configured. Setting it to *."
    Set-Item WSMan:localhost\client\trustedhosts -value * -Force
}
winrm quickconfig
Enable-PSRemoting -SkipNetworkProfileCheck -Force
Test-WSMan
Stop-Transcript
'@
    $installScript = $installScript.Replace('<userName>', $Context.Account.Id)
    $installScript | Set-Content -Path $FilePath -Encoding UTF8 -Force
    $blob = Get-AzStorageBlob -Context $ctx -Container "scripts" -Blob "$VmScriptPsRemExtName.ps1" -ErrorAction SilentlyContinue
    if (-Not $blob -or -Not $blob.ICloudBlob.Exists())
    {
        Set-AzStorageBlobContent -Context $ctx -Container "scripts" -Blob "$VmScriptPsRemExtName.ps1" -File $FilePath -BlobType Block -Force
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
    $VmScriptPsRemExt = Set-AzVMCustomScriptExtension -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -VMName $VMName -Name $VmScriptPsRemExtName -StorageAccountName $DiagnosticStorageName -StorageAccountKey $StrgKey -ContainerName "scripts" -FileName "$VmScriptPsRemExtName.ps1" -Run "$VmScriptPsRemExtName.ps1" -SecureExecution -TypeHandlerVersion $typeHandlerVerMjandMn
}

# Installing Windows Admin Center
Write-Host "Installing Windows Admin Center" -ForegroundColor $CommandInfo
$VmScriptExtName = "$($VMName)InstallWindowsAdminCenter"
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
    $installScript = @'
$logPath = Join-Path (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "Azure@HH") "ConfigWinAdminCenter.log"
Start-Transcript -Path $logPath -Force

$cert = Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Thumbprint -eq "<certThumbprint>"}
if (-Not $cert)
{
    Write-Error "We couldn't find the required certificate." -ErrorAction Continue
    throw "We couldn't find the required certificate."
}
Write-Host "Downloading and installing WinAdminCenter MSI"
$executePath = "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
$wacDownload = "https://aka.ms/WACDownload"
Write-Host "  Downloading Windows Admin Center MSI from $wacDownload"
Write-Host "  The MSI filepath will be '$executePath'"
Invoke-WebRequest -UseBasicParsing -Uri $wacDownload -OutFile $executePath
Write-Host "  Starting Windows Admin Center MSI installation"
# Start scheduled task process to begin MSI installation.
$taskPath = "\Hundegger\WindowsAdminCenter"
$wacProductName = "Windows Admin Center"
Write-Host "  Unregistering scheduled task '<taskName>' if it already exists"
Get-ScheduledTask | ? TaskName -eq "<taskName>" | Unregister-ScheduledTask -Confirm:$false
$timestamp = Get-Date -Format yyMM-dd-HHmm
$argumentString = "/qn /l*v WAC_MSIlog_$timestamp.txt SME_PORT=<PortNumber> SSL_CERTIFICATE_OPTION=installed SME_THUMBPRINT=<certThumbprint>"
$action = New-ScheduledTaskAction -Execute $executePath -Argument $argumentString
Write-Host "  Registering scheduled task '<taskName>'"
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U
$task = Register-ScheduledTask -TaskName "<taskName>" -TaskPath $taskPath -Action $action -Principal $principal -Force
Write-Host "  Starting scheduled task '<taskName>'"
$null = Start-ScheduledTask -InputObject $task
$secondsToStart = 20
$endTime = [DateTime]::Now.AddSeconds($secondsToStart)
$taskHasStarted = $false
while ([DateTime]::Now -lt $endTime) {
    Start-Sleep -Seconds 1
    $taskInfo = Get-ScheduledTask | ?  TaskName -eq "<taskName>" | Get-ScheduledTaskInfo
    if ($taskInfo.LastRunTime) {
        Write-Host "Scheduled task '<taskName>' has started execution"
        $taskHasStarted = $true
        break
    }
}
if (-not $taskHasStarted) {
    Write-Error "Scheduled task '<taskName>' failed to start in $secondsToStart seconds." -ErrorAction Continue
    throw "Scheduled task '<taskName>' failed to start in $secondsToStart seconds."
}
else
{
    $count = 0
    $retryAttempts = 3
    $continueRetry = $true
    while ($count -le $retryAttempts) {
        $minutesToInstall = 10
        $endTime = [DateTime]::Now.AddMinutes($minutesToInstall)
        $taskComplete = $null

        while ([DateTime]::Now -lt $endTime)
        {
            try {
                $taskInfo = Get-ScheduledTask | ? TaskName -eq "<taskName>" | Get-ScheduledTaskInfo
                Write-Host "'<taskName>' scheduled task last run at $([DateTime]::Now.ToString('HH:mm:ss')) has a last task result of $($taskInfo.LastTaskResult)"
                if ($taskInfo.LastTaskResult -eq 0)
                {
                    $taskComplete = $true
                }
            } catch { }
            if ($taskComplete) {
                break
            }
            if ($taskInfo.LastTaskResult -eq 1603)
            {
                Write-Warning "MSI installation failed with the code 'Fatal Error During Installation' (1603)."
                break
            }
            if ($taskInfo.LastTaskResult -eq 1618)
            {
                Write-Warning "MSI installation failed with the code 'ERROR_INSTALL_ALREADY_RUNNING' (1618)."
                break
            }
            if ($taskInfo.LastTaskResult -eq 1619) {
                Write-Error "MSI installation failed with the code 'ERROR_INSTALL_PACKAGE_OPEN_FAILED' (1619)." -ErrorAction Continue
                $continueRetry = $false
                break
            }
            if ($taskInfo.LastTaskResult -eq 1620)
            {
                Write-Error "MSI installation failed with the code 'ERROR_INSTALL_PACKAGE_INVALID' (1620)." -ErrorAction Continue
                $continueRetry = $false
                break
            }
            if ($taskInfo.LastTaskResult -eq 1641)
            {
                Write-Warning "You must restart your system for the configuration changes made to Windows Admin Center to take effect."
                $taskComplete = $true
                break
            }
            Start-Sleep -Seconds 10
        }
        if (-not $taskComplete -and $continueRetry)
        {
            Write-Host "Retrying MSI installation, attempt $($count + 1) of $retryAttempts"
            $task = Get-ScheduledTask | ? TaskName -eq "<taskName>"
            Write-Host "Starting scheduled task '<taskName>'"
            $null = Start-ScheduledTask -InputObject $task
            $count++
        } else {
            break
        }
    }
    if (-not $taskComplete) {
        Write-Error "We couldn't install Windows Admin Center MSI on virtual machine." -ErrorAction Continue
        throw "We couldn't install Windows Admin Center MSI on virtual machine."
    }
    Write-Host "Installation of Windows Admin Center on virtual machine is successful"
    Write-Host "Verifying firewall rule"
    if (-not (Get-NetFirewallRule | ? DisplayName -eq SmeInboundOpenException)) {
	    $null = New-NetFirewallRule -DisplayName SmeInboundOpenException -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow -Description "Windows Admin Center inbound port exception"
	}
}
Stop-Transcript
'@
    $installScript = $installScript.Replace('<taskName>', "Install Windows Admin Center")
    $installScript = $installScript.Replace('<PortNumber>', 443)
    $installScript = $installScript.Replace('<certThumbprint>', $AzureKeyVaultCertificate.Thumbprint)
    $installScript | Set-Content -Path $FilePath -Encoding UTF8 -Force
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

<# Cloud Shell version

# Enable PowerShell Remoting on the VM
Write-Host "Enabling PowerShell Remoting on virtual machine" -ForegroundColor Green
Enable-AzVMPSRemoting -Name $VMName -ResourceGroupName $ResourceGroupName

# Checking certificate on VM
Write-Host "Checking certificate on VM" -ForegroundColor $CommandInfo
$checkCertOnVMLiteral =
@'
$logPath = Join-Path (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "Azure@HH") "GetWinAdminCenterCert.log"
Start-Transcript -Path $logPath -Force
return (Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Thumbprint -eq "<certThumbprint>"})
'@
$checkCertOnVMLiteral = $checkCertOnVMLiteral.Replace('<certThumbprint>', $cert.Thumbprint)
$checkCertOnVMScriptBlock = [ScriptBlock]::Create($checkCertOnVMLiteral)
$hasCert = Invoke-AzVMCommand -Name $VMName -ResourceGroupName $ResourceGroupName -ScriptBlock $checkCertOnVMScriptBlock -Credential $VMCredential
if (-Not $hasCert)
{
    Write-Warning "Adding certificate to VM"
    $certURL = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AzureCertificateName).id
    $Vm = Add-AzVMSecret -VM $Vm -SourceVaultId $KeyVault.ResourceId -CertificateStore "My" -CertificateUrl $certURL
    $result = Update-AzVM -ResourceGroupName $ResourceGroupName -VM $Vm
    if (-not $result.IsSuccessStatusCode)
    {
        Write-Error "We couldn't add the given certificate to virtual machine $VMName" -ErrorAction Continue
        Exit 4
    }
}

# Downloading and installing WinAdminCenter MSI
Write-Host "Downloading and installing WinAdminCenter MSI" -ForegroundColor $CommandInfo
$taskName = "Install Windows Admin Center"
$msiScriptLiteral =
@'
$logPath = Join-Path (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "Azure@HH") "InstallWinAdminCenterMSI.log"
Start-Transcript -Path $logPath -Force
$executePath = "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
$wacDownload = "https://aka.ms/WACDownload"
Write-Host "Downloading Windows Admin Center MSI from $wacDownload"
Write-Host "The MSI filepath will be '$executePath'"
Invoke-WebRequest -UseBasicParsing -Uri $wacDownload -OutFile $executePath
Write-Host "Starting Windows Admin Center MSI installation"
# Start scheduled task process to begin MSI installation.
$taskPath = "\Hundegger\WindowsAdminCenter"
$wacProductName = "Windows Admin Center"
Write-Host "Unregistering scheduled task '<taskName>' if it already exists"
Get-ScheduledTask | ? TaskName -eq "<taskName>" | Unregister-ScheduledTask -Confirm:$false
$timestamp = Get-Date -Format yyMM-dd-HHmm
$argumentString = "/qn /l*v WAC_MSIlog_$timestamp.txt SME_PORT=<PortNumber> SSL_CERTIFICATE_OPTION=installed SME_THUMBPRINT=<certThumbprint>"
$action = New-ScheduledTaskAction -Execute $executePath -Argument $argumentString
Write-Host "Registering scheduled task '<taskName>'"
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U
$task = Register-ScheduledTask -TaskName "<taskName>" -TaskPath $taskPath -Action $action -Principal $principal -Force
Write-Host "Starting scheduled task '<taskName>'"
$null = Start-ScheduledTask -InputObject $task
$secondsToStart = 20
$endTime = [DateTime]::Now.AddSeconds($secondsToStart)
$taskHasStarted = $false
while ([DateTime]::Now -lt $endTime) {
    Start-Sleep -Seconds 1
    $taskInfo = Get-ScheduledTask | ?  TaskName -eq "<taskName>" | Get-ScheduledTaskInfo
    if ($taskInfo.LastRunTime) {
        Write-Host "Scheduled task '<taskName>' has started execution"
        $taskHasStarted = $true
        break
    }
}
if (-not $taskHasStarted) {
    Write-Error "Scheduled task '<taskName>' failed to start in $secondsToStart seconds."
}
Stop-Transcript
return $taskHasStarted
'@
$msiScriptLiteral = $msiScriptLiteral.Replace('<taskName>', $taskName)
$msiScriptLiteral = $msiScriptLiteral.Replace('<PortNumber>', 443)
$msiScriptLiteral = $msiScriptLiteral.Replace('<certThumbprint>', $cert.Thumbprint)
$msiScriptBlock = [ScriptBlock]::Create($msiScriptLiteral)
$taskHasStarted = Invoke-AzVMCommand -Name $VMName -ResourceGroupName $ResourceGroupName -ScriptBlock $msiScriptBlock -Credential $VMCredential
if (-not $taskHasStarted) {
    Write-Error "Ending installation of WAC on virtual machine." -ErrorAction Continue
    Exit 5
}

#Checking MSI installation result
Write-Host "Checking MSI installation result" -ForegroundColor $CommandInfo
$getTaskInfoScriptLiteral = 
@'
Get-ScheduledTask | ? TaskName -eq "<taskName>" | Get-ScheduledTaskInfo
'@
$getTaskInfoScriptLiteral = $getTaskInfoScriptLiteral.Replace('<taskName>', $taskName)
$getTaskInfoScriptBlock = [ScriptBlock]::Create($getTaskInfoScriptLiteral)

$startScheduledTaskScriptLiteral = 
@'
$task = Get-ScheduledTask | ? TaskName -eq "<taskName>"

Write-Host "Starting scheduled task '<taskName>'"
$null = Start-ScheduledTask -InputObject $task
'@
$startScheduledTaskScriptLiteral = $startScheduledTaskScriptLiteral.Replace('<taskName>', $taskName)
$startScheduledTaskScriptBlock = [ScriptBlock]::Create($startScheduledTaskScriptLiteral)

$count = 0
$retryAttempts = 3
$continueRetry = $true

while ($count -le $retryAttempts) {
    $minutesToInstall = 10
    $endTime = [DateTime]::Now.AddMinutes($minutesToInstall)
    $taskComplete = $null

    while ([DateTime]::Now -lt $endTime)
    {
        try {
            $taskInfo = Invoke-AzVMCommand -Name $VMName -ResourceGroupName $ResourceGroupName -ScriptBlock $getTaskInfoScriptBlock -Credential $VMCredential
            Write-Host "'$taskName' scheduled task last run at $([DateTime]::Now.ToString('HH:mm:ss')) has a last task result of $($taskInfo.LastTaskResult)"
            if ($taskInfo.LastTaskResult -eq 0)
            {
                $taskComplete = $true
            }
        } catch { }
        if ($taskComplete) {
            break
        }
        if ($taskInfo.LastTaskResult -eq 1603)
        {
            Write-Warning "MSI installation failed with the code 'Fatal Error During Installation' (1603)."
            break
        }
        if ($taskInfo.LastTaskResult -eq 1618)
        {
            Write-Warning "MSI installation failed with the code 'ERROR_INSTALL_ALREADY_RUNNING' (1618)."
            break
        }
        if ($taskInfo.LastTaskResult -eq 1619) {
            Write-Error "MSI installation failed with the code 'ERROR_INSTALL_PACKAGE_OPEN_FAILED' (1619)."
            $continueRetry = $false
            break
        }
        if ($taskInfo.LastTaskResult -eq 1620)
        {
            Write-Error "MSI installation failed with the code 'ERROR_INSTALL_PACKAGE_INVALID' (1620)."
            $continueRetry = $false
            break
        }
        if ($taskInfo.LastTaskResult -eq 1641)
        {
            Write-Warning "You must restart your system for the configuration changes made to Windows Admin Center to take effect."
            $taskComplete = $true
            break
        }
        Start-Sleep -Seconds 10
    }
    if (-not $taskComplete -and $continueRetry)
    {
        Write-Host "Retrying MSI installation, attempt $($count + 1) of $retryAttempts"
        Invoke-AzVMCommand -Name $VMName -ResourceGroupName $ResourceGroupName -ScriptBlock $startScheduledTaskScriptBlock -Credential $VMCredential
        $count++
    } else {
        break
    }
}
if (-not $taskComplete) {
    Write-Error "We couldn't install Windows Admin Center MSI on virtual machine." -ErrorAction Continue
    Exit 6
}
Write-Host "Installation of Windows Admin Center on virtual machine is successful"

# Verifying firewall rule
Write-Host "Verifying firewall rule" -ForegroundColor $CommandInfo
$checkFirewallScriptBlock = {
    if (-not (Get-NetFirewallRule | ? DisplayName -eq SmeInboundOpenException)) {
	    $null = New-NetFirewallRule -DisplayName SmeInboundOpenException -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow -Description "Windows Admin Center inbound port exception"
	}
}
Invoke-AzVMCommand -Name $VMName -ResourceGroupName $ResourceGroupName -ScriptBlock $checkFirewallScriptBlock -Credential $VMCredential

#>

# Resarting VM
Write-Host "Resarting VM" -ForegroundColor $CommandInfo
Restart-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName

# Done
$wacIp = $VMNic.IpConfigurations[0].PrivateIpAddress
Write-Host "Windows Admin Center was successfully installed." -ForegroundColor Green
Write-Host "Please access WAC by visiting https://$VMName or https://$wacIp" -ForegroundColor Green

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIvCQYJKoZIhvcNAQcCoIIu+jCCLvYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBGLMStCEJb1Cft
# RmVeiSRFC3XmR84t0jlPG6cHV8/xrqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFGKdt2G
# JyT9L/AIWKOUBrNaOa3IiuCg7vbZImfjFWruMA0GCSqGSIb3DQEBAQUABIICABSa
# M9Iix0zmeIPmv4+Dh+medcFwc6a0N/tvBJWroSJwnbbM2Pcul7jm7iZXLkegofw/
# nnr63I9BGn89TEvy/xGL1lyt5WoAKdhQ5IYWuygF27DHTWoKoH0z8+5Y8aTn0529
# L9o8Nj6lUgKibrgvW/1JnYQhvOikjB3Rg0HEX2Vx+rmj89hC4hLHIRg4bBPVsiUv
# sP2MjPDeBacvSl0urPJwKQ6Aso6Y+3VJlQ2E2mhpObmvwi+0nR6LQig8txCawWYG
# uJBIi4kMMOEm4RObWnV0LOywDg2hnp53UgdGb8Uuh3ZNeeJBGxJdEqAXN6+BBeA0
# u7JFbiCL3qTzRDfmc8fn98iYT49H9lH5sjDMjONPEMaBG3RRqnB3L8SIi2aG0mis
# px+ADiBWV+FJQgE44sr+OslVSBT4TCj69crVVG+7rtCJP/PD3kSLnDXJcmVhisrz
# aqL64cgv8K2CjwT/hlRnKbi6Vr6/ynhVvnjuazMA2thR/vcd65T54rQgFSwuyOXs
# vRDBv3h1M15W+uZV5UL6qn9b13oPf2xmKpw9Rl3OrocCrSbhzsc7xciNpecf9h9H
# nNY5k+q5tLJ9vQDd/43Zy6LcUOnhjXMF+2ZjAjUOIx/cslPQi21HQkzB8Oeb54RA
# 60gZ2a+KhEr0SoDFJYSqtIvKBaU7TMaw/W/dYOeSoYIWuzCCFrcGCisGAQQBgjcD
# AwExghanMIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEw
# gd8GCyqGSIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCAlbVnQH7wXmd4VSccWmjsdxztQm/DyiQiP75t+WpM8VgIUZZNP
# VUfjEQSi39pP+UHAb7ffIEoYDzIwMjYwMTE2MTMwOTE0WjADAgEBoFikVjBUMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwh
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMC
# AQICEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNp
# Z24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5
# WhcNMzQxMjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFs
# U2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWdu
# MSAtIFI2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4
# PuCF6+aqCj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb
# 5gk0Xydy3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJSc
# RV1W6/6efi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy
# 5RJY+o1NWhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY
# 0Lie04DuKbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2Z
# wbI6yiFHaS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYh
# KUlrMH9+2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5s
# WtX1qvCzk6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGo
# MIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYD
# VR0OBBYEFIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQC
# MEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSB
# gzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2Ev
# Z3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2Jh
# bHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaA
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9j
# cmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG
# 9w0BAQwFAAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26
# IFq7fQMIrN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76Tkv
# L+v2f4mHolGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftP
# ttS+G/MhNUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIl
# S3Ki74CU15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt
# 8DT4RQj9LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5
# lgJkgXEc1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD
# 9hQchjiGkyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71
# yzGKWnbAWQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGL
# ZtJFJzGJD7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVA
# GXCqHsh62QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZ
# MIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAw
# MDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOv
# dYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt
# 0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHP
# vIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFU
# UweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16
# ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS
# 2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm1
# 9m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIG
# bxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMD
# Ad6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/Miy
# Tdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9
# GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGG
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDD
# vWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEB
# BDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jv
# b3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29t
# L3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0B
# AQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYW
# axlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCy
# z+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQ
# cXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0
# Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59e
# odaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8
# oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1
# If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbcl
# IA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2M
# tnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB
# +SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIID
# a6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQL
# ExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjET
# MBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAw
# MDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQK
# EwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4
# QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTe
# c5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWy
# ZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7tt
# U+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrK
# otudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKF
# t3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTfl
# puwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2Fm
# CWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5
# paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4O
# hxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwo
# TK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki
# 5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnm
# XNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJE
# lrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMp
# mY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6
# JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG
# 7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/
# gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324G
# abbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5
# MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO7
# 7oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4st
# Q1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjx
# guhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJ
# YIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZI
# hvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcN
# AQkEMSIEIELSPT45D4Psl6vV4IIqM3EnNk+K69aNwcVwoFJu2Y8nMIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1or
# d69gXP0wczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAWzf1
# qRd7Dv0TvqKUNyP5ro1d9HePXWqN0OvxOaqwwLDLQzQI8FwWIPBEkXbCeVDW/iVT
# ZqUAdTrJIYMtulriRjn0d9dqkJX8j6MMvMNLbeU3iAqPY0tIGo18aHR3Y/iNJJov
# ambNZXkHWFvi78d8JdjQMsVAsZPsV6nlABZG/ASyoLWKs9Z/1HHhSHeNvRUkjZ0s
# +RX+7hbKrXoT2A5RvmkHgNLp6JEzyjKDgeL52hpwPtz3Z2RmlAvMwy39WbayBSRy
# RLYxaXZrCR0AyoQ1A5hfUWWqVDDmMtpdnNhOU6bDpiP6NGW2ANAYwnNy0b7HtpTK
# zLn63k7VSLCpnJ1XaSOxC0BiBztqDSJlCL7XopY3kmuFAasnbNXKFwl9RWurzRKn
# OmkuEpQwPCNuqszcZkFgXJqyByBQQW0ZeKsjbVnzs5U+W3pZ/hjR1J2VGIdM31k+
# eyuzTVUFbhLgjmgyOfSjmlzcbDveY0T6q9xN6TdFfm5Fv3/TjaNmVOGwzaCh
# SIG # End signature block
