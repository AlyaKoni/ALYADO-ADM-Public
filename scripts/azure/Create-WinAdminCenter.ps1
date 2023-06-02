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
    $StrgAccountDiag = New-AzStorageAccount -Name $DiagnosticStorageName -ResourceGroupName $DiagnosticResourceGroupName -Location $AlyaLocation -SkuName "Standard_LRS" -Kind StorageV2 -AccessTier Cool -Tag @{DisplayName="Diagnostic storage";Service="Logging"}
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
