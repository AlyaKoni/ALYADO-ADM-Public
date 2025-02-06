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

# SIG # Begin signature block
# MIIvGwYJKoZIhvcNAQcCoIIvDDCCLwgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCIYbBLxpr8rIbo
# 1BxR1L0Ld0O3jGqUX+89dbMCn7LSgqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxghnmMIIZ4gIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIE59IXec
# xhmxakgJyWXiTl1xI4nAZaFPhdGLg2s8quuQMA0GCSqGSIb3DQEBAQUABIICAG39
# 8gmSeozGagBgSobjgie/2xi6UzDt+iqfDKPybGgsgXsIa/XN4U2qrzz7AJ+HF+Ih
# pu96Or+O6iniECrYokx29FtfgywmWr/JqkhZysdzE8HqIR1/tz2i9/FndxV1ERS6
# R2Y/1xDh3v+Q5FQs90Dd7ZIDrI1wMg54fLqjuO/RnJPNivYHvOjP/7Y/xemENKLe
# qjP3EuTzpVA4+amtp1AunmhjoajoPg8e9SrZyVzeipfc+kF2Hoa0nhniKMdo3FzQ
# L/Jmidt1OE0Bp/e0AuSFvQvyMTLv7C4YeuCdT+8gclv4gCR4Q3aTBuYFzBblBGtn
# maggyv7UR4JOMT0/Jwc9XGcJ4fqe6dYoe2k6xo0jBhyesel9dMqoYRHv06KsX8L6
# B4PKLqvG2obtLe/CxQ5pizgJuNjuf2QQ0dAI6rESX8Vy8pnKO//sBX/7RcM7kRnh
# xZrrNfKui1Bd6Ha3TciIsWdJ65Q6yNsflt8QGGBgZKs55IKLP87sQ3BYIV4s47lD
# Ce2CJ3cS6BPZXf2d+02KLAYDTvjkXhEUPv56J1wssOD6QFsfCzr92cgrT335Zsty
# 2XhD9FMZXCA7vpYY1h5aW2M80YC+Y8yrhGojImbUvvz6GI2S/CGfuQJvFL2WxSBZ
# 8qqKFxDDCEly3yxvepunxn9ooASRuSykzhsfv2ywoYIWzTCCFskGCisGAQQBgjcD
# AwExgha5MIIWtQYJKoZIhvcNAQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEw
# gegGCyqGSIb3DQEJEAEEoIHYBIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCDJRAvKG/B4KkLGoC3zFWQ6e6r8RKnrAFsGVxTO9xxtNgIUF/2Q
# GUNU/NMcO6jHNkkNk5m8P5UYDzIwMjUwMjA2MTkxNDExWjADAgEBoGGkXzBdMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwq
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2IC0gMjAyMzExoIISVDCC
# BmwwggRUoAMCAQICEAGb6t7ITWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAwWzEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMT
# KEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjMx
# MTA3MTcxMzQwWhcNMzQxMjA5MTcxMzQwWjBdMQswCQYDVQQGEwJCRTEZMBcGA1UE
# CgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9y
# IENvZGVTaWduMSAtIFI2IC0gMjAyMzExMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
# MIIBigKCAYEA6oQ3UGg8lYW1SFRxl/OEcsmdgNMI3Fm7v8tNkGlHieUs2PGoan5g
# N0lzm7iYsxTg74yTcCC19SvXZgV1P3qEUKlSD+DW52/UHDUu4C8pJKOOdyUn4Ljz
# fWR1DJpC5cad4tiHc4vvoI2XfhagxLJGz2DGzw+BUIDdT+nkRqI0pz4Yx2u0tvu+
# 2qlWfn+cXTY9YzQhS8jSoxMaPi9RaHX5f/xwhBFlMxKzRmUohKAzwJKd7bgfiWPQ
# HnssW7AE9L1yY86wMSEBAmpysiIs7+sqOxDV8Zr0JqIs/FMBBHkjaVHTXb5zhMub
# g4htINIgzoGraiJLeZBC5oJCrwPr1NDag3rDLUjxzUWRtxFB3RfvQPwSorLAWapU
# l05tw3rdhobUOzdHOOgDPDG/TDN7Q+zw0P9lpp+YPdLGulkibBBYEcUEzOiimLAd
# M9DzlR347XG0C0HVZHmivGAuw3rJ3nA3EhY+Ao9dOBGwBIlni6UtINu41vWc9Q+8
# iL8nLMP5IKLBAgMBAAGjggGoMIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFPlOq764+Fv/wscD9EHunPjWdH0/MFYG
# A1UdIARPME0wCAYGZ4EMAQQCMEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8E
# AjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3Au
# Z2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdo
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0
# ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6
# MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNo
# YTM4NGc0LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAlfRnz5OaQ5KDF3bWIFW8if/k
# X7LlFRq3lxFALgBBvsU/JKAbRwczBEy0tGL/xu7TDMI0oJRcN5jrRPhf+CcKAr4e
# 0SQdI8svHKsnerOpxS8M5OWQ8BUkHqMVGfjvg+hPu2ieI299PQ1xcGEyfEZu8o/R
# nOhDTfqD4f/E4D7+3lffBmvzagaBaKsMfCr3j0L/wHNp2xynFk8mGVhz7ZRe5Bqi
# EIIHMjvKnr/dOXXUvItUP35QlTSfkjkkUxiDUNRbL2a0e/5bKesexQX9oz37obDz
# K3kPsUusw6PZo9wsnCsjlvZ6KrutxVe2hLZjs2CYEezG1mZvIoMcilgD9I/snE7Q
# 3+7OYSHTtZVUSTshUT2hI4WSwlvyepSEmAqPJFYiigT6tJqJSDX4b+uBhhFTwJN7
# OrTUNMxi1jVhjqZQ+4h0HtcxNSEeEb+ro2RTjlTic2ak+2Zj4TfJxGv7KzOLEcN0
# kIGDyE+Gyt1Kl9t+kFAloWHshps2UgfLPmJV7DOm5bga+t0kLgz5MokxajWV/vbR
# /xeKriMJKyGuYu737jfnsMmzFe12mrf95/7haN5EwQp04ZXIV/sU6x5a35Z1xWUZ
# 9/TVjSGvY7br9OIXRp+31wduap0r/unScU7Svk9i00nWYF9A43aZIETYSlyzXRrZ
# 4qq/TVkAF55gZzpHEqAwggZZMIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqG
# SIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMw
# EQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYy
# MDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDwAuIwI/rgG+GadLOvdYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64H
# iifuV6PENe2zNMeswwzrgGZt0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//
# NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe
# 9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirU
# IceU/kKWO/ELsX9/RpgOhz16ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0Kvq
# WsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50
# xHAotIB7vSqbu4ThDqxvDbm19m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU
# 2EESwVX9bpHFu7FMCEue1EIGbxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE
# 6giunUlnEYuC5a1ahqdm/TMDAd6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3s
# qSbldwKsDlcMCdFhniaI/MiyTdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac
# 0zd0hNkdZqs0c48efXxeltY9GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCC
# ASUwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3Ay
# Lmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8v
# Y3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0g
# ADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBv
# c2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZM
# v9sbB3DG+wsJrQA6YDMfOcYWaxlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7A
# I4zGhf5LFST5GETsH8KkrNCyz+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG
# 0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0
# +X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3Wd
# rG9KyC5qucqIwxIwTrIIc59eodaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXa
# jR63Wy+ILj198fKRMAWcznt8oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpI
# iScseeI85Zse46qEgok+wEr1If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ
# 7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx
# 773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZq
# HcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV
# 5yBZtnjGpGqqIpswggWDMIIDa6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG
# 9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEG
# A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAw
# MDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9v
# dCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxT
# aWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns8
# 9w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0b
# WsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZ
# gQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ
# 3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2M
# sonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI5
# 5KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPF
# OJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4Py
# XhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYF
# AJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWV
# ZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlw
# g3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4IC
# AQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/A
# VJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6x
# CCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc
# 053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6q
# TFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvd
# OxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJd
# w+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ
# 4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4Z
# sRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3
# nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZ
# xRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8w
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb
# 6t7ITWuP92w6ny4BJBYwCwYJYIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZI
# hvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEIE1IKGGpxaxq9fwPyhP3O9RMG2VkDqCm
# 1AB4gX08qpJ1MIGwBgsqhkiG9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe
# 4U9su3aCN6VF0BBb8EURveJfgqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJ
# KoZIhvcNAQELBQAEggGAEyQaKV1+Yyxkijjq6+eztvM1ws6X4L/uJPaIKFfcDnDs
# 5pfsiMKajLhxDonoHyhGSI19l9uUrQ0K3My+R0oSbh/evriLDQD9n1ECeFBOECQG
# WkS8zqYd7qC1zlDPFkdvxrm9hfxcaCoRKcS2O9MWra5w+a/RZCfayktCbAh6k4XP
# U/5/MZnqlskUHMtcOoSFRajaUQVYPy4I/K4Qa9r9Q8dmXkrUtjk51NpITcgHx37E
# nXDQLmNzi5XGUBfd/XA8jtF962IKvvUmdP2UxjqKPycfobDy9BIVS5JkVkIGrdQk
# GjaCj/rIn+wuJXlmLs+IzUT1guGwfz5izbSYaTn+RYAMJoHH2L+VG115GKfjHzNH
# SnqpGb8wgr5KB/eHsWDbvTZO8PBMCjiSC+gleWG45Pg5CR7fCSMs4icU+MyJf2i2
# SrfCZCM1WMdZ9tz07+DctEvceImv3PPNPu4KN26xiWwKfeaM5MZ0gjqEFLgH3GTD
# cM8EfEzmoyTO9AVmLe+Q
# SIG # End signature block
