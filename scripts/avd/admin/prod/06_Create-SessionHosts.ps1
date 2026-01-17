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
    16.11.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [ValidateSet("AD","AAD")]
    [String]
    $JoinOption = "AD",
    [ValidateSet("Image","Gallery")]
    [String]
    $ImageOption = "Gallery"
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\prod\Create-SessionHosts-$($AlyaTimeString).log" | Out-Null

# Constants
$ShResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdSessionHostsResGrp)"
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdManagementResGrp)"
$WorkspaceName = "$($AlyaNamingPrefix)avdw$($AlyaResIdAvdWorkspace)"
$HostPoolName = "$($AlyaNamingPrefix)avdh$($AlyaResIdAvdHostpool)"
$AvailabilitySetName = "$($AlyaNamingPrefix)avls$($AlyaResIdAvdSessionHostsResGrp)"
$SessionHostPrefix = "$($AlyaNamingPrefix)avd$($AlyaResIdAvdSessionHostsResGrp.Substring(1, 2))"
$SessionHostCount = $AlyaAvdSessionHostCount
$NetworkResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainNetwork)"
$VirtualNetworkName = "$($AlyaNamingPrefix)vnet$($AlyaAvdResIdVirtualNetwork)"
$VMSubnetName = "$($AlyaNamingPrefix)vnet$($AlyaAvdResIdVirtualNetwork)snet$($AlyaResIdAvdHostSNet)"
$DiagnosticResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$DiagnosticStorageName = "$($AlyaNamingPrefix)strg$($AlyaResIdDiagnosticStorage)"
$KeyVaultResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$LogAnaResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$LogAnaWrkspcName = "$($AlyaNamingPrefix)loga$($AlyaResIdLogAnalytics)"
$LogAnaStorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdAuditStorage)"
$VmImageResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdImageResGrp)"
$VmImageName = "$($AlyaNamingPrefix)avdi$($AlyaResIdAvdImageClient)"
$VmImageImageName = "$($VmImageName)_ImageClient"
$GalleryName = "$($AlyaNamingPrefix)imgg$($AlyaResIdAvdImageResGrp)"
$VmSize = $AlyaAvdVmSize
$VmAcceleratedNetworking = $AlyaAvdAcceleratedNetworking
$VmStartTime = $AlyaAvdStartTime
$VmStopTime = $AlyaAvdStopTime
$hostpoolShareServer = "$($AlyaNamingPrefix)serv$($AlyaResIdJumpHost)"
$hostpoolShareName = "$($HostPoolName)$"
if ($JoinOption -eq "AD")
{
    $DomJoinCredential = Get-Credential -Message "Account to join domain"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.DesktopVirtualization"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AVD | Create-SessionHosts | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking Management Ressource Group
Write-Host "Checking Management Ressource Group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    throw "Management Ressource Group not found. Please create the Management Ressource Group $ResourceGroupName"
}

# Checking HostPool
Write-Host "Checking HostPool" -ForegroundColor $CommandInfo
$HstPl = Get-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $HstPl)
{
    throw "HostPool not found. Please create the HostPool $HostPoolName with the script Create-HostPool.ps1"
}

# Checking workspace
Write-Host "Checking workspace" -ForegroundColor $CommandInfo
$WrkSpc = Get-AzWvdWorkspace -Name $WorkspaceName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $WrkSpc)
{
    throw "Workspace not found. Please create the workspace $WorkspaceName with the script Create-Workspace.ps1"
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ShResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ShResourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $ShResourceGroupName -Location $AlyaAvdSessionHostLocation -Tag @{displayName="AVD $($WrkSpc.FriendlyName) host pool";ownerEmail=$Context.Account.Id}
}

# Checking virtual network
Write-Host "Checking virtual network" -ForegroundColor $CommandInfo
$VNet = Get-AzVirtualNetwork -ResourceGroupName $NetworkResourceGroupName -Name $VirtualNetworkName -ErrorAction SilentlyContinue
if (-Not $VNet)
{
    throw "Virtual network not found. Please create the virtual network $VirtualNetworkName with the script Configure-Network.ps1"
}

# Checking network subnets
Write-Host "Checking network subnets" -ForegroundColor $CommandInfo
$Subnet = $VNet.Subnets | Where-Object { $_.Name -eq $VMSubnetName }
if (-Not $Subnet)
{
    throw "Virtual network subnet not found. Please create the virtual network subnet $VMSubnetName with the script Configure-Network.ps1"
}
$Subnet = Get-AzVirtualNetworkSubnetConfig -Name $VMSubnetName -VirtualNetwork $VNet

# Checking storage account
Write-Host "Checking diag storage account" -ForegroundColor $CommandInfo
$StrgAccountDiag = Get-AzStorageAccount -ResourceGroupName $DiagnosticResourceGroupName -Name $DiagnosticStorageName -ErrorAction SilentlyContinue
if (-Not $StrgAccountDiag)
{
    Write-Warning "Storage account not found. Creating the storage account $DiagnosticStorageName"
    $StrgAccountDiag = New-AzStorageAccount -Name $DiagnosticStorageName -ResourceGroupName $DiagnosticResourceGroupName -Location $AlyaAvdSessionHostLocation -SkuName "Standard_LRS" -Kind StorageV2 -MinimumTlsVersion "TLS1_2" -AccessTier Cool -Tag @{displayName="AVD Diagnostic Log Storage"}
    if (-Not $StrgAccountDiag)
    {
        Write-Error "Storage account $DiagnosticStorageName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Checking availability set
Write-Host "Checking availability set" -ForegroundColor $CommandInfo
$AvSet = Get-AzAvailabilitySet -ResourceGroupName $ShResourceGroupName -Name $AvailabilitySetName -ErrorAction SilentlyContinue
if (-Not $AvSet)
{
    Write-Warning "Availability set not found. Creating the availability set $AvailabilitySetName"
    $AvSet = New-AzAvailabilitySet -ResourceGroupName $ShResourceGroupName -Name $AvailabilitySetName -Location $AlyaAvdSessionHostLocation -PlatformFaultDomainCount 2 -PlatformUpdateDomainCount 2 -Sku Aligned
}

# Checking key vault
Write-Host "Checking key vault" -ForegroundColor $CommandInfo
$KeyVault = Get-AzKeyVault -ResourceGroupName $KeyVaultResourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue
if (-Not $KeyVault)
{
    Write-Warning "Key Vault not found. Creating the Key Vault $KeyVaultName"
    $KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $KeyVaultResourceGroupName -Location $AlyaLocation -Sku Standard
    if (-Not $KeyVault)
    {
        Write-Error "Key Vault $KeyVaultName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Checking log analytics workspace
Write-Host "Checking log analytics workspace" -ForegroundColor $CommandInfo
$LogAnaWrkspc = Get-AzOperationalInsightsWorkspace -ResourceGroupName $LogAnaResourceGroupName -Name $LogAnaWrkspcName -ErrorAction SilentlyContinue
if (-Not $LogAnaWrkspc)
{
    throw "Log analytics workspace not found. Please create the log analytics workspace $LogAnaWrkspcName with the script Configure-LogAnalytics.ps1"
}

# Checking storage account
Write-Host "Checking storage account" -ForegroundColor $CommandInfo
$StrgAccount = Get-AzStorageAccount -ResourceGroupName $LogAnaResourceGroupName -Name $LogAnaStorageAccountName -ErrorAction SilentlyContinue
if (-Not $StrgAccount)
{
    throw "Storage account not found. Please create the storage account $LogAnaStorageAccountName with the script Configure-LogAnalytics.ps1"
}

if ($ImageOption -eq "Image")
{
	
	# Checking vm image
	Write-Host "Checking vm image" -ForegroundColor $CommandInfo
	$image = Get-AzImage -ResourceGroupName $VmImageResourceGroupName -ImageName $VmImageImageName -ErrorAction SilentlyContinue
	if (-Not $image)
	{
		throw "VM image $VmImageImageName not found. Please create it with the script Prepare-ImageClient"
	}

}
else
{
	
	# Checking image versions
	Write-Host "Checking image versions" -ForegroundColor $CommandInfo
	$ImgVersions = Get-AzGalleryImageVersion -ResourceGroupName $VmImageResourceGroupName -GalleryName $GalleryName -GalleryImageDefinitionName $VmImageImageName -ErrorAction SilentlyContinue
	$maxVersion = [Version]"0.0.0"
	foreach ($version in $ImgVersions)
	{
		$actVersion = [Version]$version.Name
		if ($actVersion -gt $maxVersion)
		{
			$maxVersion = $actVersion
			$image = $version
		}
	}
	
}

# Checking session hosts
for ($h = 0; $h -lt $SessionHostCount; $h++)
{
    $VMName = $SessionHostPrefix+"-"+$h
    $VMNicName = "$($VMName)nic1"
    $VMDiskName = "$($VMName)osdisk"
    $LogAnaDiagnosticRuleName = "$($VMName)diag"
    Write-Host "Checking session host $VMName" -ForegroundColor $CommandInfo

    # Checking azure key vault secret
    Write-Host "Checking azure key vault secret"
    $ImageHostCredentialAssetName = "$($VMName)AdminCredential"
    $AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ImageHostCredentialAssetName -ErrorAction SilentlyContinue
    if (-Not $AzureKeyVaultSecret)
    {
        Write-Warning "Key Vault secret not found. Creating the secret $ImageHostCredentialAssetName"
        $VMPassword = "*" + [Guid]::NewGuid().ToString() + "$"
        $VMPasswordSec = ConvertTo-SecureString $VMPassword -AsPlainText -Force
        $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ImageHostCredentialAssetName -SecretValue $VMPasswordSec
    }
    else
    {
        $VMPassword = ($AzureKeyVaultSecret.SecretValue | Foreach-Object { [System.Net.NetworkCredential]::new("", $_).Password })
        $VMPasswordSec = ConvertTo-SecureString $VMPassword -AsPlainText -Force
    }
    Clear-Variable -Name "VMPassword" -Force -ErrorAction SilentlyContinue

    # Checking vm nic
    Write-Host "Checking vm nic"
    $VMNic = Get-AzNetworkInterface -ResourceGroupName $ShResourceGroupName -Name $VMNicName -ErrorAction SilentlyContinue
    if (-Not $VMNic)
    {
        Write-Warning "VM nic not found. Creating the vm nic $VMNicName"
        $VMNic = New-AzNetworkInterface -ResourceGroupName $ShResourceGroupName -Name $VMNicName -Location $AlyaAvdSessionHostLocation -SubnetId $Subnet.Id -EnableAcceleratedNetworking:$VmAcceleratedNetworking 
        Set-AzNetworkInterface -NetworkInterface $VMNic
    }

    # Checking image host vm
    Write-Host "Checking session host vm"
    $SessionHostVm = Get-AzVM -ResourceGroupName $ShResourceGroupName -Name $VMName -Status -ErrorAction SilentlyContinue
    $vmAdminName = "$($VMName)admin"
    if (-Not $SessionHostVm)
    {
        Write-Warning "Session host vm not found. Creating the session host vm $VMName"
        #Get-AzVMSize -Location $AlyaAvdSessionHostLocation | Where-Object { $_.Name -like "Standard_D8s*" }
        #Get-AzVMImagePublisher -Location $AlyaAvdSessionHostLocation
        #Get-AzVMImageOffer -Location $AlyaAvdSessionHostLocation -PublisherName "MicrosoftWindowsDesktop"
        $VMCredential = New-Object System.Management.Automation.PSCredential ($vmAdminName, $VMPasswordSec)
        #TODO -LicenseType $AlyaVmLicenseType if server and hybrid benefit
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VmSize -AvailabilitySetId $AvSet.Id -LicenseType "Windows_Client" -IdentityType SystemAssigned
        $VMConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VMName -Credential $VMCredential -TimeZone $AlyaTimeZone | Out-Null
        $VMConfig | Set-AzVMSourceImage -Id $image.Id
        $VMConfig | Add-AzVMNetworkInterface -Id $VMNic.Id | Out-Null
        $VMConfig | Set-AzVMOSDisk -Name $VMDiskName -CreateOption FromImage -Caching ReadWrite -DiskSizeInGB 128 | Out-Null
        $VMConfig | Set-AzVMBootDiagnostic -Enable -ResourceGroupName $DiagnosticResourceGroupName -StorageAccountName $DiagnosticStorageName | Out-Null
        $null = New-AzVM -ResourceGroupName $ShResourceGroupName -Location $AlyaAvdSessionHostLocation -VM $VMConfig -DisableBginfoExtension
        $SessionHostVm = Get-AzVM -ResourceGroupName $ShResourceGroupName -Name $VMName
        $null = Set-AzResource -ResourceId $SessionHostVm.Id -Tag @{displayName="AVD $($WrkSpc.FriendlyName) host $h";ownerEmail=$Context.Account.Id;startTime=$VmStartTime;stopTime=$VmStopTime} -Force
        $SessionHostVm = Get-AzVM -ResourceGroupName $ShResourceGroupName -Name $VMName -Status
    }

    # Starting image vm if not running
    Write-Host "Starting session host if not running"
    if (-Not ($SessionHostVm.Statuses | Where-Object { $_.Code -eq "PowerState/running"}))
    {
        Write-Warning "Starting VM $VMName"
        Start-AzVM -ResourceGroupName $ShResourceGroupName -Name $VMName
    }
    $SessionHostVm = Get-AzVM -ResourceGroupName $ShResourceGroupName -Name $VMName

    <#
    # Setting auto shutdown on vm
    Write-Host "Setting auto shutdown on vm"
    $SubscriptionId = $Context.Subscription.Id
    $ScheduledShutdownResourceId = "/subscriptions/$($Context.Subscription.Id)/resourceGroups/$ShResourceGroupName/providers/microsoft.devtestlab/schedules/shutdown-computevm-$VMName"
    $Properties = @{}
    $Properties.Add('status', 'Enabled')
    $Properties.Add('taskType', 'ComputeVmShutdownTask')
    $Properties.Add('dailyRecurrence', @{'time'= 2200})
    $Properties.Add('timeZoneId', $AlyaTimeZone)
    $Properties.Add('notificationSettings', @{status='Disabled'; timeInMinutes=15})
    $Properties.Add('targetResourceId', $SessionHostVm.Id)
    New-AzResource -Location $AlyaAvdSessionHostLocation -ResourceId $ScheduledShutdownResourceId -Properties $Properties -Force
    #>

    # Setting diagnostic setting
    Write-Host "Setting diagnostic setting"
    $catListLog = @(); $catListMetric = @()
    Get-AzDiagnosticSettingCategory -ResourceId $SessionHostVm.Id | ForEach-Object {
        if ($_.CategoryType -eq "Logs")
        {
	        $catListLog += (New-AzDiagnosticSettingLogSettingsObject -Category $_.Name -Enabled $true)
        }
        else
        {
	        $catListMetric += (New-AzDiagnosticSettingMetricSettingsObject -Category $_.Name -Enabled $true)
        }
    }
    #$diagSetting = New-AzDiagnosticSetting -Name $LogAnaDiagnosticRuleName -ResourceId $SessionHostVm.Id -Log $catListLog -Metric $catListMetric -WorkspaceId $LogAnaWrkspc.ResourceId -StorageAccountId $StrgAccount.Id
    $diagSetting = New-AzDiagnosticSetting -Name $LogAnaDiagnosticRuleName -ResourceId $SessionHostVm.Id -Log $catListLog -Metric $catListMetric -WorkspaceId $LogAnaWrkspc.ResourceId -StorageAccountId $StrgAccountDiag.Id
    
    # Checking guest level diagnostics vm extension
    Write-Host "Checking guest level diagnostics vm extension"
    $VmExtName = "$($VMName)GuestLevelDiagnostics"
    $VmExt = Get-AzVMExtension -ResourceGroupName $ShResourceGroupName -VMName $VMName -Name $VmExtName -ErrorAction SilentlyContinue
    if (-Not $VmExt)
    {
        Write-Warning "$VmExtName extension on vm not found. Installing $VmExtName on vm $VMName"
        #Get-AzVmImagePublisher -Location $AlyaAvdSessionHostLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select-Object Type, Version
        #Get-Command Set-Az*Extension* -Module Az.Compute
        #$Extension = Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Diagnostics.IaaSDiagnostics" -Type "IaaSAntimalware" | Select-Object -last 1
        $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Diagnostics" -Type "IaaSDiagnostics" | %{ new-object System.Version ($_.Version) } | Sort | Select-Object -Last 1).ToString()
        $typeHandlerVerMjandMn = $typeHandlerVer.split(".")
        $typeHandlerVerMjandMn = $typeHandlerVerMjandMn[0] + "." + $typeHandlerVerMjandMn[1]
        $diagSettings = @'
{
  "StorageAccount": "##DIAGSTORAGEACCOUNTNAME##",
  "WadCfg": {
    "DiagnosticMonitorConfiguration": {
      "overallQuotaInMB": 5120,
      "Metrics": {
        "resourceId": "##VMRESOURCEID##",
        "MetricAggregation": [
          {
            "scheduledTransferPeriod": "PT1H"
          },
          {
            "scheduledTransferPeriod": "PT1M"
          }
        ]
      },
      "DiagnosticInfrastructureLogs": {
        "scheduledTransferLogLevelFilter": "Error"
      },
      "PerformanceCounters": {
        "scheduledTransferPeriod": "PT1M",
        "PerformanceCounterConfiguration": [
          {
            "counterSpecifier": "\\Processor Information(_Total)\\% Processor Time",
            "unit": "Percent",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Processor Information(_Total)\\% Privileged Time",
            "unit": "Percent",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Processor Information(_Total)\\% User Time",
            "unit": "Percent",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Processor Information(_Total)\\Processor Frequency",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\System\\Processes",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Process(_Total)\\Thread Count",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Process(_Total)\\Handle Count",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\System\\System Up Time",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\System\\Context Switches/sec",
            "unit": "CountPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\System\\Processor Queue Length",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Memory\\% Committed Bytes In Use",
            "unit": "Percent",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Memory\\Available Bytes",
            "unit": "Bytes",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Memory\\Committed Bytes",
            "unit": "Bytes",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Memory\\Cache Bytes",
            "unit": "Bytes",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Memory\\Pool Paged Bytes",
            "unit": "Bytes",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Memory\\Pool Nonpaged Bytes",
            "unit": "Bytes",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Memory\\Pages/sec",
            "unit": "CountPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Memory\\Page Faults/sec",
            "unit": "CountPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Process(_Total)\\Working Set",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Process(_Total)\\Working Set - Private",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\% Disk Time",
            "unit": "Percent",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\% Disk Read Time",
            "unit": "Percent",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\% Disk Write Time",
            "unit": "Percent",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\% Idle Time",
            "unit": "Percent",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\Disk Bytes/sec",
            "unit": "BytesPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\Disk Read Bytes/sec",
            "unit": "BytesPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\Disk Write Bytes/sec",
            "unit": "BytesPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\Disk Transfers/sec",
            "unit": "BytesPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\Disk Reads/sec",
            "unit": "BytesPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\Disk Writes/sec",
            "unit": "BytesPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\Avg. Disk sec/Transfer",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\Avg. Disk sec/Read",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\Avg. Disk sec/Write",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\Avg. Disk Queue Length",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\Avg. Disk Read Queue Length",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\Avg. Disk Write Queue Length",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\% Free Space",
            "unit": "Percent",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\LogicalDisk(_Total)\\Free Megabytes",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Network Interface(*)\\Bytes Total/sec",
            "unit": "BytesPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Network Interface(*)\\Bytes Sent/sec",
            "unit": "BytesPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Network Interface(*)\\Bytes Received/sec",
            "unit": "BytesPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Network Interface(*)\\Packets/sec",
            "unit": "BytesPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Network Interface(*)\\Packets Sent/sec",
            "unit": "BytesPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Network Interface(*)\\Packets Received/sec",
            "unit": "BytesPerSecond",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Network Interface(*)\\Packets Outbound Errors",
            "unit": "Count",
            "sampleRate": "PT60S"
          },
          {
            "counterSpecifier": "\\Network Interface(*)\\Packets Received Errors",
            "unit": "Count",
            "sampleRate": "PT60S"
          }
        ]
      },
      "WindowsEventLog": {
        "scheduledTransferPeriod": "PT1M",
        "DataSource": [
          {
            "name": "Application!*[System[(Level = 1 or Level = 2 or Level = 3)]]"
          },
          {
            "name": "Security!*[System[band(Keywords,4503599627370496)]]"
          },
          {
            "name": "System!*[System[(Level = 1 or Level = 2 or Level = 3)]]"
          }
        ]
      }
    }
  }
}
'@
        $diagSettings = $diagSettings.Replace("##DIAGSTORAGEACCOUNTNAME##", $DiagnosticStorageName).Replace("##VMRESOURCEID##", $SessionHostVm.Id)
        $tmpFile = New-TemporaryFile
        $diagSettings | Set-Content -Path $tmpFile.FullName -Encoding UTF8 -Force
        Set-AzVMDiagnosticsExtension -Name $VmExtName -ResourceGroupName $ShResourceGroupName -VMName $VMName -DiagnosticsConfigurationPath $tmpFile.FullName
        Remove-Item -Path $tmpFile.FullName -Force -ErrorAction SilentlyContinue
    }

    # Checking monitoring vm extension
    Write-Host "Checking monitoring vm extension"
    $VmExtName = "$($VMName)Monitoring"
    $VmExt = Get-AzVMExtension -ResourceGroupName $ShResourceGroupName -VMName $VMName -Name $VmExtName -ErrorAction SilentlyContinue
    if (-Not $VmExt)
    {
        Write-Warning "$VmExtName extension on vm not found. Installing $VmExtName on vm $VMName"
        #Get-AzVmImagePublisher -Location $AlyaAvdSessionHostLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select-Object Type, Version
        #Get-Command Set-Az*Extension* -Module Az.Compute
        #$Extension = Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | Select-Object -last 1
        $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Monitor" -Type "AzureMonitorWindowsAgent" | %{ new-object System.Version ($_.Version) } | Sort | Select-Object -Last 1).ToString()
        $typeHandlerVerMjandMn = $typeHandlerVer.split(".")
        $typeHandlerVerMjandMn = $typeHandlerVerMjandMn[0] + "." + $typeHandlerVerMjandMn[1]
        $PublicSettings = @{"workspaceId" = $LogAnaWrkspc.CustomerId}
        $key = Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $LogAnaResourceGroupName -Name $LogAnaWrkspcName
        $ProtectedSettings = @{"workspaceKey" = $key.PrimarySharedKey}
        $VmExt = Set-AzVMExtension -ResourceGroupName $ShResourceGroupName -VMName $VMName -Location $AlyaAvdSessionHostLocation `
            -Publisher "Microsoft.Azure.Monitor" -ExtensionType "AzureMonitorWindowsAgent" -Name $VmExtName `
            -Settings $PublicSettings -ProtectedSettings $ProtectedSettings -TypeHandlerVersion $typeHandlerVerMjandMn
    }

    # Checking dependency agent vm extension
    Write-Host "Checking dependency agent vm extension"
    $VmExtName = "$($VMName)DependencyAgent"
    $VmExt = Get-AzVMExtension -ResourceGroupName $ShResourceGroupName -VMName $VMName -Name $VmExtName -ErrorAction SilentlyContinue
    if (-Not $VmExt)
    {
        Write-Warning "$VmExtName extension on vm not found. Installing $VmExtName on vm $VMName"
        #Get-AzVmImagePublisher -Location $AlyaAvdSessionHostLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select-Object Type, Version
        #Get-Command Set-Az*Extension* -Module Az.Compute
        #$Extension = Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | Select-Object -last 1
        $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Monitoring.DependencyAgent" -Type "DependencyAgentWindows" | %{ new-object System.Version ($_.Version) } | Sort | Select-Object -Last 1).ToString()
        $typeHandlerVerMjandMn = $typeHandlerVer.split(".")
        $typeHandlerVerMjandMn = $typeHandlerVerMjandMn[0] + "." + $typeHandlerVerMjandMn[1]
        $VmExt = Set-AzVMExtension -ResourceGroupName $ShResourceGroupName -VMName $VMName -Location $AlyaAvdSessionHostLocation `
            -Publisher "Microsoft.Azure.Monitoring.DependencyAgent" -ExtensionType "DependencyAgentWindows" -Name $VmExtName `
            -TypeHandlerVersion $typeHandlerVerMjandMn
    }

    # Checking anti malware vm extension
    Write-Host "Checking anti malware vm extension"
    $VmExtName = "$($VMName)AntiMalware"
    $VmExt = Get-AzVMExtension -ResourceGroupName $ShResourceGroupName -VMName $VMName -Name $VmExtName -ErrorAction SilentlyContinue
    if (-Not $VmExt)
    {
        Write-Warning "$VmExtName extension on vm not found. Installing $VmExtName on vm $VMName"
        #Get-AzVmImagePublisher -Location $AlyaAvdSessionHostLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select-Object Type, Version
            #$Extension = Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | Select-Object -last 1
        $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | %{ new-object System.Version ($_.Version) } | Sort | Select-Object -Last 1).ToString()
        $typeHandlerVerMjandMn = $typeHandlerVer.split(".")
        $typeHandlerVerMjandMn = $typeHandlerVerMjandMn[0] + "." + $typeHandlerVerMjandMn[1]
        $amsettings = @'
            {
                "AntimalwareEnabled": true,
                "RealtimeProtectionEnabled": true,
                "ScheduledScanSettings": {
                    "isEnabled": true,
                    "day": 7,
                    "time": 720,
                    "scanType": "Quick"
                },
                "Exclusions": {
                    "Extensions": ".vhd;.vhdx",   
                    "Paths": "C:\\ProgramFiles\\FSLogix\\Apps",
                    "Processes": "mssence.svc;frxccd.exe;frxccds.exe;frxsvc.exe"
                }
            }
'@
        $VmExt = Set-AzVMExtension -ResourceGroupName $ShResourceGroupName -VMName $VMName -Location $AlyaAvdSessionHostLocation `
            -Publisher "Microsoft.Azure.Security" -ExtensionType "IaaSAntimalware" -Name $VmExtName `
            -SettingString $amsettings -TypeHandlerVersion $typeHandlerVerMjandMn
    }

    if ($JoinOption -eq "AAD")
    {

        # Checking aad join vm extension
        Write-Host "Checking aad join vm extension"
        $VmDomainJoinExtName = "$($VMName)AadJoin"
        $VmDomainJoinExt = Get-AzVMExtension -ResourceGroupName $ShResourceGroupName -VMName $VMName -Name $VmDomainJoinExtName -ErrorAction SilentlyContinue
        if (-Not $VmDomainJoinExt)
        {
            Write-Warning "$VmDomainJoinExtName extension on vm not found. Installing $VmDomainJoinExtName on vm $VMName"
            $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.ActiveDirectory" -Type "AADLoginForWindows" | %{ new-object System.Version ($_.Version) } | Sort | Select-Object -Last 1).ToString()
            $typeHandlerVerMjandMn = $typeHandlerVer.split(".")
            $typeHandlerVerMjandMn = $typeHandlerVerMjandMn[0] + "." + $typeHandlerVerMjandMn[1]
            $VmExt = Set-AzVMExtension -ResourceGroupName $ShResourceGroupName -VMName $VMName -Location $AlyaAvdSessionHostLocation `
                -Publisher "Microsoft.Azure.ActiveDirectory" -ExtensionType "AADLoginForWindows" -Name $VmDomainJoinExtName `
                -TypeHandlerVersion $typeHandlerVerMjandMn

            # Restarting session vm if not running
            Write-Host "Restarting session vm"
            Restart-AzVM -ResourceGroupName $ShResourceGroupName -Name $VMName
        }
    
    }
    else
    {

        # Checking domain join vm extension
        $DomJoinOption = 0x00000003
        $VmDomainJoinExtName = "$($VMName)DomainJoin"
        Write-Host "Checking domain join vm extension $VmDomainJoinExtName"
        $VmDomainJoinExt = Get-AzVMADDomainExtension -ResourceGroupName $ShResourceGroupName -VMName $VMName -Name $VmDomainJoinExtName -ErrorAction SilentlyContinue
        if (-Not $VmDomainJoinExt)
        {
            Write-Host "  Does not exist. Creating it now" -ForegroundColor $CommandWarning
            Write-Warning "  **ATTENTION**: Make sure your account is already with AADDS synced!"
            $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Compute" -Type "JsonADDomainExtension" | %{ new-object System.Version ($_.Version) } | Sort | Select-Object -Last 1).ToString()
            $typeHandlerVerMjandMn = $typeHandlerVer.split(".")
            $typeHandlerVerMjandMn = $typeHandlerVerMjandMn[0] + "." + $typeHandlerVerMjandMn[1]
            Set-AzVMADDomainExtension -ResourceGroupName $ShResourceGroupName -VMName $VMName -Location $AlyaAvdSessionHostLocation `
                -Name $VmDomainJoinExtName -DomainName $AlyaDomainName -JoinOption $DomJoinOption -Credential $DomJoinCredential -Restart `
                -TypeHandlerVersion $typeHandlerVerMjandMn 

            # Restarting session vm if not running
            Write-Host "Restarting session vm"
            Restart-AzVM -ResourceGroupName $ShResourceGroupName -Name $VMName
        }

    }

    # Checking avd agent registration token
    Write-Host "Checking avd agent registration token"
    $HstPlRegInf = Get-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName
    if ($HstPlRegInf.ExpirationTime -lt (Get-Date).AddHours(1))
    {
        Write-Warning "Registration token has expired. Creating a new one."
        $HstPlRegInf = New-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
            -ExpirationTime $((get-date).ToUniversalTime().AddDays(1).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))
    }

    # Configuring vm with avd agent and fslogix
    Write-Host "Configuring vm with avd agent and fslogix"
    $VmExtName = "$($VMName)AvdConfiguration"
    $VmExt = Get-AzVMCustomScriptExtension -ResourceGroupName $ShResourceGroupName -VMName $VMName -Name $VmExtName -ErrorAction SilentlyContinue
    if (-Not $VmExt)
    {
        Write-Warning "$VmExtName extension on vm not found. Installing $VmExtName on vm $VMName"
        $ctx = $StrgAccountDiag.Context
        $container = Get-AzStorageContainer -Context $ctx -Name "$VMName" -ErrorAction SilentlyContinue
        if (-Not $container)
        {
            $container = New-AzStorageContainer -Context $ctx -Name "$VMName" -Permission Blob
        }
        $FilePath = Join-Path $env:TEMP "$VmExtName.ps1"
        $installScript = @'
$logPath = Join-Path (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "AzureVirtualDesktop") "AvdConfiguration.log"
Start-Transcript -Path $logPath -Force

# Configuring share properties
Write-Host "Configuring share properties"
[string]$hostpoolShareServer = "<SHARESERVER>.<CUSTDOMAIN>"
[string]$hostpoolShareName = "<SHARENAME>"
[string[]]$LocalAdmins = @("<VMADMIN>", "<ACTADMIN>", "<CUSTDOMAIN>\AAD DC Administrators")
$uncPath = "\\$($hostpoolShareServer)\$($hostpoolShareName)"
if (-Not (Test-Path $uncPath))
{
    Write-Error "Not able to access unc path $uncPath" -ErrorAction Continue
}

# Configure Regional Settings
Write-Host "Configure Regional Settings"
Set-Timezone -Id "<CUSTTIMEZONE>"
Set-WinHomeLocation -GeoId <CUSTGEOID>

# Azure Virtual Desktop Agent install
Write-Host "Azure Virtual Desktop Agent installation"
$downloadUrl = "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv"
Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -Method Get -OutFile "AVDAgent.msi"
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i AVDAgent.msi", "/quiet", "/qn", "/norestart", "/passive", "REGISTRATIONTOKEN=<TOKEN>", "/l* C:\Users\AgentInstall.txt" -Wait -Passthru

Start-Sleep -Seconds 30

# Azure Virtual Desktop Bootloader install
Write-Host "Azure Virtual Desktop Bootloader installation"
$downloadUrl = "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH"
Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -Method Get -OutFile "AVDBootloader.msi"
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i AVDBootloader.msi", "/quiet", "/qn", "/norestart", "/passive", "/l* C:\Users\AgentBootLoaderInstall.txt" -Wait -Passthru

Start-Sleep -Seconds 30

# Enable PSRemoting
Write-Host "Enable PSRemoting"
Enable-PSRemoting -Force
New-NetFirewallRule -Name "Allow WinRM HTTPS" -DisplayName "WinRM HTTPS" -Enabled True -Profile Any -Action Allow -Direction Inbound -LocalPort 5986 -Protocol TCP
$cert = Get-ChildItem "Cert:\LocalMachine\My" -Recurse | Where-Object { $_.DnsNameList -eq $env:COMPUTERNAME }
if(-Not $cert)
{
    $thumbprint = (New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation "Cert:\LocalMachine\My").Thumbprint
}
else
{
    $thumbprint = $cert.Thumbprint
}
$command = "winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=""$env:computername""; CertificateThumbprint=""$thumbprint""}"
cmd.exe /C $command

# Configure FSLogix
Write-Host "Configure FSLogix"
$fslogixAppsRegPath = "HKLM:\SOFTWARE\FSLogix\Apps"
$fslogixProfileRegPath = "HKLM:\SOFTWARE\FSLogix\Profiles"
$fslogixContainerRegPath = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
if (!(Test-Path $fslogixAppsRegPath))
{
    New-Item -Path $fslogixAppsRegPath -Force
}
if (!(Test-Path $fslogixProfileRegPath))
{
    New-Item -Path $fslogixProfileRegPath -Force
}
New-ItemProperty -Path $fslogixProfileRegPath -Name "Enabled" -Value "1" -PropertyType DWORD -Force
New-ItemProperty -Path $fslogixProfileRegPath -Name "VHDLocations" -Value "$uncPath\Profiles" -PropertyType MultiString -Force
if (!(Test-Path $fslogixContainerRegPath))
{
    New-Item -Path $fslogixContainerRegPath -Force
}
New-ItemProperty -Path $fslogixContainerRegPath -Name "Enabled" -Value "1" -PropertyType DWORD -Force
New-ItemProperty -Path $fslogixContainerRegPath -Name "VHDLocations" -Value "$uncPath\Containers" -PropertyType MultiString -Force

# Configure local groups
Write-Host "Configure local groups"
foreach($LocalAdmin in $LocalAdmins)
{
    $adminsGroup = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value
    Add-LocalGroupMember -Group "$adminsGroup" -Member $LocalAdmin -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "$adminsGroup" -Member $LocalAdmin -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "FSLogix ODFC Exclude List" -Member $LocalAdmin -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "FSLogix Profile Exclude List" -Member $LocalAdmin -ErrorAction SilentlyContinue
}

#Get-Service -Name "WSearch" | Set-Service -StartupType Automatic
$drv = Get-WmiObject win32_volume -filter 'DriveLetter = "E:"'
if ($drv)
{
    $drv.DriveLetter = "G:"
    $drv.Put()
}

Stop-Transcript
'@
        $installScript = $installScript.Replace('<ACTADMIN>', $Context.Account.Id)
        $installScript = $installScript.Replace('<VMADMIN>', $vmAdminName)
        $installScript = $installScript.Replace('<CUSTDOMAIN>', $AlyaDomainName)
        $installScript = $installScript.Replace('<SHARESERVER>', $hostpoolShareServer)
        $installScript = $installScript.Replace('<SHARENAME>', $hostpoolShareName)
        $installScript = $installScript.Replace('<CUSTTIMEZONE>', $AlyaTimeZone)
        $installScript = $installScript.Replace('<CUSTGEOID>', $AlyaGeoId)
        $installScript = $installScript.Replace('<TOKEN>', $HstPlRegInf.Token)

        $installScript | Set-Content -Path $FilePath -Encoding UTF8 -Force
        $blob = Get-AzStorageBlob -Context $ctx -Container "$VMName" -Blob "$VmExtName.ps1" -ErrorAction SilentlyContinue
        if (-Not $blob -or -Not $blob.ICloudBlob.Exists())
        {
            Set-AzStorageBlobContent -Context $ctx -Container "$VMName" -Blob "$VmExtName.ps1" -File $FilePath -BlobType Block -Force
        }
        else
        {
            $blob | Set-AzStorageBlobContent -File $FilePath -Force
        }
        Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        $StrgKeys = Get-AzStorageAccountKey -ResourceGroupName $DiagnosticResourceGroupName -Name $DiagnosticStorageName
        $StrgKey = $StrgKeys.GetValue(0).Value
        #Get-AzVmImagePublisher -Location $AlyaAvdSessionHostLocation | Where-Object { $_.PublisherName -like "Microsoft.*" }
        #(Get-AzVMExtensionImageType -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Compute").Type
        #Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Compute" -Type CustomScriptExtension
        $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Compute" -Type "CustomScriptExtension" | %{ new-object System.Version ($_.Version) } | Sort | Select-Object -Last 1).ToString()
        $typeHandlerVerMjandMn = $typeHandlerVer.split(".")
        $typeHandlerVerMjandMn = $typeHandlerVerMjandMn[0] + "." + $typeHandlerVerMjandMn[1]
        $VmExt = Set-AzVMCustomScriptExtension -ResourceGroupName $ShResourceGroupName -Location $AlyaAvdSessionHostLocation `
            -VMName $VMName -Name $VmExtName -StorageAccountName $DiagnosticStorageName `
            -StorageAccountKey $StrgKey -ContainerName "$VMName" -FileName "$VmExtName.ps1" `
            -Run "$VmExtName.ps1" -SecureExecution -TypeHandlerVersion $typeHandlerVerMjandMn
        Get-AzStorageBlob -Context $ctx -Container "$VMName" -Blob "$VmExtName.ps1" | Remove-AzStorageBlob -Force

        # Restarting session vm if not running
        Write-Host "Restarting session vm"
        Restart-AzVM -ResourceGroupName $ShResourceGroupName -Name $VMName
    }

}
Clear-Variable -Name "DomJoinCredential" -Force -ErrorAction SilentlyContinue

#Setting role on resourcegroup
& "$PSScriptRoot\07_Configure-AutoStartRole.ps1"

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIvCQYJKoZIhvcNAQcCoIIu+jCCLvYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDjZs3khca3G6yA
# 0Lc/3C/9mgAyp/XaBYPvTKRJQ4AzRqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBgp9Sqf
# M1ZzZ63UFI6fknIDWCb2qruw+87WPlUivvsSMA0GCSqGSIb3DQEBAQUABIICABTc
# qDZU3HAoVNA1lQznIVdIjpozO3ZILBNuan2n5C9zUfl82CFIdglr03cMfZWWPU3V
# XhYEPfptE67yfF+Zs+jMHy0dI1QIV0TELOwvYMw0kDd/roa6K9+vhQnTtlJ1x919
# NH9Y2A9fBkfsjshh8xmxPl2rBLSLT576NNhSCa8ZyAqs29NMLu2DBGvK+PKeggfG
# s4cSCmBi74ChU0eb3qOhE8DdWXga5m0FSeh9Kp5M4KaFxFnBA5MVZ6CHpIJGns26
# ayowcAGRa2y7WWN1zENzVCv3EjlH4Cu4lT+uJ8hEGVLu+XF2TmN5V4XYxMCowkMV
# HI154e8A2tzKEuQDfDtW0RTGoI8ju7gb0ee4M1bab3igNWfzFe4KaAgnoxe7V2zy
# kOIeXnE7DSdX3MzH6Nlfj8IOEtmWi/CXKwD3C47WwCxq/T5JAVef7t1O7L9hFlOI
# ppIINnpHc6oDFltzX5u65Cuw5rz9CgnTNH4tAUi1tzcEQCltWBeM3Ac+nbf7Fz1+
# HIJX6W7DLCwkW8a6YysA4ZLseogyk9iJCizafml9Z7mEY8fThYG1Abx5got9hlzI
# 7gob3ufKSM3QMRJ4DHbkjvH6isqsaaGXx7DHvRzM7QAKjRdGVFga9XIkR5HNmKjl
# 7sCHwOydYxtMLlwdKLqI0t+bGOxa5h8qIDHfeFHqoYIWuzCCFrcGCisGAQQBgjcD
# AwExghanMIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEw
# gd8GCyqGSIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCCa1LkU9LpOddZngCzwspzq9c/O1VoSEfvSTT8YZXVPQgIUd6Ch
# qaXwtpA3TY80n4rE3lWQMvgYDzIwMjYwMTE2MTMwOTE5WjADAgEBoFikVjBUMQsw
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
# AQkEMSIEIIZ2us4LoudtzvcmuEElnc+VNKsSK1CWqDOOwHzjA11XMIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1or
# d69gXP0wczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAM9fU
# DnRnbgDucx1/jpVmxS2AuKlaSU/G7KSMroXpZS+tYzJH0b/LzZM9vFa0OeQPqfYo
# zcD2/1Q8NMD7I8iArJoCdpt5mKO8hOLhhfq842ogURRAb0Bs2SVfT2Z6X8cfsQFH
# g4liS2DbQDb8I9VBZpj9dSNcI8KWqkMZl0CB4YwbEsj6rfZupS5voVbKF220if5I
# Gw+LBUCLuajA6nMr2U7C90q+TXaLtaLx6eTmM9TFgbHFobwIL6zLH9gDyTKKf2M8
# rmIkAS8Yg4EpCRwjFHhT8WmjOiNRKwp5dh5J0x336fikQEHcoc6rB4+X0sSfB7Qa
# e89URqmM00FXbbcOce9I1zVHrqz39SN2zZUmcYI3RHm7X5qmmT04/DsRij3QmmlZ
# OX0xhkrbedfpn4ZYVTewb+z10ZzjejIlLe8VocZbLtdaFrWFy0MBSuedn9uIrSg8
# 2rq2iSv7wvYW3PdDPUtuM5dhnKgcSL+Qe7QwY+x2VgSmB19pj8Uqfy5yZ+9M
# SIG # End signature block
