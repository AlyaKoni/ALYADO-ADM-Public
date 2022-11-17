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
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\test\Create-SessionHosts-$($AlyaTimeString).log" | Out-Null

# Constants
$ShResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdAvdSessionHostsResGrp)"
$ResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdAvdManagementResGrp)"
$WorkspaceName = "$($AlyaNamingPrefixTest)avdw$($AlyaResIdAvdWorkspace)"
$HostPoolName = "$($AlyaNamingPrefixTest)avdh$($AlyaResIdAvdHostpool)"
$AvailabilitySetName = "$($AlyaNamingPrefixTest)avls$($AlyaResIdAvdSessionHostsResGrp)"
$SessionHostPrefix = "$($AlyaNamingPrefixTest)avd$($AlyaResIdAvdSessionHostsResGrp.Substring(1, 2))"
$SessionHostCount = $AlyaAvdSessionHostCountTest
$NetworkResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdMainNetwork)"
$VirtualNetworkName = "$($AlyaNamingPrefixTest)vnet$($AlyaAvdResIdVirtualNetworkTest)"
$VMSubnetName = "$($AlyaNamingPrefixTest)vnet$($AlyaAvdResIdVirtualNetworkTest)snet$($AlyaResIdAvdHostSNetTest)"
$DiagnosticResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdAuditing)"
$DiagnosticStorageName = "$($AlyaNamingPrefixTest)strg$($AlyaResIdDiagnosticStorage)"
$KeyVaultResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefixTest)keyv$($AlyaResIdMainKeyVault)"
$LogAnaResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdAuditing)"
$LogAnaWrkspcName = "$($AlyaNamingPrefixTest)loga$($AlyaResIdLogAnalytics)"
$LogAnaStorageAccountName = "$($AlyaNamingPrefixTest)strg$($AlyaResIdAuditStorage)"
$ProdSubscription = $AlyaSubscriptionName
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

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionNameTest

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
$Subnet = $VNet.Subnets | where { $_.Name -eq $VMSubnetName }
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
    $StrgAccountDiag = New-AzStorageAccount -Name $DiagnosticStorageName -ResourceGroupName $DiagnosticResourceGroupName -Location $AlyaAvdSessionHostLocation -SkuName "Standard_LRS" -Kind StorageV2 -AccessTier Cool -Tag @{displayName="AVD Diagnostic Log Storage"}
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
    $sub = Get-AzSubscription -SubscriptionName $ProdSubscription
    $null = Set-AzContext -Subscription $sub.Id
    $Context = Get-AzContext
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
    $sub = Get-AzSubscription -SubscriptionName $AlyaSubscriptionNameTest
    $null = Set-AzContext -Subscription $sub.Id
    $Context = Get-AzContext	
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
        $VMPassword = ($AzureKeyVaultSecret.SecretValue | foreach { [System.Net.NetworkCredential]::new("", $_).Password })
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
        #Get-AzVMSize -Location $AlyaAvdSessionHostLocation | where { $_.Name -like "Standard_D8s*" }
        #Get-AzVMImagePublisher -Location $AlyaAvdSessionHostLocation
        #Get-AzVMImageOffer -Location $AlyaAvdSessionHostLocation -PublisherName "MicrosoftWindowsDesktop"
        $VMCredential = New-Object System.Management.Automation.PSCredential ($vmAdminName, $VMPasswordSec)
        #TODO -LicenseType $AlyaVmLicenseType if server and hybrid benefit
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VmSize -AvailabilitySetId $AvSet.Id -LicenseType $AlyaVMLicenseTypeClient -IdentityType SystemAssigned
        $VMConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VMName -Credential $VMCredential -TimeZone $AlyaTimeZone | Out-Null
        $VMConfig | Set-AzVMSourceImage -Id $image.Id
        $VMConfig | Add-AzVMNetworkInterface -Id $VMNic.Id | Out-Null
        $VMConfig | Set-AzVMOSDisk -Name $VMDiskName -CreateOption FromImage -Caching ReadWrite -DiskSizeInGB 128 | Out-Null
        $VMConfig | Set-AzVMBootDiagnostic -Enable -ResourceGroupName $DiagnosticResourceGroupName -StorageAccountName $DiagnosticStorageName | Out-Null
        $tmp = New-AzVM -ResourceGroupName $ShResourceGroupName -Location $AlyaAvdSessionHostLocation -VM $VMConfig -DisableBginfoExtension
        $SessionHostVm = Get-AzVM -ResourceGroupName $ShResourceGroupName -Name $VMName
        $tmp = Set-AzResource -ResourceId $SessionHostVm.Id -Tag @{displayName="AVD $($WrkSpc.FriendlyName) host $h";ownerEmail=$Context.Account.Id;startTime=$VmStartTime;stopTime=$VmStopTime} -Force
        $SessionHostVm = Get-AzVM -ResourceGroupName $ShResourceGroupName -Name $VMName -Status
    }

    # Starting image vm if not running
    Write-Host "Starting session host if not running"
    if (-Not ($SessionHostVm.Statuses | where { $_.Code -eq "PowerState/running"}))
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
        #Get-AzVmImagePublisher -Location $AlyaAvdSessionHostLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select Type, Version
        #Get-Command Set-Az*Extension* -Module Az.Compute
        #$Extension = Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Diagnostics.IaaSDiagnostics" -Type "IaaSAntimalware" | select -last 1
        $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Diagnostics" -Type "IaaSDiagnostics" | %{ new-object System.Version ($_.Version) } | Sort | Select -Last 1).ToString()
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
        #Get-AzVmImagePublisher -Location $AlyaAvdSessionHostLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select Type, Version
        #Get-Command Set-Az*Extension* -Module Az.Compute
        #$Extension = Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | select -last 1
        $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Monitor" -Type "AzureMonitorWindowsAgent" | %{ new-object System.Version ($_.Version) } | Sort | Select -Last 1).ToString()
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
        #Get-AzVmImagePublisher -Location $AlyaAvdSessionHostLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select Type, Version
        #Get-Command Set-Az*Extension* -Module Az.Compute
        #$Extension = Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | select -last 1
        $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Monitoring.DependencyAgent" -Type "DependencyAgentWindows" | %{ new-object System.Version ($_.Version) } | Sort | Select -Last 1).ToString()
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
        #Get-AzVmImagePublisher -Location $AlyaAvdSessionHostLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select Type, Version
        #Get-Command Set-Az*Extension* -Module Az.Compute     
        #$Extension = Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | select -last 1
        $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | %{ new-object System.Version ($_.Version) } | Sort | Select -Last 1).ToString()
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
            $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Azure.ActiveDirectory" -Type "AADLoginForWindows" | %{ new-object System.Version ($_.Version) } | Sort | Select -Last 1).ToString()
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
            $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Compute" -Type "JsonADDomainExtension" | %{ new-object System.Version ($_.Version) } | Sort | Select -Last 1).ToString()
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
$cert = Get-ChildItem "Cert:\LocalMachine\My" -Recurse | where { $_.DnsNameList -eq $env:COMPUTERNAME }
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
    Add-LocalGroupMember -Group "Administrators" -Member $LocalAdmin -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "Administrators" -Member $LocalAdmin -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "Administratoren" -Member $LocalAdmin -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "Administratoren" -Member $LocalAdmin -ErrorAction SilentlyContinue
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
        #Get-AzVmImagePublisher -Location $AlyaAvdSessionHostLocation | where { $_.PublisherName -like "Microsoft.*" }
        #(Get-AzVMExtensionImageType -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Compute").Type
        #Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Compute" -Type CustomScriptExtension
        $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaAvdSessionHostLocation -PublisherName "Microsoft.Compute" -Type "CustomScriptExtension" | %{ new-object System.Version ($_.Version) } | Sort | Select -Last 1).ToString()
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
