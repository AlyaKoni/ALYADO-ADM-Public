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
Install-ModuleIfNotInstalled "Az.DesktopVirtualization"

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
# MIIvGwYJKoZIhvcNAQcCoIIvDDCCLwgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC/tpiv1ajyX9UJ
# ZDBxaj3Z2zsy/z7W1fr4oUJpSyfK1aCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGzUh8Vd
# j9hQVYmSoutQUj1bYelzCXACF0fI1RwDYCDhMA0GCSqGSIb3DQEBAQUABIICAASC
# wPH/h3+8Tz9tl3G8EoXoVHK8rOCROsYVa2G2kJY/LKups6nyMZzkm07yOkxH98tS
# k7WPUDGK4bcMIe64OxFPGlyLe3MuPTCbLM41jF7Y9opXzVvxYR3tlIl4q3IJ/eax
# jEE4O8BAGUQNFhVIGVidaDc7WvyzqHK4vZJKLc51+LA6VkhnTrufqzzPHDLX2cRf
# uNm7fr4qdkXjc7O2cXzIZBKzFjnTQuzzcP6MufCm/z8m/sabHMnLcGIBcHlZw2yy
# AWXs0ytDl6y60rTvDc668v90z/bfr8ZPqPPpNAjI2gSrvogO54QU9l8qFOjtUZcD
# 0daEVn3uup+o0kjc5nYRU3BFvwUYbnaOUNGsrejraKHpKlUw7wFPbmOgenfw3iBI
# GhUN/+94MYUQrcWaP6Z67p4laR/rA+PE6JB3Dk/7KtjmUCmwSKytQ9y8xAPlvfJT
# eDs2SHrqT4s5anTK5ozJcqR0oLEmZRln4bFU8WS+ZIxdEBE53LLtJ3woLF4qsmKV
# bXIOuUcGGjS+pZ/54fb7ang5JBakNj7YGyGMmxRrJ2ZQQks5QXlEgI2ViM6Go+yH
# Dj6hBVjgsvCpuerYjq4TOi8IbDC+I3NwqMPwGx7mQHTNSH/UQgzkEiSvOyqPn9GP
# QCk8UAaKQI6yyiU1bhOuByvzi6wXRxgpezEOXcDhoYIWzTCCFskGCisGAQQBgjcD
# AwExgha5MIIWtQYJKoZIhvcNAQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEw
# gegGCyqGSIb3DQEJEAEEoIHYBIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCC+v/p6CMgKlukXXvUuE1ikZnhIyPLEMsGXX33LgDie5QIUdEuC
# XoY4Ry1Ka6RBQwCta8v1QbYYDzIwMjUwMjA2MTkxMTUxWjADAgEBoGGkXzBdMQsw
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
# hvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEIEkvZY18R/v9lVsFfv4rbNGEhf3c9K6T
# Z+1BV0uyCeHaMIGwBgsqhkiG9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe
# 4U9su3aCN6VF0BBb8EURveJfgqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJ
# KoZIhvcNAQELBQAEggGAH5mmtaioeC2MCJ1pMJWVtb0axzMwALvYM7aWfbDN/KsF
# 8iimuws+ZnTkLqnJkw4DNxkXQyBH+5wzZW+t0G/7VRWT+i3VSe8bGVQ1BX7FZ1Ju
# F7xKbtkbX4t+JdaanJ86pUR5p/CX7e6Wi48m+uptCJugkRVKXh/HY8wsO6tSfTfA
# kSToYHQi/8yJLu75xIfLyLt0tK1uEcnBK0DeY3Vgx/vI+FUsiCSnU64I1hNVm7kW
# OwXjiGwSb3p1y7kAhkxJNCjWgqVMNyZpcqU0OQEkGW6eSVd+WpmGedxqhRHokZk0
# KPAhFTMtHFvWSqzRh/PYaeYtrBoDtXGUmRUD18y03GbaE/Au3bp8sn/w8XZ5dpDJ
# IpySF95oF/QLASDH2N94JWGDIuMCsbiPoRwgkvScwMeHXYrtgWN8VH4ZXAVGzWPO
# hhkNU1T0wImV5geYlcYgRW5XVDT2IHaPWjESapdQLU9CfqnCCo2w109K+nOsJ1/N
# 6rDk4rzPDTI4l/g39Dkf
# SIG # End signature block
