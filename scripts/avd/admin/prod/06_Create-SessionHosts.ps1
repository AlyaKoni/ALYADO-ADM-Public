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
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAfz1E+laSBOe5a
# 0NCHxe4IuKbgIhlyJHGi26gW9YH++6CCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAS/mIxxuaoYGbT5
# CzZvevG4iptidmKS9zZaeOSdaKEVMA0GCSqGSIb3DQEBAQUABIICAGFxrUiW6wQZ
# xUeLsHHtGuBwPdpeh/5ODDwEtyajrO06M72t2gphpsTtBUHZ6usf78WUGSxZBbu/
# bxfUMASAw9pUWSxSjcil6c1yb8tuiY8/apb/AD140HTWXr1jRXgFF5C3G8etUEgq
# OncvZAaKljK3i6TZSBXLrpyk2hNcMjKaiYEG7pVLiwEUMMxUeHd22fFEbPQiIz8T
# ZX+xlRRIw25wnYoPbOXY2F9c+Hv3jjXDm8Ar/lO2Y3va4V94sPQ6TpWCXxGvPf3d
# HTLPOfy+tt9JBrLSipoMgVoKRg/aJeYOARtclpr6USpE2mjkJL+Fe2H1D8BlxF7Y
# a3skY/9O/iKFYJ+CmZquJ7pbah3wnSWTVYkS5T+oBn9gFcEWbUz8Cm/4EasyKiYx
# RmcBV4NEWshvUsZrz8DpHVDkf2+nruvTyQh+nVUoHC/9fyQL1i5hSQP8yA+B4vZ1
# WLS9dXIRRvmihCxK7hXuwhWbbBZd69Ldy6VbvJZe9YEH0jH9sLqKXq2bse7bVxAt
# Pjx4j26pJXQRm0OnBcHXRYyY6rMpu/+cwVaWwl/Zv0K1T89/P7p1kFfZ86novPbM
# F6YWHCDtVu2V2hC08FEcjTOXPbRVA4ZcEhLwDFSAGr8CprKGy/GSXiiBvxNcj6G5
# roa9sdiyZgMX5bSkJkaCjZWYdDvcSdIuoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCDh73o3PnVCSEyqbX7GhWRX+CLFmO4ZiXkpav5sTnG4wgIUJV7D18lWrz//
# XMoWNhUPJSMHGxQYDzIwMjUwODI1MTUyNzUwWjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# INORNPn/+cdgpRflMFcGZmF+Lb7rUir115fVGF8BbpXBMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGARFohyfc+nhG/
# XPG9XtQKgxTUoi6VxOPFfu9v1JTu0Kubn41v7JEU1PE5WaH/lX+P91NBjTw4EoUG
# ynYlxsStoTu3pAoJPICnCdfxLjwQKUArSDuSWQfpq4VRDyIWuGlYHkiXrcPN/8X3
# 54aute4fILsmlfHhNerhrKbvb5q/HuFWmeV6WiWy4NYllAERnHldO9LFgei52b+f
# RsdbjXCUCQPrHL75qa5kTF2pY8ReNF8BRlBNNNZfSuMtRFSYZY/1jaH1GuK6cUg3
# acb7ja/ejmzBAEmKSH7okw12i1S8ZVoFBx10k4rEZxatdejLHFNyg+FN2XYxGoIG
# 3qyGEUvqkzBnveEv/AYN0PhTmkVDtwpnAa4w54fdMgZN2VN/OXVoTHtvgx60D+Ft
# JoCZAVAKh+AXH45T7Nqvm5/+2ZXzlCGA+Uv6Lww8Xfwu9Tfiwo0jGVBYt013OAAj
# vIzy4Ggpe5VHVvZ38ZXZa6HfNRwSlnfFXsRTYreO3J1FXENYdHZI
# SIG # End signature block
