#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    11.03.2020 Konrad Brunner       Initial Version
    10.10.2020 Konrad Brunner       Added parameters and generalized
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Updates an existing Azure Virtual Desktop (WVD) host pool by restarting session hosts, applying configuration, and redeploying host pool settings.

.DESCRIPTION
The script updates a specified Azure WVD host pool by performing a sequence of actions, including validating the Azure and WVD login contexts, starting virtual machines, applying configuration changes via an ARM template, updating virtual machine diagnostics, and configuring FSLogix profiles and containers. It concludes by tagging Azure resources and setting host pool operational parameters such as load balancing and validation mode.

.PARAMETER HostPoolName
Specifies the name of the host pool to update.

.PARAMETER ResourceGroupName
Defines the name of the resource group that contains the WVD host pool resources.

.PARAMETER NamePrefix
Specifies a prefix used for naming host pool instances.

.PARAMETER NumberOfInstances
Determines the number of session host virtual machines in the host pool.

.PARAMETER VmSize
Defines the size of the virtual machines to be used for session hosts.

.PARAMETER EnableAcceleratedNetworking
Indicates whether accelerated networking should be enabled on the virtual machines.

.INPUTS
None. The script does not take pipeline input.

.OUTPUTS
None. The script produces console output and log files.

.EXAMPLE
PS> .\08_updateHostPool.ps1 -HostPoolName "WVD-ProdPool" -ResourceGroupName "WVD-ResourceGroup" -NamePrefix "WVDHost" -NumberOfInstances 3 -VmSize "Standard_D8s_v3" -EnableAcceleratedNetworking $true

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [string]$HostPoolName,
    [string]$ResourceGroupName,
    [string]$NamePrefix,
    [int]$NumberOfInstances,
    [string]$VmSize,
    [bool]$EnableAcceleratedNetworking
)

Write-Error "Update does not work yet. Please remove and recreate the hostpool" -ErrorAction Continue
exit

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019test\08_updateAppHostPool-$($AlyaTimeString).log" | Out-Null

# Constants
$ImageSourceName = "$($AlyaNamingPrefix)serv$($AlyaResIdWvdImageClient)_ImageClient"
$ImageSourceResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdWvdImageResGrp)"
$AdminDomainUPN = $AlyaWvdDomainAdminUPN
$WvdHostName = "$($NamePrefix)-"
$DiagnosticStorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdDiagnosticStorage)"
$OuPath = $AlyaWvdOuTest
$ExistingVnetName = "$($AlyaNamingPrefixTest)vnet$($AlyaResIdVirtualNetwork)"
$ExistingSubnetName = "$($AlyaNamingPrefixTest)vnet$($AlyaResIdVirtualNetwork)snet$($AlyaResIdWvdHostSNet)"
$virtualNetworkResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdMainNetwork)"
$ShareServer = $AlyaWvdShareServer
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.KeyVault"
Install-ModuleIfNotInstalled "Az.Compute"
Install-ModuleIfNotInstalled "Az.Monitor"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionNameTest

# Domain credentials
Write-Host "Domain credentials" -ForegroundColor $CommandInfo
if (-Not $Global:AdminDomainCred)
{
    Write-Host "  Account requireements: domain admin" -ForegroundColor Red
    $Global:AdminDomainCred = Get-Credential -UserName $AdminDomainUPN -Message "Please specify admins domain password" -ErrorAction Stop
}

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 08_updateAppHostPool | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$AzureAdApplication = Get-AzADApplication -DisplayName $AlyaWvdServicePrincipalNameTest -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    throw "Azure AD Application not found. Please create the Azure AD Application $AlyaWvdServicePrincipalNameTest"
}
$AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdServicePrincipalNameTest

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$AlyaWvdServicePrincipalAssetName = "$($AlyaWvdServicePrincipalNameTest)Key"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AlyaWvdServicePrincipalAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    throw "Key Vault secret not found. Please create the secret $AlyaWvdServicePrincipalAssetName"
}
$AlyaWvdServicePrincipalPasswordSave = $AzureKeyVaultSecret.SecretValue
Clear-Variable -Name AlyaWvdServicePrincipalPassword -Force -ErrorAction SilentlyContinue
Clear-Variable -Name AzureKeyVaultSecret -Force -ErrorAction SilentlyContinue

# Login to WVD
if (-Not $Global:RdsContext)
{
	Write-Host "Logging in to wvd" -ForegroundColor $CommandInfo
	$rdsCreds = New-Object System.Management.Automation.PSCredential($AzureAdServicePrincipal.AppId, $AlyaWvdServicePrincipalPasswordSave)
	$Global:RdsContext = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $rdsCreds -ServicePrincipal -AadTenantId $AlyaTenantId
	#LoginTo-Wvd -AppId $AzureAdServicePrincipal.AppId -SecPwd $AlyaWvdServicePrincipalPasswordSave
}

# Getting members
Write-Host "Getting members" -ForegroundColor $CommandInfo
$RootDir = "$AlyaScripts\wvd\admin\fall2019test"
$subscription = Get-AzSubscription -SubscriptionName $AlyaSubscriptionNameTest

# Preparing parameters
Write-Host "Configuring deployment parameters" -ForegroundColor $CommandInfo
$TemplateFilePath = "$($RootDir)\template\templateUpdate.json"
$ParametersFilePath = "$($RootDir)\template\parametersUpdate.json"
$params = Get-Content -Path $ParametersFilePath -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json
$ParametersObject = @{}
$params.parameters.psobject.properties | Foreach-Object { $ParametersObject[$_.Name] = $_.Value.value }
$ParametersObject["rdshCustomImageSourceName"] = $ImageSourceName
$ParametersObject["rdshCustomImageSourceResourceGroup"] = $ImageSourceResourceGroupName
$ParametersObject["enableAcceleratedNetworking"] = $EnableAcceleratedNetworking
$ParametersObject["domainToJoin"] = $AlyaLocalDomainName
$ParametersObject["ouPath"] = $OuPath
$ParametersObject["existingVnetName"] = $ExistingVnetName
$ParametersObject["existingSubnetName"] = $ExistingSubnetName
$ParametersObject["virtualNetworkResourceGroupName"] = $virtualNetworkResourceGroupName
$ParametersObject["rdBrokerURL"] = $AlyaWvdRDBroker
$ParametersObject["existingTenantGroupName"] = $AlyaWvdTenantGroupName
$ParametersObject["aadTenantId"] = $AlyaTenantId
$ParametersObject["rdshNumberOfInstances"] = $NumberOfInstances
$ParametersObject["rdshVmSize"] = $VmSize
$ParametersObject["existingDomainUPN"] = $AdminDomainUPN
$ParametersObject["existingHostpoolName"] = $HostPoolName
#$ParametersObject["defaultDesktopUsers"] = ($AlyaWvdAdmins -join ",")
$ParametersObject["tenantAdminUpnOrApplicationId"] = $AzureAdServicePrincipal.AppId.Guid.ToString()
$ParametersObject["location"] = $AlyaLocation
$ParametersObject["rdshNamePrefix"] = $NamePrefix
$ParametersObject["existingTenantName"] = $AlyaWvdTenantNameTest
$ParametersObject["existingDomainPassword"] = [SecureString]$Global:AdminDomainCred.Password
$ParametersObject["tenantAdminPassword"] = [SecureString]$AlyaWvdServicePrincipalPasswordSave

# Starting all vms
Write-Host "Starting all vms" -ForegroundColor $CommandInfo
for ($hi=0; $hi -lt $NumberOfInstances; $hi++)
{
    #$hi=0
    $actHostName = "$($WvdHostName)$($hi)"
    Start-AzVM -ResourceGroupName $ResourceGroupName -Name $actHostName
}

# Deploying hostpool
Write-Host "Deploying hostpool" -ForegroundColor $CommandInfo
& "$($RootDir)\template\deploy.ps1" `
    -Subscription $Subscription `
    -ResourceGroupName $ResourceGroupName `
    -ResourceGroupLocation $AlyaLocation `
    -TemplateFilePath $TemplateFilePath `
    -ParametersObject $ParametersObject `
    -ErrorAction Stop
#Deployment error? Get-AzLog -CorrelationId 4711348d-5b11-408e-929b-cbf541b4302e -DetailedOutput

# Checking share for hostpool
Write-Host "Checking share for hostpool" -ForegroundColor $CommandInfo
$hostpoolShareDir = "$($AlyaWvdShareRoot)\$($HostPoolName)"
$hostpoolShareName = "$($HostPoolName)$"
$hostpoolSharePath = "\\$($ShareServer)\$hostpoolShareName"
if (-Not (Test-Path $hostpoolSharePath))
{
    throw "Share does not exist. Should be created with the create script!"
}

Write-Host "Configuring hostpool" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionNameTest
for ($hi=0; $hi -lt $NumberOfInstances; $hi++)
{
    #$hi=0
    $actHostName = "$($WvdHostName)$($hi)"
    Write-Host "  $($actHostName)" -ForegroundColor $CommandInfo
    Write-Host "    Copying files"
    if (-Not (Test-Path "\\$($actHostName)\C$\$($AlyaCompanyName)"))
    {
        $null = New-Item -Path "\\$($actHostName)\C$" -Name $AlyaCompanyName -ItemType Directory
    }
	if ((Test-Path "$($AlyaData)\wvd\WvdAtp\WindowsDefenderATPLocalOnboardingScript.cmd"))
	{
		$null = Copy-Item "$($AlyaData)\wvd\WvdAtp\WindowsDefenderATPLocalOnboardingScript.cmd" "\\$($actHostName)\C$\$($AlyaCompanyName)\WindowsDefenderATPLocalOnboardingScript.cmd" -Force
	}
	else
	{
		Write-Warning "No ATP onboarding script found in $($AlyaData)\wvd\WvdAtp"
	}
    robocopy /mir "$($RootDir)\..\..\WvdIcons" "\\$($actHostName)\C$\$($AlyaCompanyName)\WvdIcons"
    robocopy /mir "$($RootDir)\..\..\WvdStartApps\$($AlyaCompanyName)" "\\$($actHostName)\C$\ProgramData\Microsoft\Windows\Start Menu\Programs\$($AlyaCompanyName)"
    $null = Copy-Item "$($RootDir)\..\..\WvdTheme\$($AlyaCompanyName)Test.theme" "\\$($actHostName)\C$\Windows\resources\Themes\$($AlyaCompanyName).theme" -Force

    Write-Host "    Adding diagnostics"
    $diagConfig = Get-Content -Path "$($RootDir)\diagnosticConfig.xml" -Encoding $AlyaUtf8Encoding -Raw
    $vmResourceId = "/subscriptions/$($subscription)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.Compute/virtualMachines/$($actHostName)"
    $diagConfig = $diagConfig.Replace("##VMRESOURCEID##", $vmResourceId).Replace("##DIAGSTORAGEACCOUNTNAME##", $DiagnosticStorageAccountName)
    $tmpFile = New-TemporaryFile
    $diagConfig | Set-Content -Path $tmpFile.FullName -Encoding UTF8 -Force
    Set-AzVMDiagnosticsExtension -ResourceGroupName $ResourceGroupName -VMName $actHostName -DiagnosticsConfigurationPath $tmpFile.FullName
    Remove-Item -Path $tmpFile.FullName -Force

    Write-Host "    Remote session"
    $session = New-PSSession -ComputerName $actHostName
    Invoke-Command -Session $session {
        $HostPoolName = $args[0]
        $AdminDomainUPN = $args[1]
        $AlyaTenantId = $args[2]
        $AlyaTimeZone = $args[3]
        $AlyaGeoId = $args[4]
        $ShareServer = $args[5]
        $AlyaCompanyName = $args[6]
        Set-Timezone -Id $AlyaTimeZone
        Set-WinHomeLocation -GeoId $AlyaGeoId
        $fslogixAppsRegPath = "HKLM:\SOFTWARE\FSLogix\Apps"
        $fslogixProfileRegPath = "HKLM:\SOFTWARE\FSLogix\Profiles"
        $fslogixContainerRegPath = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
        if (!(Test-Path $fslogixAppsRegPath))
        {
            New-Item -Path $fslogixAppsRegPath -Force
        }
        #New-ItemProperty -Path $fslogixAppsRegPath -Name "RoamSearch" -Value "2" -PropertyType DWORD -Force
        if (!(Test-Path $fslogixProfileRegPath))
        {
            New-Item -Path $fslogixProfileRegPath -Force
        }
        New-ItemProperty -Path $fslogixProfileRegPath -Name "Enabled" -Value "1" -PropertyType DWORD -Force
        New-ItemProperty -Path $fslogixProfileRegPath -Name "VHDLocations" -Value "\\$($ShareServer)\$($HostPoolName)$\Profiles" -PropertyType MultiString -Force
        #New-ItemProperty -Path $fslogixProfileRegPath -Name "DeleteLocalProfileWhenVHDShouldApply" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixProfileRegPath -Name "PreventLoginWithFailure" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixProfileRegPath -Name "PreventLoginWithTempProfile" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixProfileRegPath -Name "SizeInMBs" -Value "51200" -PropertyType DWORD -Force
        if (!(Test-Path $fslogixContainerRegPath))
        {
            New-Item -Path $fslogixContainerRegPath -Force
        }
        New-ItemProperty -Path $fslogixContainerRegPath -Name "Enabled" -Value "1" -PropertyType DWORD -Force
        New-ItemProperty -Path $fslogixContainerRegPath -Name "VHDLocations" -Value "\\$($ShareServer)\$($HostPoolName)$\Containers" -PropertyType MultiString -Force
        #New-ItemProperty -Path $fslogixContainerRegPath -Name "DeleteLocalProfileWhenVHDShouldApply" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixContainerRegPath -Name "PreventLoginWithFailure" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixContainerRegPath -Name "PreventLoginWithTempProfile" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixContainerRegPath -Name "IncludeOneDrive" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixContainerRegPath -Name "IncludeOneNote" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixContainerRegPath -Name "IncludeOneNote_UWP" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixContainerRegPath -Name "IncludeOutlook" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixContainerRegPath -Name "IncludeOutlookPersonalization" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixContainerRegPath -Name "IncludeSharepoint" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixContainerRegPath -Name "IncludeSkype" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixContainerRegPath -Name "IncludeTeams" -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $fslogixContainerRegPath -Name "RoamSearch" -Value "2" -PropertyType DWORD -Force
        #$OneDriveHKLMregistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
        #$OneDriveDiskSizeregistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\DiskSpaceCheckThresholdMB'
        #if (!(Test-Path $OneDriveHKLMregistryPath))
        #{
        #    New-Item -Path $OneDriveHKLMregistryPath -Force
        #}
        #if (!(Test-Path $OneDriveDiskSizeregistryPath))
        #{
        #    New-Item -Path $OneDriveDiskSizeregistryPath -Force
        #}
        #New-ItemProperty -Path $OneDriveHKLMregistryPath -Name 'SilentAccountConfig' -Value "1" -PropertyType DWORD -Force
        #New-ItemProperty -Path $OneDriveDiskSizeregistryPath -Name $AlyaTenantId -Value "51200" -PropertyType DWORD -Force
        <# TODO
        $themeRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes"
        $themePersonalizeRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        $themeDWMRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\DWM"
        if (!(Test-Path $themeRegPath))
        {
            New-Item -Path $themeRegPath -Force
        }
        if (!(Test-Path $themePersonalizeRegPath))
        {
            New-Item -Path $themePersonalizeRegPath -Force
        }
        if (!(Test-Path $themeDWMRegPath))
        {
            New-Item -Path $themeDWMRegPath -Force
        }
        New-ItemProperty -Path $themeRegPath -Name "InstallTheme" -Value "C:\Windows\resources\Themes\$($AlyaCompanyName).theme" -PropertyType String -Force
        New-ItemProperty -Path $themePersonalizeRegPath -Name "EnableTransparency" -Value "1" -PropertyType DWORD -Force
        New-ItemProperty -Path $themePersonalizeRegPath -Name "AppsUseLightTheme" -Value "1" -PropertyType DWORD -Force
        New-ItemProperty -Path $themePersonalizeRegPath -Name "ColorPrevalence" -Value "1" -PropertyType DWORD -Force
        New-ItemProperty -Path $themeDWMRegPath -Name "ColorPrevalence" -Value "1" -PropertyType DWORD -Force
		#>
        Get-Service -Name "WSearch" | Set-Service -StartupType Automatic
        Add-LocalGroupMember -Group "FSLogix ODFC Exclude List" -Member $AdminDomainUPN
        Add-LocalGroupMember -Group "FSLogix Profile Exclude List" -Member $AdminDomainUPN
        $drv = Get-WmiObject win32_volume -filter 'DriveLetter = "E:"'
        if ($drv)
        {
            $drv.DriveLetter = "G:"
            $drv.Put()
        }
        if ((Test-Path "C:\$($AlyaCompanyName)\WindowsDefenderATPLocalOnboardingScript.cmd"))
        {
        	& "C:\$($AlyaCompanyName)\WindowsDefenderATPLocalOnboardingScript.cmd"
    	}
    } -Args $HostPoolName, $AdminDomainUPN, $AlyaTenantId, $AlyaTimeZone, $AlyaGeoId, $ShareServer, $AlyaCompanyName
    Remove-PSSession -Session $session
}

Write-Host "Restarting session hosts" -ForegroundColor $CommandInfo
for ($hi=0; $hi -lt $NumberOfInstances; $hi++)
{
    $actHostName = "$($WvdHostName)$($hi)"
    Write-Host "  $($actHostName)"
    Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $actHostName -Force
    Start-AzVM -ResourceGroupName $ResourceGroupName -Name $actHostName
}

Start-Sleep -Seconds 120

Write-Host "Configuring hostpool" -ForegroundColor $CommandInfo
for ($hi=0; $hi -lt $NumberOfInstances; $hi++)
{
    #$hi = 2
    $actHostName = "$($WvdHostName)$($hi)"
    Write-Host "  $($actHostName)" -ForegroundColor $CommandInfo
    Write-Host "    Remote session"
    $session = New-PSSession -ComputerName $actHostName
    Invoke-Command -Session $session {
        #Set-MpPreference -ExclusionPath "\\$($ShareServer)\*\*\*\*.vhd", "C:\Program Files\FSLogix\Apps"
        #Set-MpPreference -ExclusionExtension "vhd"
        #Set-MpPreference -DisableArchiveScanning $false
        #Set-MpPreference -DisableAutoExclusions $false
        #Set-MpPreference -DisableBehaviorMonitoring $false
        #Set-MpPreference -DisableBlockAtFirstSeen $false
        #Set-MpPreference -DisableCatchupFullScan $true
        #Set-MpPreference -DisableCatchupQuickScan $false
        #Set-MpPreference -DisableEmailScanning $false
        #Set-MpPreference -DisableIOAVProtection $false
        #Set-MpPreference -DisablePrivacyMode $false
        #Set-MpPreference -DisableRealtimeMonitoring $false
        #Set-MpPreference -DisableRemovableDriveScanning $true
        #Set-MpPreference -DisableRestorePoint $true
        #Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $true
        #Set-MpPreference -DisableScanningNetworkFiles $false
        #Set-MpPreference -DisableScriptScanning $false
        $nlaEnabled = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired
        if ($nlaEnabled -eq 1)
        {
            (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)
        }
    } -Args $HostPoolName
    Remove-PSSession -Session $session
}

# Login to WVD
Write-Host "Logging in to wvd" -ForegroundColor $CommandInfo
$rdsCreds = New-Object System.Management.Automation.PSCredential($AzureAdServicePrincipal.AppId, $AlyaWvdServicePrincipalPasswordSave)
$Global:RdsContext = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $rdsCreds -ServicePrincipal -AadTenantId $AlyaTenantId

Write-Host "Setting hostpool to validation (test)" -ForegroundColor $CommandInfo
#TODO Comment for prod env
Set-RdsHostPool -TenantName $AlyaWvdTenantNameTest -Name $HostPoolName -ValidationEnv $true

Write-Host "Setting hostpool to depth first" -ForegroundColor $CommandInfo
Set-RdsHostPool -TenantName $AlyaWvdTenantNameTest -Name $HostPoolName -DepthFirstLoadBalancer -MaxSessionLimit 6

Write-Host "Setting tags on resource group" -ForegroundColor $CommandInfo
$resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if($resourceGroup)
{
    $tags = @{}
    $tags += @{displayName="WVD $($HostPoolName)"}
    $tags += @{ownerEmail=$Context.Account.Id}
    Set-AzResource -ResourceId $resourceGroup.ResourceId -Tag $tags -ApiVersion "2022-03-01" -Force
}

Write-Host "Setting tags on vms" -ForegroundColor $CommandInfo
for ($hi=0; $hi -lt $NumberOfInstances; $hi++)
{
    $actHostName = "$($WvdHostName)$($hi)"
    Write-Host "  $($actHostName)"
    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $actHostName
    $tags = @{}
    #TODO enable for prod if ($hi -eq 0) { $tags += @{startTime=$AlyaWvdStartTime} }
    $tags += @{displayName="WVD Host $($HostPoolName)"}
    $tags += @{stopTime=$AlyaWvdStopTime}
    $tags += @{ownerEmail=$Context.Account.Id}
    $null = Set-AzResource -ResourceId $vm.Id -Tag $tags -ApiVersion "2022-03-01" -Force
}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDEyYCUvYfFs1gB
# U3N84QTZ0swAhM7az6APy5eLGpdV3qCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g604YfM/tV
# 5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD4ED6gVYD
# U/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S/gJXhZrh
# 0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp8nKmrVa4
# 6Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqtf2phU7+y
# R2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJQWTEE/bP
# 0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKXvYkPbEdx
# +QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4yMYgcMKb
# 9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmYF8T4xO2k
# 6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2mMIVpqWC
# Z1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7spNY6rQb
# 3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd2jANBgkq
# hkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy/fAHsVv1
# RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW2H3Bh6zN
# XULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0MP6pBPKO
# L6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/pFL9zlcc
# tWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcexU0bcV0hL
# Q4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf6AMOGaM5
# 6A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzECp9LnR+34
# c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9mUF5qE6Yw
# QqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+KuaJRsz+cn
# ZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/JlN6m6GM1j
# EhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutofdgNBzMUx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIP0tgMqJ2VuEkLfs
# AeZ7/xGzH019g742YaVUuoJMBT1lMA0GCSqGSIb3DQEBAQUABIICAFqcH+QXGUgc
# qcZ0hrLPpqQcMs32kymzynyE6Bc7wumHOC1t2OgRuFk7FQnFGM6DIgxQ0bMwEVIO
# kk471d5G3zMB7CViIL9Bc+7RC7lsXNJZbTj+CBn7Ei2a22jeb0oo2nIgjU7Em2MR
# mVA2Q1d4goNFGXhrdMLVMR86C87tkbsFcExTbCgxlv4lxz6eRlDnsfXwY0yfLBcN
# TpGZf7unHgSA+u2PJL02wCYOr2U1LLbiQ2RzgutZjeVc7Yjt0gmMnx7l+h+yokCy
# ozJhMn1A5tFeQL3IyVF5Se5XB3nGgFx0VAYdrkbtIKPA7c2mWXKGLdZcCtT5OHcp
# 1C54C6MgoMBMv8WuFmOwgqwVC0LTEJZW6ZeIKFA6tcUQH02mdZr7hiDWIjw9q2Tt
# eawNra0y6RdeQSjYDkdylAqS518c2eVM9YOx71Wou+slWAAtljA1SOvktOt9yJfi
# kuaoDxpQOumy6zS7O0IFVAcgxTYcdP2s15NV3Ugi+clXRqpEPeGGi+VMPil1nWIf
# Vy9k8A/AxQJlAERFhzlz5Il0ofmkChEZe7CztihYoETNf0DnC6nYsurfZhOJB30V
# 9pkxkCjVa2ERUb0MFo6Nz0MgsS0WM2XuVWKD75gqjCPmvpBae7Bu6Ts9PK+GmV9f
# 1YOZGJfp8RMTgqTRwX4ENBJ2Rr4FC191oYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCAuLfThYFkgHDNrg0xz7f14DB752m4GQ4RTVrVOUFjKJwIUdBDdTNKp1Dho
# FVbdgRYKaIsozaoYDzIwMjYwMjA2MTIyNTUzWjADAgEBoFikVjBUMQswCQYDVQQG
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
# IKTMqvRQFlaalSuK1rTMW0QG3BJhTfwqG0ZNiXzwg6jVMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAa7i91G2tj1gd
# s4DRh6OnywFOcf/kxQiQsTvX8Ayrn+E3YY81Xperg7ytCAFkpniFE9WHCxLFy9pE
# fnKqldaBWb/s6W32cU5iX6y4K/dhQ8qo0iTGlH3IkoEq/uAK7HF89i5/NsBQSTqW
# n/7yoGB2tjIa8yeXF5VSe1X88NPmPEShGwMQC/+VrnqpiurGVxXzm9XgVMt3C0G1
# khQPao4lo7Hvj6psQukl2xTBoQZC3+WFM9jwmYS1wo7L9FOuQEtxP8XgVzmululT
# IKL3hqHjE8yGiDPFCPugt6PDvyxcbdlCW4Rz7ntm7xGLdmi+XQtjEFYlicIw2gRU
# PE3QrYMf0QNHqnRnZOp6WSg/p2WUrMGSMdd2ka82S0e88ZVyW5+vfCOHGxKDi8Y4
# jcKDwCt0zKKpxda3bt+rdLaVA3+I634PZKJzmfTC1LaX8TUtJkS+orRqT1/YzunZ
# RksoLkcV6x9AjxXnO4Beea5eKXKL5d+1cB6nk5uOr70S3F6Oj0Uu
# SIG # End signature block
