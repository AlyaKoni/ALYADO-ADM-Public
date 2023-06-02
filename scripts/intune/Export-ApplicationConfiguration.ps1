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
    30.09.2020 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Export-ApplicationConfiguration-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$IsOneDriveDir = $true
$DataRoot = Join-Path (Join-Path $AlyaData "intune") "Configuration"
if (-Not (Test-Path $DataRoot))
{
    $null = New-Item -Path $DataRoot -ItemType Directory -Force
}
Write-Host "Exporting Intune data to $DataRoot"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "Directory.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementRBAC.Read.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Export-ApplicationConfiguration | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

function MakeFsCompatiblePath()
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [string]$path
    )
    $npath = $path
    $hadDisk = $false
    if ($npath.Substring(1,1) -eq ":") { $hadDisk = $true }
    $npath = $npath.Replace("<", "_"). `
       Replace(">", "_"). `
       Replace(":", "_"). `
       Replace("`"", "_"). `
       Replace("/", "_"). `
       Replace("|", "_"). `
       Replace("?", "_"). `
       Replace("*", "_")
    if ($hadDisk) { $npath = $npath.Remove(1,1).Insert(1,":") }

    $parent = Split-Path -Path $npath -Parent
    $leaf = Split-Path -Path $npath -Leaf

    $maxDirLen = 248
    $maxFileLen = 260
    if ($IsOneDriveDir)
    { 
        $maxDirLen = 236
        $maxFileLen = 248
    }

    if ($parent.Length -gt $maxDirLen)
    {
        throw "Directory too long. Max $maxDirLen charcters allowed if OneDrive=$IsOneDriveDir"
    }
    if ($npath.Length -gt $maxFileLen)
    {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
        $ext = [System.IO.Path]::GetExtension($leaf)
        $maxLength = $maxFileLen - $parent.Length - $ext.Length - 1
        $npath = Join-Path $parent ($name.Substring(0,$maxLength)+$ext)
    }

    if ($npath.Length -ne $path.Length)
    {
        Write-Warning "Path shortened from to: (OneDrive=$IsOneDriveDir)"
        Write-Warning $path
        Write-Warning $npath
    }

    return $npath
}

##### Starting exports Applications
#####
Write-Host "Exporting Applications" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\Applications")) { $null = New-Item -Path "$DataRoot\Applications" -ItemType Directory -Force }

#mobileAppCategories
$uri = "/beta/deviceAppManagement/mobileAppCategories"
$mobileAppCategories = Get-MsGraphObject -Uri $uri
$mobileAppCategories | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\mobileAppCategories.json")) -Force

#intuneApplications
$uri = "/beta/deviceAppManagement/mobileApps?`$expand=categories"
$intuneApplications = Get-MsGraphCollection -Uri $uri
$intuneApplications | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplications.json")) -Force
if (-Not (Test-Path "$DataRoot\Applications\Data")) { $null = New-Item -Path "$DataRoot\Applications\Data" -ItemType Directory -Force }
foreach($application in $intuneApplications)
{
    $uri = "/beta/deviceAppManagement/mobileApps/$($application.id)?`$expand=categories"
    $application = Get-MsGraphObject -Uri $uri
    $application | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_application.json")) -Force
    $uri = "/beta/deviceAppManagement/mobileApps/$($application.id)/assignments"
    $applicationAssignments = Get-MsGraphObject -Uri $uri
    $applicationAssignments | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_applicationAssignments.json")) -Force
    $uri = "/beta/deviceAppManagement/mobileApps/$($application.id)/installSummary"
    $installSummary = Get-MsGraphObject -Uri $uri
    $installSummary | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_installSummary.json")) -Force
    $uri = "/beta/deviceAppManagement/mobileApps/$($application.id)/deviceStatuses"
    $deviceStatuses = Get-MsGraphObject -Uri $uri
    $deviceStatuses | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_deviceStatuses.json")) -Force
    $uri = "/beta/deviceAppManagement/mobileApps/$($application.id)/userStatuses"
    $userStatuses = Get-MsGraphObject -Uri $uri
    $userStatuses | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_userStatuses.json")) -Force
}
$mdmApps = $intuneApplications | Where-Object { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }
foreach($mdmApp in $mdmApps)
{
    $uri = "/beta/deviceAppManagement/mobileApps/$($mdmApp.id)?`$select=largeIcon"
    $appIcon = Get-MsGraphObject -Uri $uri
    $mdmApp.largeIcon = $appIcon.largeIcon
}

$intuneApplications | Where-Object { ($_.'@odata.type').Contains("managed") } | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsMAM.json")) -Force
$mdmApps | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsMDMfull.json")) -Force
$intuneApplications | Where-Object { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) -and (!($_.'@odata.type').Contains("#microsoft.graph.windowsAppX")) -and (!($_.'@odata.type').Contains("#microsoft.graph.androidForWorkApp")) -and (!($_.'@odata.type').Contains("#microsoft.graph.windowsMobileMSI")) -and (!($_.'@odata.type').Contains("#microsoft.graph.androidLobApp")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosLobApp")) -and (!($_.'@odata.type').Contains("#microsoft.graph.microsoftStoreForBusinessApp")) } | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsMDM.json")) -Force
$intuneApplications | Where-Object { ($_.'@odata.type').Contains("win32") } | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsWIN32.json")) -Force
$intuneApplications | Where-Object { ($_.'@odata.type').Contains("managedAndroidStoreApp") } | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsAndroid.json")) -Force
$intuneApplications | Where-Object { ($_.'@odata.type').Contains("managedIOSStoreApp") } | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsIos.json")) -Force

#mobileAppConfigurations
$uri = "/beta/deviceAppManagement/mobileAppConfigurations?`$expand=assignments"
$mobileAppConfigurations = Get-MsGraphObject -Uri $uri
$mobileAppConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\mobileAppConfigurations.json")) -Force

#targetedManagedAppConfigurations
$uri = "/beta/deviceAppManagement/targetedManagedAppConfigurations"
$targetedManagedAppConfigurations = Get-MsGraphCollection -Uri $uri
$targetedManagedAppConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\targetedManagedAppConfigurations.json")) -Force
foreach($configuration in $targetedManagedAppConfigurations)
{
    $uri = "/beta/deviceAppManagement/targetedManagedAppConfigurations('$($configuration.id)')?`$expand=apps,assignments"
    $configuration = Get-MsGraphObject -Uri $uri
    $configuration | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\targetedManagedAppConfiguration_$($configuration.id).json")) -Force
}

#appregistrationSummary
$uri = "/beta/deviceAppManagement/managedAppStatuses('appregistrationsummary')?fetch=6000&policyMode=0&columns=DisplayName,UserEmail,ApplicationName,ApplicationInstanceId,ApplicationVersion,DeviceName,DeviceType,DeviceManufacturer,DeviceModel,AndroidPatchVersion,AzureADDeviceId,MDMDeviceID,Platform,PlatformVersion,ManagementLevel,PolicyName,LastCheckInDate"
$appregistrationSummary = Get-MsGraphObject -Uri $uri
$appregistrationSummary | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\appregistrationSummary.json")) -Force

#windowsProtectionReport
$uri = "/beta/deviceAppManagement/managedAppStatuses('windowsprotectionreport')"
$windowsProtectionReport = Get-MsGraphObject -Uri $uri
$windowsProtectionReport | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\windowsProtectionReport.json")) -Force

#mdmWindowsInformationProtectionPolicies
$uri = "/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies"
$mdmWindowsInformationProtectionPolicies = Get-MsGraphObject -Uri $uri
$mdmWindowsInformationProtectionPolicies | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\mdmWindowsInformationProtectionPolicies.json")) -Force

#managedAppPolicies
$uri = "/beta/deviceAppManagement/managedAppPolicies"
$managedAppPolicies = Get-MsGraphCollection -Uri $uri
$managedAppPolicies | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicies.json")) -Force
foreach($policy in $managedAppPolicies)
{
    $uri = "/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')?`$expand=apps"
    $policy = Get-MsGraphObject -Uri $uri
    $policy | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_android.json")) -Force
    $uri = "/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')?`$expand=apps"
    $policy = Get-MsGraphObject -Uri $uri
    $policy | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_ios.json")) -Force
    $uri = "/beta/deviceAppManagement/windowsInformationProtectionPolicies('$($policy.id)')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
    $policy = Get-MsGraphObject -Uri $uri
    $policy | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_windows.json")) -Force
    $uri = "/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies('$($policy.id)')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
    $policy = Get-MsGraphObject -Uri $uri
    $policy | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_mdm.json")) -Force
}

#Stopping Transscript
Stop-Transcript
