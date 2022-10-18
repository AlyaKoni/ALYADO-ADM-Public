#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2021

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
    30.09.2020 Konrad Brunner       Initial Version

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
    $tmp = New-Item -Path $DataRoot -ItemType Directory -Force
}
Write-Host "Exporting Intune data to $DataRoot"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Export-ApplicationConfiguration | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context and token
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}
$token = Get-AdalAccessToken

# shorten export path
# uncomment following lines to fix long path names
<#
if ((Test-Path "C:\AlyaExport"))
{
    cmd /c rmdir "C:\AlyaExport"
}
cmd /c mklink /d "C:\AlyaExport" "$DataRoot"
if (-Not (Test-Path "C:\AlyaExport"))
{
    throw "Not able to create symbolic link"
}
$DataRoot = "C:\AlyaExport"
#>

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
if (-Not (Test-Path "$DataRoot\Applications")) { $tmp = New-Item -Path "$DataRoot\Applications" -ItemType Directory -Force }

#mobileAppCategories
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppCategories"
$mobileAppCategories = Get-MsGraphObject -AccessToken $token -Uri $uri
$mobileAppCategories | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\mobileAppCategories.json")) -Force

#intuneApplications
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$expand=categories"
$intuneApplications = Get-MsGraphObject -AccessToken $token -Uri $uri
$intuneApplications | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplications.json")) -Force
$applications = $intuneApplications.value
if (-Not (Test-Path "$DataRoot\Applications\Data")) { $tmp = New-Item -Path "$DataRoot\Applications\Data" -ItemType Directory -Force }
foreach($application in $applications)
{
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($application.id)?`$expand=categories"
    $application = Get-MsGraphObject -AccessToken $token -Uri $uri
    $application | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_application.json")) -Force
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($application.id)/assignments"
    $applicationAssignments = Get-MsGraphObject -AccessToken $token -Uri $uri
    $applicationAssignments | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_applicationAssignments.json")) -Force
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($application.id)/installSummary"
    $installSummary = Get-MsGraphObject -AccessToken $token -Uri $uri
    $installSummary | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_installSummary.json")) -Force
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($application.id)/deviceStatuses"
    $deviceStatuses = Get-MsGraphObject -AccessToken $token -Uri $uri
    $deviceStatuses | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_deviceStatuses.json")) -Force
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($application.id)/userStatuses"
    $userStatuses = Get-MsGraphObject -AccessToken $token -Uri $uri
    $userStatuses | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_userStatuses.json")) -Force
}
$intuneApplications.value | where { ($_.'@odata.type').Contains("managed") } | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsMAM.json")) -Force
$intuneApplications.value | where { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) } | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsMDMfull.json")) -Force
$intuneApplications.value | where { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) -and (!($_.'@odata.type').Contains("#microsoft.graph.windowsAppX")) -and (!($_.'@odata.type').Contains("#microsoft.graph.androidForWorkApp")) -and (!($_.'@odata.type').Contains("#microsoft.graph.windowsMobileMSI")) -and (!($_.'@odata.type').Contains("#microsoft.graph.androidLobApp")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosLobApp")) -and (!($_.'@odata.type').Contains("#microsoft.graph.microsoftStoreForBusinessApp")) } | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsMDM.json")) -Force
$intuneApplications.value | where { ($_.'@odata.type').Contains("win32") } | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsWIN32.json")) -Force
$intuneApplications.value | where { ($_.'@odata.type').Contains("managedAndroidStoreApp") } | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsAndroid.json")) -Force
$intuneApplications.value | where { ($_.'@odata.type').Contains("managedIOSStoreApp") } | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsIos.json")) -Force

#mobileAppConfigurations
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations?`$expand=assignments"
$mobileAppConfigurations = Get-MsGraphObject -AccessToken $token -Uri $uri
$mobileAppConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\mobileAppConfigurations.json")) -Force

#targetedManagedAppConfigurations
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations"
$targetedManagedAppConfigurations = Get-MsGraphObject -AccessToken $token -Uri $uri
$targetedManagedAppConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\targetedManagedAppConfigurations.json")) -Force
$configurations = $targetedManagedAppConfigurations.value
foreach($configuration in $configurations)
{
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations('$($configuration.id)')?`$expand=apps,assignments"
    $configuration = Get-MsGraphObject -AccessToken $token -Uri $uri
    $configuration | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\targetedManagedAppConfiguration_$($configuration.id).json")) -Force
}

#appregistrationSummary
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppStatuses('appregistrationsummary')?fetch=6000&policyMode=0&columns=DisplayName,UserEmail,ApplicationName,ApplicationInstanceId,ApplicationVersion,DeviceName,DeviceType,DeviceManufacturer,DeviceModel,AndroidPatchVersion,AzureADDeviceId,MDMDeviceID,Platform,PlatformVersion,ManagementLevel,PolicyName,LastCheckInDate"
$appregistrationSummary = Get-MsGraphObject -AccessToken $token -Uri $uri
$appregistrationSummary | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\appregistrationSummary.json")) -Force

#windowsProtectionReport
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppStatuses('windowsprotectionreport')"
$windowsProtectionReport = Get-MsGraphObject -AccessToken $token -Uri $uri
$windowsProtectionReport | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\windowsProtectionReport.json")) -Force

#mdmWindowsInformationProtectionPolicies
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies"
$mdmWindowsInformationProtectionPolicies = Get-MsGraphObject -AccessToken $token -Uri $uri
$mdmWindowsInformationProtectionPolicies | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\mdmWindowsInformationProtectionPolicies.json")) -Force

#managedAppPolicies
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies"
$managedAppPolicies = Get-MsGraphObject -AccessToken $token -Uri $uri
$managedAppPolicies | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicies.json")) -Force
$policies = $managedAppPolicies.value
foreach($policy in $policies)
{
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')?`$expand=apps"
    $policy = Get-MsGraphObject -AccessToken $token -Uri $uri
    $policy | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_android.json")) -Force
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')?`$expand=apps"
    $policy = Get-MsGraphObject -AccessToken $token -Uri $uri
    $policy | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_ios.json")) -Force
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies('$($policy.id)')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
    $policy = Get-MsGraphObject -AccessToken $token -Uri $uri
    $policy | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_windows.json")) -Force
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies('$($policy.id)')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
    $policy = Get-MsGraphObject -AccessToken $token -Uri $uri
    $policy | ConvertTo-Json -Depth 50 | Set-Content -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_mdm.json")) -Force
}

#Stopping Transscript
Stop-Transcript
