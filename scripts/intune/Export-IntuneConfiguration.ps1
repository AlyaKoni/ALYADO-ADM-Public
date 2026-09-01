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
    03.09.2020 Konrad Brunner       Initial Version
    23.11.2021 Konrad Brunner       Group policies
    24.04.2023 Konrad Brunner       Switched to Graph
    10.09.2025 Konrad Brunner       Better error handling
    06.02.2026 Konrad Brunner       Added powershell documentation
    30.08.2026 Konrad Brunner       Added ExportGitFriendly parameter

#>

<#
.SYNOPSIS
Exports Microsoft Intune configuration data and reports using Microsoft Graph API.

.DESCRIPTION
The Export-IntuneConfiguration.ps1 script connects to Microsoft Graph and retrieves comprehensive Intune configuration data including settings, policies, applications, compliance, configurations, and user or device details. It exports the data into JSON files organized by categories, such as ConfigurationPolicy, CompliancePolicy, Devices, Applications, and more. The script includes optional exports for user data and Intune reports. All retrieved data is written to structured directories under the defined data root path for backup, audit, or documentation purposes.

.PARAMETER doUserDataExport
Specifies whether user-specific Intune configuration and status data should be exported. When set to $true, the script exports detailed data for each user.

.PARAMETER doReportExport
Specifies whether Intune reports should be exported. When set to $true, detailed reports are downloaded and stored.

.PARAMETER doAppReportExport
Specifies whether application-specific reports should be exported. When set to $true, additional Intune app reports, such as installation statuses, are generated.

.INPUTS
None. The script does not accept pipeline input.

.OUTPUTS
Creates JSON and log files under the Intune configuration export directory structure for different Intune object types and reports.

.EXAMPLE
PS> .\Export-IntuneConfiguration.ps1 -doUserDataExport $true -doReportExport $false -doAppReportExport $true
Exports Intune configuration and application reports but skips exporting general reports.

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [bool]$doUserDataExport = $false,
    [bool]$doReportExport = $false,
    [bool]$doAppReportExport = $false,
    [bool]$zipAllData = $false,
    [bool]$ExportGitFriendly = $false
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Export-IntuneConfiguration-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$IntuneRoot = Join-Path $AlyaData "intune"
$DataRoot = Join-Path $IntuneRoot "Configuration"
$GitReadyFiles = @()
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
    "Organization.Read.All",
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
Write-Host "Intune | Export-IntuneConfiguration | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

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

function GetReportUri($reportname,$filter)
{
    $uri = "/beta/deviceManagement/reports/exportJobs"
    if ([string]::IsNullOrEmpty($filter)) {
        $body = @"
{
    "reportName": "$reportname",
    "localizationType": "LocalizedValuesAsAdditionalColumn", 
    "format": "json"
}
"@
    } else {
        $body = @"
{
    "reportName": "$reportname",
    "filter": "$filter",
    "localizationType": "LocalizedValuesAsAdditionalColumn", 
    "format": "json"
}
"@
    }
    $rep = Post-MsGraph -Uri $uri -Body $body
    $rep = "$uri('$($rep.id)')"
    $null = Get-MsGraphObject -Uri $rep
    return $rep
}
function DownloadReport($repUri, $repName, $repDir)
{
    $rep = Get-MsGraphObject -Uri $repUri
    while ($rep.status -eq "inProgress" -or $rep.status -eq "notStarted")
    {
        Start-Sleep -Seconds 10
        $rep = Get-MsGraphObject -Uri $repUri
    }
    Invoke-WebRequestIndep -Method "Get" -Uri $rep.url -OutFile (MakeFsCompatiblePath("$DataRoot$repDir\$repName.zip"))
}

##### Starting exports GeneralInformation
#####
Write-Host "Exporting GeneralInformation" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot")) { $null = New-Item -Path "$DataRoot" -ItemType Directory -Force }

try {
    #groups
    $uri = "/beta/groups"
    $groups = Get-MsGraphCollection -Uri $uri
    $groups | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\"+(MakeFsCompatiblePath("groups.json"))) -Force
    $GitReadyFiles += ("$DataRoot\"+(MakeFsCompatiblePath("groups.json")))
} catch {
    Write-Warning "Could not export groups"
    Write-Warning $_
}

try {
    #users
    $uri = "/beta/users"
    $users = Get-MsGraphCollection -Uri $uri
    $users | Sort-Object -Property Id | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\"+(MakeFsCompatiblePath("users.json"))) -Force
    $GitReadyFiles += ("$DataRoot\"+(MakeFsCompatiblePath("users.json")))
} catch {
    Write-Warning "Could not export users"
    Write-Warning $_
}

try {
    #roles
    $uri = "/beta/directoryRoles"
    $roles = Get-MsGraphCollection -Uri $uri
    $roles | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\"+(MakeFsCompatiblePath("directoryRoles.json"))) -Force
    $GitReadyFiles += ("$DataRoot\"+(MakeFsCompatiblePath("directoryRoles.json")))
} catch {
    Write-Warning "Could not export roles"
    Write-Warning $_
}

try {
    #managedDeviceOverview
    $uri = "/beta/deviceManagement/managedDeviceOverview"
    $managedDeviceOverview = Get-MsGraphCollection -Uri $uri
    $managedDeviceOverview | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\"+(MakeFsCompatiblePath("managedDeviceOverview.json"))) -Force
    $GitReadyFiles += ("$DataRoot\"+(MakeFsCompatiblePath("managedDeviceOverview.json")))
} catch {
    Write-Warning "Could not export managedDeviceOverview"
    Write-Warning $_
}

##### Starting exports AndroidEnterprise
#####
Write-Host "Exporting AndroidEnterprise" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\AndroidEnterprise")) { $null = New-Item -Path "$DataRoot\AndroidEnterprise" -ItemType Directory -Force }

try {
    #deviceEnrollmentConfigurations
    $uri = "/beta/deviceManagement/deviceEnrollmentConfigurations"
    $deviceEnrollmentConfigurations = Get-MsGraphCollection -Uri $uri
    $deviceEnrollmentConfigurations | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AndroidEnterprise\"+(MakeFsCompatiblePath("deviceEnrollmentConfigurations.json"))) -Force
    $GitReadyFiles += ("$DataRoot\AndroidEnterprise\"+(MakeFsCompatiblePath("deviceEnrollmentConfigurations.json")))
    $androidEnterpriseConfig = $deviceEnrollmentConfigurations | Where-Object { $_.androidForWorkRestriction.platformBlocked -eq $false }
    foreach($androidConfig in $androidEnterpriseConfig)
    {
        $uri = "/beta/deviceManagement/deviceEnrollmentConfigurations/$($androidConfig.id)/assignments"
        $assignments = Get-MsGraphObject -Uri $uri
        $assignments | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AndroidEnterprise\"+(MakeFsCompatiblePath("assignments_$($androidConfig.id).json"))) -Force
        $GitReadyFiles += ("$DataRoot\AndroidEnterprise\"+(MakeFsCompatiblePath("assignments_$($androidConfig.id).json")))
    }
} catch {
    Write-Warning "Could not export deviceEnrollmentConfigurations"
    Write-Warning $_
}

try {
    #androidDeviceOwnerEnrollmentProfiles
    $now = (Get-Date -Format s)
    $uri = "/beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles?`$filter=tokenExpirationDateTime gt $($now)z"
    $androidDeviceOwnerEnrollmentProfiles = Get-MsGraphCollection -Uri $uri
    $androidDeviceOwnerEnrollmentProfiles | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AndroidEnterprise\"+(MakeFsCompatiblePath("androidDeviceOwnerEnrollmentProfiles.json"))) -Force
    $GitReadyFiles += ("$DataRoot\AndroidEnterprise\"+(MakeFsCompatiblePath("androidDeviceOwnerEnrollmentProfiles.json")))
    $profiles = $androidDeviceOwnerEnrollmentProfiles
    foreach($profile in $profiles)
    {
        $uri = "/beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles/$($profile.id)?`$select=qrCodeImage"
        $qrCode = Get-MsGraphObject -Uri $uri
        $qrCode | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AndroidEnterprise\"+(MakeFsCompatiblePath("qrCode_$($profile.id).json"))) -Force
        $GitReadyFiles += ("$DataRoot\AndroidEnterprise\"+(MakeFsCompatiblePath("qrCode_$($profile.id).json")))
        if ($qrCode.value -and $qrCode.value.qrCodeImage)
        {
            $type = $qrCode.value.qrCodeImage.type
            $value = $qrCode.value.qrCodeImage.value
            $imageType = $type.split("/")[1]
            $filename = "$DataRoot\AndroidEnterprise\qrCode_$($profile.id).$($imageType)"
            $bytes = [Convert]::FromBase64String($value)
            [IO.File]::WriteAllBytes($filename, $bytes)
        }
    }
} catch {
    Write-Warning "Could not export androidDeviceOwnerEnrollmentProfiles"
    Write-Warning $_
}

try {
    #androidManagedStoreAccountEnterpriseSettings
    $uri = "/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings"
    $androidManagedStoreAccountEnterpriseSettings = Get-MsGraphObject -Uri $uri
    $androidManagedStoreAccountEnterpriseSettings | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AndroidEnterprise\"+(MakeFsCompatiblePath("androidManagedStoreAccountEnterpriseSettings.json"))) -Force
    $GitReadyFiles += ("$DataRoot\AndroidEnterprise\"+(MakeFsCompatiblePath("androidManagedStoreAccountEnterpriseSettings.json")))
} catch {
    Write-Warning "Could not export androidManagedStoreAccountEnterpriseSettings"
    Write-Warning $_
}


##### Starting exports ConfigurationPolicy
#####
Write-Host "Exporting ConfigurationPolicy" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\ConfigurationPolicy")) { $null = New-Item -Path "$DataRoot\ConfigurationPolicy" -ItemType Directory -Force }

try {
    #configurationPolicies
    $uri = "/beta/deviceManagement/configurationPolicies"
    $configurationPolicies = Get-MsGraphCollection -Uri $uri
    foreach($configurationPolicy in $configurationPolicies)
    {
        $uri = "/beta/deviceManagement/configurationPolicies/$($configurationPolicy.Id)/settings"
        $configurationPolicySettings = Get-MsGraphCollection -Uri $uri
        $configurationPolicySettings | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\ConfigurationPolicy\"+(MakeFsCompatiblePath("$($configurationPolicy.Id).json"))) -Force
        $GitReadyFiles += ("$DataRoot\ConfigurationPolicy\"+(MakeFsCompatiblePath("$($configurationPolicy.Id).json")))
        $configurationPolicy["settings"] = $configurationPolicySettings
    }
    $configurationPolicies | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\ConfigurationPolicy\"+(MakeFsCompatiblePath("configurationPolicies.json"))) -Force
    $GitReadyFiles += ("$DataRoot\ConfigurationPolicy\"+(MakeFsCompatiblePath("configurationPolicies.json")))
} catch {
    Write-Warning "Could not export configurationPolicies"
    Write-Warning $_
}


##### Starting exports AppConfigurationPolicy
#####
Write-Host "Exporting AppConfigurationPolicy" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\AppConfigurationPolicy")) { $null = New-Item -Path "$DataRoot\AppConfigurationPolicy" -ItemType Directory -Force }

try {
    #targetedManagedAppConfigurations
    $uri = "/beta/deviceAppManagement/targetedManagedAppConfigurations?`$expand=apps"
    $targetedManagedAppConfigurations = Get-MsGraphObject -Uri $uri
    $targetedManagedAppConfigurations | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AppConfigurationPolicy\"+(MakeFsCompatiblePath("targetedManagedAppConfigurations.json"))) -Force
    $GitReadyFiles += ("$DataRoot\AppConfigurationPolicy\"+(MakeFsCompatiblePath("targetedManagedAppConfigurations.json")))
} catch {
    Write-Warning "Could not export targetedManagedAppConfigurations"
    Write-Warning $_
}

try {
    #mobileAppConfigurations
    $uri = "/beta/deviceAppManagement/mobileAppConfigurations"
    $mobileAppConfigurations = Get-MsGraphCollection -Uri $uri
    $mobileAppConfigurations | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AppConfigurationPolicy\"+(MakeFsCompatiblePath("mobileAppConfigurations.json"))) -Force
    $GitReadyFiles += ("$DataRoot\AppConfigurationPolicy\"+(MakeFsCompatiblePath("mobileAppConfigurations.json")))
    foreach($config in $mobileAppConfigurations)
    {
        $uri = "/beta/deviceAppManagement/mobileAppConfigurations/$($config.id)/deviceStatuses"
        $deviceStatuses = Get-MsGraphObject -Uri $uri
        $deviceStatuses | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AppConfigurationPolicy\"+(MakeFsCompatiblePath("mobileAppConfiguration_deviceStatuses_$($config.id).json"))) -Force
        $GitReadyFiles += ("$DataRoot\AppConfigurationPolicy\"+(MakeFsCompatiblePath("mobileAppConfiguration_deviceStatuses_$($config.id).json")))
        $uri = "/beta/deviceAppManagement/mobileAppConfigurations/$($config.id)/userStatuses"
        $userStatuses = Get-MsGraphObject -Uri $uri
        $userStatuses | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AppConfigurationPolicy\"+(MakeFsCompatiblePath("mobileAppConfiguration_userStatuses_$($config.id).json"))) -Force
        $GitReadyFiles += ("$DataRoot\AppConfigurationPolicy\"+(MakeFsCompatiblePath("mobileAppConfiguration_userStatuses_$($config.id).json")))
    }
} catch {
    Write-Warning "Could not export mobileAppConfigurations"
    Write-Warning $_
}


##### Starting exports AppleEnrollment
#####
Write-Host "Exporting AppleEnrollment" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\AppleEnrollment")) { $null = New-Item -Path "$DataRoot\AppleEnrollment" -ItemType Directory -Force }

#applePushNotificationCertificateapplePushNotificationCertificate
#TODO $uri = "/beta/devicemanagement/applePushNotificationCertificate"
#TODO $applePushNotificationCertificate = Get-MsGraphObject -Uri $uri
#TODO $applePushNotificationCertificate | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AppleEnrollment\"+(MakeFsCompatiblePath("applePushNotificationCertificate.json")) -Force


try {
    #depOnboardingSettings
    $uri = "/beta/deviceManagement/depOnboardingSettings"
    $depOnboardingSettings = Get-MsGraphCollection -Uri $uri
    $depOnboardingSettings | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AppleEnrollment\"+(MakeFsCompatiblePath("depOnboardingSettings.json"))) -Force
    $GitReadyFiles += ("$DataRoot\AppleEnrollment\"+(MakeFsCompatiblePath("depOnboardingSettings.json")))
    foreach($profile in $depOnboardingSettings)
    {
        $uri = "/beta/deviceManagement/depOnboardingSettings/$($profile.id)/enrollmentProfiles"
        $enrollmentProfile = Get-MsGraphObject -Uri $uri
        $enrollmentProfile | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AppleEnrollment\"+(MakeFsCompatiblePath("enrollmentProfile_$($profile.id).json"))) -Force
        $GitReadyFiles += ("$DataRoot\AppleEnrollment\"+(MakeFsCompatiblePath("enrollmentProfile_$($profile.id).json")))
    }
} catch {
    Write-Warning "Could not export depOnboardingSettings"
    Write-Warning $_
}

try {
    #managedEbooks
    $uri = "/beta/deviceAppManagement/managedEbooks"
    $managedEbooks = Get-MsGraphObject -Uri $uri
    $managedEbooks | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AppleEnrollment\"+(MakeFsCompatiblePath("managedEbooks.json"))) -Force
    $GitReadyFiles += ("$DataRoot\AppleEnrollment\"+(MakeFsCompatiblePath("managedEbooks.json")))
} catch {
    Write-Warning "Could not export managedEbooks"
    Write-Warning $_
}

try {
    #iosLobAppProvisioningConfigurations
    $uri = "/beta/deviceAppManagement/iosLobAppProvisioningConfigurations?`$expand=assignments"
    $iosLobAppProvisioningConfigurations = Get-MsGraphObject -Uri $uri
    $iosLobAppProvisioningConfigurations | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\AppleEnrollment\"+(MakeFsCompatiblePath("iosLobAppProvisioningConfigurations.json"))) -Force
    $GitReadyFiles += ("$DataRoot\AppleEnrollment\"+(MakeFsCompatiblePath("iosLobAppProvisioningConfigurations.json")))
} catch {
    Write-Warning "Could not export iosLobAppProvisioningConfigurations"
    Write-Warning $_
}


##### Starting exports Auditing
#####
Write-Host "Exporting Auditing" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\Auditing")) { $null = New-Item -Path "$DataRoot\Auditing" -ItemType Directory -Force }


try {
    #auditCategories
    $uri = "/beta/deviceManagement/auditEvents/getAuditCategories"
    $auditCategories = Get-MsGraphObject -Uri $uri
    $auditCategories | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Auditing\"+(MakeFsCompatiblePath("auditCategories.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Auditing\"+(MakeFsCompatiblePath("auditCategories.json")))
} catch {
    Write-Warning "Could not export auditCategories"
    Write-Warning $_
}

#auditEvents
#TODO
#$daysago = "{0:s}" -f (get-date).AddDays(-30) + "Z"
#$uri = "/beta/deviceManagement/auditEvents?`$filter=activityDateTime gt $daysago"
#$auditEvents = Get-MsGraphObject -Uri $uri
#$auditEvents | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Auditing\"+(MakeFsCompatiblePath("auditEvents.json")) -Force

try {
    #remoteActionAudits
    $uri = "/beta/deviceManagement/remoteActionAudits"
    $remoteActionAudits = Get-MsGraphObject -Uri $uri
    $remoteActionAudits | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Auditing\"+(MakeFsCompatiblePath("remoteActionAudits.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Auditing\"+(MakeFsCompatiblePath("remoteActionAudits.json")))
} catch {
    Write-Warning "Could not export remoteActionAudits"
    Write-Warning $_
}

try {
    #iosUpdateStatuses
    $uri = "/beta/deviceManagement/iosUpdateStatuses"
    $iosUpdateStatuses = Get-MsGraphObject -Uri $uri
    $iosUpdateStatuses | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Auditing\"+(MakeFsCompatiblePath("iosUpdateStatuses.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Auditing\"+(MakeFsCompatiblePath("iosUpdateStatuses.json")))
} catch {
    Write-Warning "Could not export managedDeviceOverview"
    Write-Warning $_
}


##### Starting exports CertificationAuthority
#####
Write-Host "Exporting CertificationAuthority" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\CertificationAuthority")) { $null = New-Item -Path "$DataRoot\CertificationAuthority" -ItemType Directory -Force }

try {
    #ndesconnectors
    $uri = "/beta/deviceManagement/ndesconnectors"
    $ndesconnectors = Get-MsGraphObject -Uri $uri
    $ndesconnectors | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\CertificationAuthority\"+(MakeFsCompatiblePath("ndesconnectors.json"))) -Force
    $GitReadyFiles += ("$DataRoot\CertificationAuthority\"+(MakeFsCompatiblePath("ndesconnectors.json")))

    if (-Not $AlyaIsDevOpsPipeline)
    {
        ##### Starting exports CompanyPortalBranding
        #####
        Write-Host "Exporting CompanyPortalBranding" -ForegroundColor $CommandInfo
        if (-Not (Test-Path "$DataRoot\CompanyPortalBranding")) { $null = New-Item -Path "$DataRoot\CompanyPortalBranding" -ItemType Directory -Force }

        #intuneBrand
        $uri = "/beta/deviceManagement/intuneBrand"
        $intuneBrand = Get-MsGraphObject -Uri $uri
        $intuneBrand | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\CompanyPortalBranding\"+(MakeFsCompatiblePath("intuneBrand.json"))) -Force
        $GitReadyFiles += ("$DataRoot\CompanyPortalBranding\"+(MakeFsCompatiblePath("intuneBrand.json")))

        #intuneBrandingProfiles
        $uri = "/beta/deviceManagement/intuneBrandingProfiles"
        $intuneBrandingProfiles = Get-MsGraphObject -Uri $uri
        $intuneBrandingProfiles | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\CompanyPortalBranding\"+(MakeFsCompatiblePath("intuneBrandingProfiles.json"))) -Force
        $GitReadyFiles += ("$DataRoot\CompanyPortalBranding\"+(MakeFsCompatiblePath("intuneBrandingProfiles.json")))
    }
} catch {
    Write-Warning "Could not export ndesconnectors"
    Write-Warning $_
}


##### Starting exports CompliancePolicy
#####
Write-Host "Exporting CompliancePolicy" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\CompliancePolicy")) { $null = New-Item -Path "$DataRoot\CompliancePolicy" -ItemType Directory -Force }

try {
    #deviceCompliancePolicies
    $uri = "/beta/deviceManagement/deviceCompliancePolicies"
    $deviceCompliancePolicies = Get-MsGraphCollection -Uri $uri
    $deviceCompliancePolicies | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\CompliancePolicy\"+(MakeFsCompatiblePath("deviceCompliancePolicies.json"))) -Force
    $GitReadyFiles += ("$DataRoot\CompliancePolicy\"+(MakeFsCompatiblePath("deviceCompliancePolicies.json")))
    foreach($policy in $deviceCompliancePolicies)
    {
        $uri = "/beta/deviceManagement/deviceCompliancePolicies/$($policy.id)/assignments"
        $assignments = Get-MsGraphObject -Uri $uri
        $assignments | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\CompliancePolicy\"+(MakeFsCompatiblePath("deviceCompliancePolicy_assignment_$($policy.id).json"))) -Force
        $GitReadyFiles += ("$DataRoot\CompliancePolicy\"+(MakeFsCompatiblePath("deviceCompliancePolicy_assignment_$($policy.id).json")))
    }
} catch {
    Write-Warning "Could not export deviceCompliancePolicies"
    Write-Warning $_
}


##### Starting exports CorporateDeviceEnrollment
#####
Write-Host "Exporting CorporateDeviceEnrollment" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\CorporateDeviceEnrollment")) { $null = New-Item -Path "$DataRoot\CorporateDeviceEnrollment" -ItemType Directory -Force }

try {
    #importedDeviceIdentities
    $uri = "/beta/deviceManagement/importedDeviceIdentities"
    $importedDeviceIdentities = Get-MsGraphObject -Uri $uri
    $importedDeviceIdentities | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\CorporateDeviceEnrollment\"+(MakeFsCompatiblePath("importedDeviceIdentities.json"))) -Force
    $GitReadyFiles += ("$DataRoot\CorporateDeviceEnrollment\"+(MakeFsCompatiblePath("importedDeviceIdentities.json")))
} catch {
    Write-Warning "Could not export importedDeviceIdentities"
    Write-Warning $_
}

##### Starting exports GroupPolicyConfiguration
#####
Write-Host "Exporting GroupPolicyConfiguration" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\GroupPolicyConfiguration")) { $null = New-Item -Path "$DataRoot\GroupPolicyConfiguration" -ItemType Directory -Force }

try {
    #groupPolicyObjectFiles
    $uri = "/beta/deviceManagement/groupPolicyObjectFiles"
    $groupPolicyObjectFiles = Get-MsGraphObject -Uri $uri
    $groupPolicyObjectFiles | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyObjectFiles.json"))) -Force
    $GitReadyFiles += ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyObjectFiles.json")))
} catch {
    Write-Warning "Could not export groupPolicyObjectFiles"
    Write-Warning $_
}

try {
    #groupPolicyMigrationReport 
    $uri = "/beta/deviceManagement/groupPolicyMigrationReports"
    $groupPolicyMigrationReport  = Get-MsGraphObject -Uri $uri
    $groupPolicyMigrationReport  | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyMigrationReport.json"))) -Force
    $GitReadyFiles += ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyMigrationReport.json")))
} catch {
    Write-Warning "Could not export groupPolicyMigrationReport "
    Write-Warning $_
}

try {
    #groupPolicyDefinitions
    $uri = "/beta/deviceManagement/groupPolicyDefinitions"
    $groupPolicyDefinitions = Get-MsGraphObject -Uri $uri
    $groupPolicyDefinitions | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyDefinitions.json"))) -Force
    $GitReadyFiles += ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyDefinitions.json")))
} catch {
    Write-Warning "Could not export groupPolicyDefinitions"
    Write-Warning $_
}

try {
    #groupPolicyDefinitions
    $uri = "/beta/deviceManagement/groupPolicyDefinitions"
    $groupPolicyDefinitions = Get-MsGraphObject -Uri $uri
    $groupPolicyDefinitions | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyDefinitions.json"))) -Force
    $GitReadyFiles += ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyDefinitions.json")))
} catch {
    Write-Warning "Could not export groupPolicyDefinitions"
    Write-Warning $_
}

try {
    #groupPolicyCategories
    $uri = "/beta/deviceManagement/groupPolicyCategories"
    $groupPolicyCategories = Get-MsGraphObject -Uri $uri
    $groupPolicyCategories | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyCategories.json"))) -Force
    $GitReadyFiles += ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyCategories.json")))
} catch {
    Write-Warning "Could not export managedDeviceOverview"
    Write-Warning $_
}

try {
    #groupPolicyUploadedDefinitionFiles
    $uri = "/beta/deviceManagement/groupPolicyUploadedDefinitionFiles"
    $groupPolicyUploadedDefinitionFiles = Get-MsGraphObject -Uri $uri
    $groupPolicyUploadedDefinitionFiles | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyUploadedDefinitionFiles.json"))) -Force
    $GitReadyFiles += ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyUploadedDefinitionFiles.json")))
} catch {
    Write-Warning "Could not export groupPolicyUploadedDefinitionFiles"
    Write-Warning $_
}

try {
    #groupPolicyConfigurations
    $uri = "/beta/deviceManagement/groupPolicyConfigurations"
    $groupPolicyConfigurations = Get-MsGraphCollection -Uri $uri
    foreach($policy in $groupPolicyConfigurations)
    {
        #$policy = $groupPolicyConfigurations[3]
        $policy | Add-Member -MemberType NoteProperty -Name "@odata.type" -Value "#Microsoft.Graph.groupPolicyConfiguration" -Force

        $uri = "/beta/deviceManagement/groupPolicyConfigurations/$($policy.id)/assignments"
        $assignments = Get-MsGraphObject -Uri $uri
        $policy | Add-Member -MemberType NoteProperty -Name assignments -Value $assignments -Force

        $uri = "/beta/deviceManagement/groupPolicyConfigurations/$($policy.id)/definitionValues"
        $definitionValues = Get-MsGraphCollection -Uri $uri
        foreach($definitionValue in $definitionValues)
        {
            #$definitionValue = $definitionValues[0]
            Add-Member -InputObject $definitionValue -MemberType NoteProperty -Name "@odata.type" -Value "#Microsoft.Graph.groupPolicyDefinitionValue" -Force

            $uri = "/beta/deviceManagement/groupPolicyConfigurations/$($policy.id)/definitionValues/$($definitionValue.id)/definition"
            $definitionValueDefinition = Get-MsGraphObject -Uri $uri -ErrorAction SilentlyContinue
            Add-Member -InputObject $definitionValue -MemberType NoteProperty -Name "definition" -Value $definitionValueDefinition -Force
            Add-Member -InputObject $definitionValue -MemberType NoteProperty -Name "definition@odata.bind" -Value "$AlyaGraphEndpoint/beta/deviceManagement/groupPolicyDefinitions('$($definitionValueDefinition.id)')" -Force

            $uri = "/beta/deviceManagement/groupPolicyConfigurations/$($policy.id)/definitionValues/$($definitionValue.id)/presentationValues?`$expand=presentation"
            $presentationValues = Get-MsGraphCollection -Uri $uri -ErrorAction SilentlyContinue
            foreach($presentationValue in $presentationValues)
            {
                Add-Member -InputObject $presentationValue -MemberType NoteProperty -Name "presentation@odata.bind" -Value "/beta/deviceManagement/groupPolicyDefinitions('$($definitionValueDefinition.id)')/presentations('$($presentationValue.presentation.id)')" -Force
                
                $uri = "/beta/deviceManagement/groupPolicyConfigurations/$($policy.id)/definitionValues/$($definitionValue.id)/presentationValues/$($presentationValue.id)/presentation"
                $presentationValuePresentation = Get-MsGraphObject -Uri $uri -ErrorAction SilentlyContinue
                Add-Member -InputObject $presentationValue -MemberType NoteProperty -Name "presentation" -Value $presentationValuePresentation -Force

                <#
                try
                {
                    # TODO BadRequest
                    $uri = "/beta/deviceManagement/groupPolicyConfigurations/$($policy.id)/definitionValues/$($definitionValue.id)/presentationValues/$($presentationValue.id)/presentation/definition"
                    $presentationValueDefinition = Get-MsGraphObject -Uri $uri -ErrorAction SilentlyContinue
                    Add-Member -InputObject $presentationValue -MemberType NoteProperty -Name definition -Value $presentationValueDefinition -Force
                } catch { }
                try
                {
                    # TODO BadRequest
                    $uri = "/beta/deviceManagement/groupPolicyConfigurations/$($policy.id)/definitionValues/$($definitionValue.id)/presentationValues/$($presentationValue.id)/presentation/definition/nextVersionDefinition"
                    $presentationValueDefinitionNext = Get-MsGraphObject -Uri $uri -ErrorAction SilentlyContinue
                    Add-Member -InputObject $presentationValue -MemberType NoteProperty -Name definitionNext -Value $presentationValueDefinitionNext -Force
                } catch { }
                try
                {
                    # TODO BadRequest
                    $uri = "/beta/deviceManagement/groupPolicyConfigurations/$($policy.id)/definitionValues/$($definitionValue.id)/presentationValues/$($presentationValue.id)/presentation/definition/previousVersionDefinition"
                    $presentationValueDefinitionPrev = Get-MsGraphObject -Uri $uri -ErrorAction SilentlyContinue
                    Add-Member -InputObject $presentationValue -MemberType NoteProperty -Name definitionPrev -Value $presentationValueDefinitionPrev -Force
                } catch { }
                try
                {
                    # TODO BadRequest
                    $uri = "/beta/deviceManagement/groupPolicyConfigurations/$($policy.id)/definitionValues/$($definitionValue.id)/presentationValues/$($presentationValue.id)/presentation/definition/category/definitions"
                    $presentationValueCategories = Get-MsGraphObject -Uri $uri -ErrorAction SilentlyContinue
                    Add-Member -InputObject $presentationValue -MemberType NoteProperty -Name categories -Value $presentationValueCategories -Force
                } catch { }
                try
                {
                    # TODO BadRequest
                    $uri = "/beta/deviceManagement/groupPolicyConfigurations/$($policy.id)/definitionValues/$($definitionValue.id)/presentationValues/$($presentationValue.id)/presentation/definition/definitionFile/definitions"
                    $presentationValueFiles = Get-MsGraphObject -Uri $uri -ErrorAction SilentlyContinue
                    Add-Member -InputObject $presentationValue -MemberType NoteProperty -Name files -Value $presentationValueFiles -Force
                } catch { }
                try
                {
                    # TODO BadRequest
                    $uri = "/beta/deviceManagement/groupPolicyConfigurations/$($policy.id)/definitionValues/$($definitionValue.id)/presentationValues/$($presentationValue.id)/presentation/definition/presentations"
                    $presentationValuePresentations = Get-MsGraphObject -Uri $uri -ErrorAction SilentlyContinue
                    Add-Member -InputObject $presentationValue -MemberType NoteProperty -Name presentations -Value $presentationValuePresentations.value -Force
                } catch { }
                #>
                <#
                GET /deviceManagement/groupPolicyConfigurations/{groupPolicyConfigurationId}/definitionValues/{groupPolicyDefinitionValueId}/presentationValues/{groupPolicyPresentationValueId}/presentation/definition/category/definitions/{groupPolicyDefinitionId}
                GET /deviceManagement/groupPolicyConfigurations/{groupPolicyConfigurationId}/definitionValues/{groupPolicyDefinitionValueId}/presentationValues/{groupPolicyPresentationValueId}/presentation/definition/definitionFile/definitions/{groupPolicyDefinitionId}
                #>
            }
            Add-Member -InputObject $definitionValue -MemberType NoteProperty -Name presentationValues -Value $presentationValues -Force
        }
        $policy | Add-Member -MemberType NoteProperty -Name definitionValues -Value $definitionValues -Force
    }
    $groupPolicyConfigurations | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyConfigurations.json"))) -Force
    $GitReadyFiles += ("$DataRoot\GroupPolicyConfiguration\"+(MakeFsCompatiblePath("groupPolicyConfigurations.json")))
} catch {
    Write-Warning "Could not export groupPolicyConfigurations"
    Write-Warning $_
}


##### Starting exports DeviceConfiguration
#####
Write-Host "Exporting DeviceConfiguration" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\DeviceConfiguration")) { $null = New-Item -Path "$DataRoot\DeviceConfiguration" -ItemType Directory -Force }

try {
    #deviceConfigurations
    $uri = "/beta/deviceManagement/deviceConfigurations"
    $deviceConfigurations = Get-MsGraphCollection -Uri $uri
    $deviceConfigurations | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("deviceConfigurations.json"))) -Force
    $GitReadyFiles += ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("deviceConfigurations.json")))
    foreach($policy in $deviceConfigurations)
    {
        $uri = "/beta/deviceManagement/deviceConfigurations/$($policy.id)/groupAssignments"
        $assignments = Get-MsGraphObject -Uri $uri
        $assignments | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("deviceConfiguration_assignment_$($policy.id).json"))) -Force
        $GitReadyFiles += ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("deviceConfiguration_assignment_$($policy.id).json")))
    }
} catch {
    Write-Warning "Could not export deviceConfigurations"
    Write-Warning $_
}

try {
    #deviceManagementScripts
    $uri = "/beta/deviceManagement/deviceManagementScripts?`$expand=groupAssignments"
    $deviceManagementScripts = Get-MsGraphCollection -Uri $uri
    $deviceManagementScripts | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("deviceManagementScripts.json"))) -Force
    $GitReadyFiles += ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("deviceManagementScripts.json")))
    foreach($script in $deviceManagementScripts)
    {
        $uri = "/beta/deviceManagement/deviceManagementScripts/$($script.id)"
        $scriptContent = Get-MsGraphObject -Uri $uri
        $fileName = $scriptContent.fileName
        $scriptContent = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($scriptContent.scriptContent))
        $scriptContent | Set-Content -Encoding UTF8 -Path ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("$($fileName)"))) -Force
        # $uri = "/beta/deviceManagement/deviceManagementScripts/$($script.id)/userRunStates"
        # $userRunStates = Get-MsGraphObject -Uri $uri
        # $userRunStates | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("userRunStates_$($script.id).json"))) -Force
    }
} catch {
    Write-Warning "Could not export deviceManagementScripts"
    Write-Warning $_
}

try {
    #deviceHealthScripts
    $uri = "/beta/deviceManagement/deviceHealthScripts"
    $deviceHealthScripts = Get-MsGraphCollection -Uri $uri
    $deviceHealthScripts | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("deviceHealthScripts.json"))) -Force
    $GitReadyFiles += ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("deviceHealthScripts.json")))
    foreach($script in $deviceHealthScripts)
    {
        $uri = "/beta/deviceManagement/deviceHealthScripts/$($script.id)"
        $scriptContent = Get-MsGraphObject -Uri $uri
        $fileName = $scriptContent.displayName
        $remediationScriptName = "deviceHealthScript_"+ $fileName + "_remediationScript.ps1"
        $scriptContent = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($scriptContent.remediationScriptContent))
        $scriptContent | Set-Content -Encoding UTF8 -Path ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("$($remediationScriptName)"))) -Force
        $detectionScriptName = "deviceHealthScript_"+ $fileName + "_detectionScript.ps1"
        $scriptContent = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($scriptContent.detectionScriptContent))
        $scriptContent | Set-Content -Encoding UTF8 -Path ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("$($detectionScriptName)"))) -Force
    }
} catch {
    Write-Warning "Could not export deviceHealthScripts"
    Write-Warning $_
}

try {
    #deviceComplianceScripts
    $uri = "/beta/deviceManagement/deviceComplianceScripts"
    $deviceComplianceScripts = Get-MsGraphCollection -Uri $uri
    $deviceComplianceScripts | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("deviceComplianceScripts.json"))) -Force
    $GitReadyFiles += ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("deviceComplianceScripts.json")))
    foreach($script in $deviceComplianceScripts)
    {
        $uri = "/beta/deviceManagement/deviceComplianceScripts/$($script.id)"
        $scriptContent = Get-MsGraphObject -Uri $uri
        $fileName = $scriptContent.displayName
        $remediationScriptName = "deviceComplianceScript_"+ $fileName + "_remediationScript.ps1"
        $scriptContent = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($scriptContent.remediationScriptContent))
        $scriptContent | Set-Content -Encoding UTF8 -Path ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("$($remediationScriptName)"))) -Force
        $detectionScriptName = "deviceComplianceScript_"+ $fileName + "_detectionScript.ps1"
        $scriptContent = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($scriptContent.detectionScriptContent))
        $scriptContent | Set-Content -Encoding UTF8 -Path ("$DataRoot\DeviceConfiguration\"+(MakeFsCompatiblePath("$($detectionScriptName)"))) -Force
    }
} catch {
    Write-Warning "Could not export deviceComplianceScripts"
    Write-Warning $_
}

##### Starting exports EnrollmentRestrictions
#####
Write-Host "Exporting EnrollmentRestrictions" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\EnrollmentRestrictions")) { $null = New-Item -Path "$DataRoot\EnrollmentRestrictions" -ItemType Directory -Force }

try {
    #deviceEnrollmentConfigurations
    $uri = "/beta/deviceManagement/deviceEnrollmentConfigurations"
    $deviceEnrollmentConfigurations = Get-MsGraphObject -Uri $uri
    $deviceEnrollmentConfigurations | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\EnrollmentRestrictions\"+(MakeFsCompatiblePath("deviceEnrollmentConfigurations.json"))) -Force
    $GitReadyFiles += ("$DataRoot\EnrollmentRestrictions\"+(MakeFsCompatiblePath("deviceEnrollmentConfigurations.json")))
} catch {
    Write-Warning "Could not export deviceEnrollmentConfigurations"
    Write-Warning $_
}


##### Starting exports Applications
#####
Write-Host "Exporting Applications" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\Applications")) { $null = New-Item -Path "$DataRoot\Applications" -ItemType Directory -Force }

try {
    #mobileAppCategories
    $uri = "/beta/deviceAppManagement/mobileAppCategories"
    $mobileAppCategories = Get-MsGraphObject -Uri $uri
    $mobileAppCategories | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("mobileAppCategories.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("mobileAppCategories.json")))
} catch {
    Write-Warning "Could not export mobileAppCategories"
    Write-Warning $_
}

try {
    #intuneApplications
    $uri = "/beta/deviceAppManagement/mobileApps"
    $intuneApplications = Get-MsGraphCollection -Uri $uri
    $intuneApplications | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplications.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplications.json")))
    if (-Not (Test-Path "$DataRoot\Applications\Data")) { $null = New-Item -Path "$DataRoot\Applications\Data" -ItemType Directory -Force }
    $DeviceInstallStatusByAppUris = @()
    $UserInstallStatusAggregateByAppUris = @()
    foreach($application in $intuneApplications)
    {
        $uri = "/beta/deviceAppManagement/mobileApps/$($application.id)?`$expand=categories"
        $application = Get-MsGraphObject -Uri $uri
        $application | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\Data\"+(MakeFsCompatiblePath("app_$($application.id)_application.json"))) -Force
        $GitReadyFiles += ("$DataRoot\Applications\Data\"+(MakeFsCompatiblePath("app_$($application.id)_application.json")))

        if ($doAppReportExport)
        {
            $uri = "/beta/deviceAppManagement/mobileApps/$($application.id)/assignments"
            $applicationAssignments = Get-MsGraphObject -Uri $uri
            if ($applicationAssignments -and $applicationAssignments.value.Count -gt 0)
            {
                $applicationAssignments | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\Data\"+(MakeFsCompatiblePath("app_$($application.id)_applicationAssignments.json"))) -Force
                $GitReadyFiles += ("$DataRoot\Applications\Data\"+(MakeFsCompatiblePath("app_$($application.id)_applicationAssignments.json")))
                $uri = GetReportUri -reportname "DeviceInstallStatusByApp" -filter "ApplicationId eq '$($application.id)'"
                $DeviceInstallStatusByAppUris += @{app=$application.id;uri=$uri}
                $uri = GetReportUri -reportname "UserInstallStatusAggregateByApp" -filter "ApplicationId eq '$($application.id)'"
                $UserInstallStatusAggregateByAppUris += @{app=$application.id;uri=$uri}
            }
        }
        
        <#
        $uri = "/beta/deviceManagement/reports/getAppStatusOverviewReport"
        $getAppStatusOverviewReport = Post-MsGraph -Uri $uri -Body "{`"filter`":`"(ApplicationId eq '$($application.id)')`"}" -OutputFile ("$DataRoot\Applications\Data\"+(MakeFsCompatiblePath("app_$($application.id)_appStatusOverviewReport.json"))
        
        $uri = "/beta/deviceManagement/reports/getAppsInstallSummaryReport"
        $getAppStatusOverviewReport = Post-MsGraph -Uri $uri -Body "{`"filter`":`"(ApplicationId eq '$($application.id)')`"}" -OutputFile ("$DataRoot\Applications\Data\"+(MakeFsCompatiblePath("app_$($application.id)_appsInstallSummaryReport.json"))
        #>
    }
    foreach($appUri in $DeviceInstallStatusByAppUris)
    {
        DownloadReport -repUri $appUri.uri -repName "app_$($appUri.app)_deviceInstallStatusByApp" -repDir "\Applications\Data"
    }
    foreach($appUri in $UserInstallStatusAggregateByAppUris)
    {
        DownloadReport -repUri $appUri.uri -repName "app_$($appUri.app)_userInstallStatusAggregateByApp" -repDir "\Applications\Data"
    }

    $mdmApps = $intuneApplications | Where-Object { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.iosVppApp")) }
    foreach($mdmApp in $mdmApps)
    {
        $uri = "/beta/deviceAppManagement/mobileApps/$($mdmApp.id)?`$select=largeIcon"
        $appIcon = Get-MsGraphObject -Uri $uri
        $mdmApp.largeIcon = $appIcon.largeIcon
    }

    $intuneApplications | Where-Object { ($_.'@odata.type').Contains("managed") } | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsMAM.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsMAM.json")))
    $mdmApps | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsMDMfull.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsMDMfull.json")))
    $intuneApplications | Where-Object { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.winGetApp")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.iosVppApp")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.windowsAppX")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.androidForWorkApp")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.windowsMobileMSI")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.androidLobApp")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.iosLobApp")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.microsoftStoreForBusinessApp")) } | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsMDM.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsMDM.json")))
    $intuneApplications | Where-Object { ($_.'@odata.type').Contains("win32") } | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsWIN32.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsWIN32.json")))
    $intuneApplications | Where-Object { ($_.'@odata.type').Contains("winGetApp") } | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsWinGet.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsWinGet.json")))
    $intuneApplications | Where-Object { ($_.'@odata.type').Contains("managedAndroidStoreApp") } | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsAndroid.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsAndroid.json")))
    $intuneApplications | Where-Object { ($_.'@odata.type').Contains("managedIOSStoreApp") } | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsIos.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("intuneApplicationsIos.json")))

} catch {
    Write-Warning "Could not export intuneApplications"
    Write-Warning $_
}

try {
    #mobileAppConfigurations
    $uri = "/beta/deviceAppManagement/mobileAppConfigurations?`$expand=assignments"
    $mobileAppConfigurations = Get-MsGraphObject -Uri $uri
    $mobileAppConfigurations | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("mobileAppConfigurations.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("mobileAppConfigurations.json")))
} catch {
    Write-Warning "Could not export mobileAppConfigurations"
    Write-Warning $_
}

try {
    #targetedManagedAppConfigurations
    $uri = "/beta/deviceAppManagement/targetedManagedAppConfigurations"
    $targetedManagedAppConfigurations = Get-MsGraphCollection -Uri $uri
    $targetedManagedAppConfigurations | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("targetedManagedAppConfigurations.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("targetedManagedAppConfigurations.json")))
    foreach($configuration in $targetedManagedAppConfigurations)
    {
        $uri = "/beta/deviceAppManagement/targetedManagedAppConfigurations('$($configuration.id)')?`$expand=apps,assignments"
        $configuration = Get-MsGraphObject -Uri $uri
        $configuration | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("targetedManagedAppConfiguration_$($configuration.id).json"))) -Force
        $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("targetedManagedAppConfiguration_$($configuration.id).json")))
    }
} catch {
    Write-Warning "Could not export targetedManagedAppConfigurations"
    Write-Warning $_
}

try {
    #appregistrationSummary
    $uri = "/beta/deviceAppManagement/managedAppStatuses('appregistrationsummary')?fetch=6000&policyMode=0&columns=DisplayName,UserEmail,ApplicationName,ApplicationInstanceId,ApplicationVersion,DeviceName,DeviceType,DeviceManufacturer,DeviceModel,AndroidPatchVersion,AzureADDeviceId,MDMDeviceID,Platform,PlatformVersion,ManagementLevel,PolicyName,LastCheckInDate"
    $appregistrationSummary = Get-MsGraphObject -Uri $uri
    $appregistrationSummary | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("appregistrationSummary.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("appregistrationSummary.json")))
} catch {
    Write-Warning "Could not export appregistrationSummary"
    Write-Warning $_
}

# TODO
#windowsProtectionReport
# $uri = "/beta/deviceAppManagement/managedAppStatuses('windowsprotectionreport')"
# $windowsProtectionReport = Get-MsGraphObject -Uri $uri
# $windowsProtectionReport | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("windowsProtectionReport.json")) -Force

try {
    #mdmWindowsInformationProtectionPolicies
    $uri = "/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies"
    $mdmWindowsInformationProtectionPolicies = Get-MsGraphObject -Uri $uri
    $mdmWindowsInformationProtectionPolicies | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("mdmWindowsInformationProtectionPolicies.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("mdmWindowsInformationProtectionPolicies.json")))
} catch {
    Write-Warning "Could not export mdmWindowsInformationProtectionPolicies"
    Write-Warning $_
}

try {
    #managedAppPolicies
    $uri = "/beta/deviceAppManagement/managedAppPolicies"
    $managedAppPolicies = Get-MsGraphCollection -Uri $uri
    $managedAppPolicies | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("managedAppPolicies.json"))) -Force
    $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("managedAppPolicies.json")))
    foreach($managedAppPolicy in $managedAppPolicies)
    {
        try {
            #TODO
            $uri = "/beta/deviceAppManagement/androidManagedAppProtections('$($managedAppPolicy.id)')?`$expand=apps"
            $policy = Get-MsGraphObject -Uri $uri
            $policy | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("managedAppPolicy_$($policy.id)_android.json"))) -Force
            $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("managedAppPolicy_$($policy.id)_android.json")))
        } catch {
            Write-Warning "Could not export androidManagedAppProtections for policy $($managedAppPolicy.id)"
        }
        try {
            #TODO
            $uri = "/beta/deviceAppManagement/iosManagedAppProtections('$($managedAppPolicy.id)')?`$expand=apps"
            $policy = Get-MsGraphObject -Uri $uri
            $policy | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("managedAppPolicy_$($policy.id)_ios.json"))) -Force
            $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("managedAppPolicy_$($policy.id)_ios.json")))
        } catch {
            Write-Warning "Could not export iosManagedAppProtections for policy $($managedAppPolicy.id)"
        }
        try {
            #TODO
            $uri = "/beta/deviceAppManagement/windowsInformationProtectionPolicies('$($managedAppPolicy.id)')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
            $policy = Get-MsGraphObject -Uri $uri
            $policy | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("managedAppPolicy_$($policy.id)_windows.json"))) -Force
            $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("managedAppPolicy_$($policy.id)_windows.json")))
        } catch {
            Write-Warning "Could not export windowsInformationProtectionPolicies for policy $($managedAppPolicy.id)"
        }
        try {
            #TODO
            $uri = "/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies('$($managedAppPolicy.id)')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
            $policy = Get-MsGraphObject -Uri $uri
            $policy | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\Applications\"+(MakeFsCompatiblePath("managedAppPolicy_$($policy.id)_mdm.json"))) -Force
            $GitReadyFiles += ("$DataRoot\Applications\"+(MakeFsCompatiblePath("managedAppPolicy_$($policy.id)_mdm.json")))
        } catch {
            Write-Warning "Could not export mdmWindowsInformationProtectionPolicies for policy $($managedAppPolicy.id)"
        }
    }
} catch {
    Write-Warning "Could not export managedAppPolicies"
    Write-Warning $_
}


##### Starting exports Reports
#####
if ($doReportExport)
{
    Write-Host "Exporting Reports" -ForegroundColor $CommandInfo
    if (-Not (Test-Path "$DataRoot\Reports")) { $null = New-Item -Path "$DataRoot\Reports" -ItemType Directory -Force }

    $DeviceComplianceUri = GetReportUri -reportname "DeviceCompliance"
    $DeviceNonComplianceUri = GetReportUri -reportname "DeviceNonCompliance"
    $DevicesUri = GetReportUri -reportname "Devices"
    $FeatureUpdatePolicyFailuresAggregateUri = GetReportUri -reportname "FeatureUpdatePolicyFailuresAggregate"
    $UnhealthyDefenderAgentsUri = GetReportUri -reportname "UnhealthyDefenderAgents"
    $DefenderAgentsUri = GetReportUri -reportname "DefenderAgents"
    $ActiveMalwareUri = GetReportUri -reportname "ActiveMalware"
    $MalwareUri = GetReportUri -reportname "Malware"
    $AllAppsListUri = GetReportUri -reportname "AllAppsList"
    $AppInstallStatusAggregateUri = GetReportUri -reportname "AppInstallStatusAggregate"
    $ComanagedDeviceWorkloadsUri = GetReportUri -reportname "ComanagedDeviceWorkloads"
    $ComanagementEligibilityTenantAttachedDevicesUri = GetReportUri -reportname "ComanagementEligibilityTenantAttachedDevices"
    $DevicesWithInventoryUri = GetReportUri -reportname "DevicesWithInventory"
    $FirewallStatusUri = GetReportUri -reportname "FirewallStatus"
    $GPAnalyticsSettingMigrationReadinessUri = GetReportUri -reportname "GPAnalyticsSettingMigrationReadiness"
    $MAMAppProtectionStatusUri = GetReportUri -reportname "MAMAppProtectionStatus"
    $MAMAppConfigurationStatusUri = GetReportUri -reportname "MAMAppConfigurationStatus"
    $AppInvAggregateUri = GetReportUri -reportname "AppInvAggregate"
    $AppInvRawDataUri = GetReportUri -reportname "AppInvRawData"

    $uri = "/beta/deviceManagement/reports/getReportFilters"
    $temp = New-TemporaryFile
    Invoke-MgGraphRequest -Method "POST" -Uri $uri -Body "{`"name`": `"FeatureUpdatePolicy`"}" -OutputFilePath $temp
    $fpolicies = (Get-Content -Path $temp -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json).Values
    Remove-Item -Path $temp -Force
    $DeviceFailuresByFeatureUpdatePolicyUris = @()
    foreach($policy in $fpolicies)
    {
        $uri = GetReportUri -reportname "DeviceFailuresByFeatureUpdatePolicy" -filter "PolicyId eq '$($policy[0])'"
        $DeviceFailuresByFeatureUpdatePolicyUris += @{name=$policy[1];uri=$uri}
    }
    $FeatureUpdateDeviceStateUris = @()
    foreach($policy in $fpolicies)
    {
        $uri = GetReportUri -reportname "FeatureUpdateDeviceState" -filter "PolicyId eq '$($policy[0])'"
        $FeatureUpdateDeviceStateUris += @{name=$policy[1];uri=$uri}
    }

    $uri = "/beta/deviceManagement/reports/getReportFilters"
    $temp = New-TemporaryFile
    Invoke-MgGraphRequest -Method "POST" -Uri $uri -Body "{`"name`": `"QualityUpdatePolicy`"}" -OutputFilePath $temp
    $qpolicies = (Get-Content -Path $temp -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json).Values
    Remove-Item -Path $temp -Force
    $QualityUpdateDeviceErrorsByPolicyUris = @()
    foreach($policy in $qpolicies)
    {
        $uri = GetReportUri -reportname "QualityUpdateDeviceErrorsByPolicy" -filter "PolicyId eq '$($policy[0])'"
        $QualityUpdateDeviceErrorsByPolicyUris += @{name=$policy[1];uri=$uri}
    }
    $QualityUpdateDeviceStatusByPolicyUris = @()
    foreach($policy in $qpolicies)
    {
        $uri = GetReportUri -reportname "QualityUpdateDeviceStatusByPolicy" -filter "PolicyId eq '$($policy[0])'"
        $QualityUpdateDeviceStatusByPolicyUris += @{name=$policy[1];uri=$uri}
    }

    DownloadReport -repUri $DeviceComplianceUri -repName "DeviceCompliance" -repDir "\Reports"
    DownloadReport -repUri $DeviceNonComplianceUri -repName "DeviceNonCompliance" -repDir "\Reports"
    DownloadReport -repUri $DevicesUri -repName "Devices" -repDir "\Reports"
    DownloadReport -repUri $FeatureUpdatePolicyFailuresAggregateUri -repName "FeatureUpdatePolicyFailuresAggregate" -repDir "\Reports"
    DownloadReport -repUri $UnhealthyDefenderAgentsUri -repName "UnhealthyDefenderAgents" -repDir "\Reports"
    DownloadReport -repUri $DefenderAgentsUri -repName "DefenderAgents" -repDir "\Reports"
    DownloadReport -repUri $ActiveMalwareUri -repName "ActiveMalware" -repDir "\Reports"
    DownloadReport -repUri $MalwareUri -repName "Malware" -repDir "\Reports"
    DownloadReport -repUri $AllAppsListUri -repName "AllAppsList" -repDir "\Reports"
    DownloadReport -repUri $AppInstallStatusAggregateUri -repName "AppInstallStatusAggregate" -repDir "\Reports"
    DownloadReport -repUri $ComanagedDeviceWorkloadsUri -repName "ComanagedDeviceWorkloads" -repDir "\Reports"
    DownloadReport -repUri $ComanagementEligibilityTenantAttachedDevicesUri -repName "ComanagementEligibilityTenantAttachedDevices" -repDir "\Reports"
    DownloadReport -repUri $DevicesWithInventoryUri -repName "DevicesWithInventory" -repDir "\Reports"
    DownloadReport -repUri $FirewallStatusUri -repName "FirewallStatus" -repDir "\Reports"
    DownloadReport -repUri $GPAnalyticsSettingMigrationReadinessUri -repName "GPAnalyticsSettingMigrationReadiness" -repDir "\Reports"
    DownloadReport -repUri $MAMAppProtectionStatusUri -repName "MAMAppProtectionStatus" -repDir "\Reports"
    DownloadReport -repUri $MAMAppConfigurationStatusUri -repName "MAMAppConfigurationStatus" -repDir "\Reports"
    DownloadReport -repUri $AppInvAggregateUri -repName "AppInvAggregate" -repDir "\Reports"
    DownloadReport -repUri $AppInvRawDataUri -repName "AppInvRawData" -repDir "\Reports"
    foreach($puriPolicy in $DeviceFailuresByFeatureUpdatePolicyUris)
    {
        DownloadReport -repUri $puriPolicy.uri -repName "DeviceFailuresByFeatureUpdatePolicy-$($puriPolicy.name)" -repDir "\Reports"
    }
    foreach($puriPolicy in $FeatureUpdateDeviceStateUris)
    {
        DownloadReport -repUri $puriPolicy.uri -repName "FeatureUpdateDeviceState-$($puriPolicy.name)" -repDir "\Reports"
    }
    foreach($puriPolicy in $QualityUpdateDeviceErrorsByPolicyUris)
    {
        DownloadReport -repUri $puriPolicy.uri -repName "QualityUpdateDeviceErrorsByPolicy-$($puriPolicy.name)" -repDir "\Reports"
    }
    foreach($puriPolicy in $QualityUpdateDeviceStatusByPolicyUris)
    {
        DownloadReport -repUri $puriPolicy.uri -repName "QualityUpdateDeviceStatusByPolicy-$($puriPolicy.name)" -repDir "\Reports"
    }
}

#TODO
#$DeviceRunStatesByProactiveRemediationUri = GetReportUri -reportname "DeviceRunStatesByProactiveRemediation"
#$DevicesByAppInvUri = GetReportUri -reportname "DevicesByAppInv"
#$AppInvByDeviceUri = GetReportUri -reportname "AppInvByDevice"

##### Starting exports ManagedDevices
#####
Write-Host "Exporting ManagedDevices" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\ManagedDevices")) { $null = New-Item -Path "$DataRoot\ManagedDevices" -ItemType Directory -Force }

try {
    #managedDevices
    $uri = "/beta/deviceManagement/managedDevices"
    $managedDevices = Get-MsGraphCollection -Uri $uri
    foreach($device in $managedDevices)
    {
        $device | Add-Member -Name "managedDeviceUser" -Value @() -MemberType NoteProperty
        $uri = "/beta/deviceManagement/manageddevices('$($device.id)')?`$select=userId"
        $managedDeviceUser = Get-MsGraphObject -Uri $uri
        $device.managedDeviceUser = $managedDeviceUser
        $uri = "/beta/deviceManagement/manageddevices('$($device.id)')?`$select=hardwareinformation,iccid,udid,ethernetMacAddress"
        $hardwareinformation = Get-MsGraphObject -Uri $uri
        $device.hardwareinformation = $hardwareinformation
        $device | Add-Member -Name "primaryUsers" -Value @() -MemberType NoteProperty
        $uri = "/beta/deviceManagement/manageddevices('$($device.id)')/users"
        $primaryUsers = Get-MsGraphObject -Uri $uri
        $device.primaryUsers = $primaryUsers
        $device | Add-Member -Name "detectedApps" -Value @() -MemberType NoteProperty
        $uri = "/beta/deviceManagement/manageddevices('$($device.id)')?`$expand=detectedApps"
        $detectedApps = Get-MsGraphObject -Uri $uri
        $device.detectedApps = $detectedApps
    }
    $managedDevices | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\ManagedDevices\"+(MakeFsCompatiblePath("managedDevices.json"))) -Force
    $GitReadyFiles += ("$DataRoot\ManagedDevices\"+(MakeFsCompatiblePath("managedDevices.json")))
} catch {
    Write-Warning "Could not export managedDevices"
    Write-Warning $_
}

try {
    #comanagedDevices
    $uri = "/beta/deviceManagement/comanagedDevices"
    $comanagedDevices = Get-MsGraphCollection -Uri $uri
    $comanagedDevices | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\ManagedDevices\"+(MakeFsCompatiblePath("comanagedDevices.json"))) -Force
    $GitReadyFiles += ("$DataRoot\ManagedDevices\"+(MakeFsCompatiblePath("comanagedDevices.json")))
} catch {
    Write-Warning "Could not export comanagedDevices"
    Write-Warning $_
}

try {
    #registeredDevices
    $uri = "/beta/devices"
    $registeredDevices = Get-MsGraphCollection -Uri $uri
    foreach($device in $registeredDevices)
    {
        $device | Add-Member -Name "registeredOwners" -Value @() -MemberType NoteProperty
        $uri = "/beta/devices/$($device.id)/registeredOwners"
        $registeredOwners = Get-MsGraphObject -Uri $uri
        $device.registeredOwners = $registeredOwners
        $device | Add-Member -Name "registeredUsers" -Value @() -MemberType NoteProperty
        $uri = "/beta/devices/$($device.id)/registeredUsers"
        $registeredUsers = Get-MsGraphObject -Uri $uri
        $device.registeredUsers = $registeredUsers
    }
    $registeredDevices | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\ManagedDevices\"+(MakeFsCompatiblePath("registeredDevices.json"))) -Force
    $GitReadyFiles += ("$DataRoot\ManagedDevices\"+(MakeFsCompatiblePath("registeredDevices.json")))
} catch {
    Write-Warning "Could not export registeredDevices"
    Write-Warning $_
}

try {
    #managedDeviceOverview
    $uri = "/beta/deviceManagement/managedDeviceOverview"
    $managedDeviceOverview = Get-MsGraphObject -Uri $uri
    $managedDeviceOverview | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\ManagedDevices\"+(MakeFsCompatiblePath("managedDeviceOverview.json"))) -Force
    $GitReadyFiles += ("$DataRoot\ManagedDevices\"+(MakeFsCompatiblePath("managedDeviceOverview.json")))
} catch {
    Write-Warning "Could not export managedDeviceOverview"
    Write-Warning $_
}

try {
    #healthStates
    $uri = "/beta/deviceAppManagement/windowsManagementApp/healthStates"
    $healthStates = Get-MsGraphObject -Uri $uri
    $healthStates | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\ManagedDevices\"+(MakeFsCompatiblePath("healthStates.json"))) -Force
    $GitReadyFiles += ("$DataRoot\ManagedDevices\"+(MakeFsCompatiblePath("healthStates.json")))
} catch {
    Write-Warning "Could not export healthStates"
    Write-Warning $_
}


##### Starting exports SoftwareUpdates
#####
Write-Host "Exporting SoftwareUpdates" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\SoftwareUpdates")) { $null = New-Item -Path "$DataRoot\SoftwareUpdates" -ItemType Directory -Force }

try {
    #softwareUpdatePoliciesWin
    $uri = "/beta/deviceManagement/deviceConfigurations?`$filter=isof('Microsoft.Graph.windowsUpdateForBusinessConfiguration')&`$expand=groupAssignments"
    $softwareUpdatePoliciesWin = Get-MsGraphObject -Uri $uri
    $softwareUpdatePoliciesWin | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\SoftwareUpdates\"+(MakeFsCompatiblePath("softwareUpdatePoliciesWin.json"))) -Force
    $GitReadyFiles += ("$DataRoot\SoftwareUpdates\"+(MakeFsCompatiblePath("softwareUpdatePoliciesWin.json")))
} catch {
    Write-Warning "Could not export softwareUpdatePoliciesWin"
    Write-Warning $_
}

try {
    #softwareUpdatePoliciesIos
    $uri = "/beta/deviceManagement/deviceConfigurations?`$filter=isof('Microsoft.Graph.iosUpdateConfiguration')&`$expand=groupAssignments"
    $softwareUpdatePoliciesIos = Get-MsGraphObject -Uri $uri
    $softwareUpdatePoliciesIos | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\SoftwareUpdates\"+(MakeFsCompatiblePath("softwareUpdatePoliciesIos.json"))) -Force
    $GitReadyFiles += ("$DataRoot\SoftwareUpdates\"+(MakeFsCompatiblePath("softwareUpdatePoliciesIos.json")))
} catch {
    Write-Warning "Could not export softwareUpdatePoliciesIos"
    Write-Warning $_
}


##### Starting exports FeatureUpdateProfiles
#####
Write-Host "Exporting FeatureUpdateProfiles" -ForegroundColor $CommandInfo

try {
    #windowsFeatureUpdateProfiles
    $uri = "/beta/deviceManagement/windowsFeatureUpdateProfiles"
    $windowsFeatureUpdateProfilesWin = Get-MsGraphObject -Uri $uri
    $windowsFeatureUpdateProfilesWin | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\SoftwareUpdates\"+(MakeFsCompatiblePath("windowsFeatureUpdateProfiles.json"))) -Force
    $GitReadyFiles += ("$DataRoot\SoftwareUpdates\"+(MakeFsCompatiblePath("windowsFeatureUpdateProfiles.json")))
} catch {
    Write-Warning "Could not export windowsFeatureUpdateProfiles"
    Write-Warning $_
}


##### Starting exports QualityUpdateProfiles
#####
Write-Host "Exporting QualityUpdateProfiles" -ForegroundColor $CommandInfo

try {
    #QualityUpdateProfiles
    $uri = "/beta/deviceManagement/windowsQualityUpdateProfiles"
    $windowsQualityUpdateProfilesWin = Get-MsGraphObject -Uri $uri
    $windowsQualityUpdateProfilesWin | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\SoftwareUpdates\"+(MakeFsCompatiblePath("windowsQualityUpdateProfiles.json"))) -Force
    $GitReadyFiles += ("$DataRoot\SoftwareUpdates\"+(MakeFsCompatiblePath("windowsQualityUpdateProfiles.json")))
} catch {
    Write-Warning "Could not export windowsQualityUpdateProfiles"
    Write-Warning $_
}


##### Starting exports DriverUpdateProfiles
#####
Write-Host "Exporting DriverUpdateProfiles" -ForegroundColor $CommandInfo

try {
    #DriverUpdateProfiles
    $uri = "/beta/deviceManagement/windowsDriverUpdateProfiles"
    $windowsDriverUpdateProfilesWin = Get-MsGraphObject -Uri $uri
    $windowsDriverUpdateProfilesWin | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\SoftwareUpdates\"+(MakeFsCompatiblePath("windowsDriverUpdateProfiles.json"))) -Force
    $GitReadyFiles += ("$DataRoot\SoftwareUpdates\"+(MakeFsCompatiblePath("windowsDriverUpdateProfiles.json")))
} catch {
    Write-Warning "Could not export DriverUpdateProfiles"
    Write-Warning $_
}


##### Starting exports TermsAndConditions
#####
Write-Host "Exporting TermsAndConditions" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\TermsAndConditions")) { $null = New-Item -Path "$DataRoot\TermsAndConditions" -ItemType Directory -Force }

try {
    #termsAndConditions
    $uri = "/beta/deviceManagement/termsAndConditions"
    $termsAndConditions = Get-MsGraphObject -Uri $uri
    $termsAndConditions | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\TermsAndConditions\"+(MakeFsCompatiblePath("termsAndConditions.json"))) -Force
    $GitReadyFiles += ("$DataRoot\TermsAndConditions\"+(MakeFsCompatiblePath("termsAndConditions.json")))
} catch {
    Write-Warning "Could not export termsAndConditions"
    Write-Warning $_
}

try {
    #termsAndConditionsAcceptanceStatuses
    foreach ($termsAndCondition in $termsAndConditions.value)
    {
        $uri = "/beta/deviceManagement/termsAndConditions/$($termsAndCondition.id)/acceptanceStatuses"
        $acceptanceStatuses = Get-MsGraphObject -Uri $uri
        $acceptanceStatuses | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\TermsAndConditions\"+(MakeFsCompatiblePath("termsAndConditionsAcceptanceStatuses_$($termsAndCondition.id).json"))) -Force
        $GitReadyFiles += ("$DataRoot\TermsAndConditions\"+(MakeFsCompatiblePath("termsAndConditionsAcceptanceStatuses_$($termsAndCondition.id).json")))
    }
} catch {
    Write-Warning "Could not export termsAndConditionsAcceptanceStatuses"
    Write-Warning $_
}


##### Starting exports IntuneDataExport
#####
Write-Host "Exporting IntuneDataExport" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\IntuneDataExport")) { $null = New-Item -Path "$DataRoot\IntuneDataExport" -ItemType Directory -Force }

try {
    $uri = "/beta/deviceAppManagement/mobileAppConfigurations"
    $mobileAppConfigurations = Get-MsGraphCollection -Uri $uri
} catch {
    Write-Warning "Could not export mobileAppConfigurations"
    Write-Warning $_
}
foreach($config in $mobileAppConfigurations)
{
    $config | Add-Member -Name "deviceStatuses" -Value @() -MemberType NoteProperty
    $config | Add-Member -Name "userStatuses" -Value @() -MemberType NoteProperty
    try {
        $uri = "/beta/deviceAppManagement/mobileAppConfigurations/$($config.id)/deviceStatuses"
        $deviceStatuses = Get-MsGraphObject -Uri $uri
        $config.deviceStatuses = $deviceStatuses
    } catch {
        Write-Warning "Could not export mobileAppConfigurations deviceStatuses"
        Write-Warning $_
    }
    try {
        $uri = "/beta/deviceAppManagement/mobileAppConfigurations/$($config.id)/userStatuses"
        $userStatuses = Get-MsGraphObject -Uri $uri
        $config.userStatuses = $userStatuses
    } catch {
        Write-Warning "Could not export mobileAppConfigurations userStatuses"
        Write-Warning $_
    }
}
try {
    $uri = "/beta/deviceManagement/deviceManagementScripts?`$expand=groupAssignments"
    $deviceManagementScripts = Get-MsGraphCollection -Uri $uri
} catch {
    Write-Warning "Could not export deviceManagementScripts"
    Write-Warning $_
}
foreach($script in $deviceManagementScripts)
{
    try {
        $script | Add-Member -Name "userRunStates" -Value @() -MemberType NoteProperty
        $uri = "/beta/deviceManagement/deviceManagementScripts/$($script.id)/userRunStates"
        $userRunStates = Get-MsGraphObject -Uri $uri
        $script.userRunStates = $userStatuses
    } catch {
        Write-Warning "Could not export deviceManagementScripts userRunStates"
        Write-Warning $_
    }
}
try {
    $uri = "/beta/deviceAppManagement/mobileApps"
    $intuneApplications = Get-MsGraphCollection -Uri $uri
} catch {
    Write-Warning "Could not export deviceAppManagement mobileApps"
    Write-Warning $_
}
if ($doUserDataExport)
{
    foreach ($user in $users)
    {
        $upn = $user.userPrincipalName
        Write-Host "Exporting user $upn"
        if (-Not (Test-Path "$DataRoot\IntuneDataExport\$upn")) { $null = New-Item -Path "$DataRoot\IntuneDataExport\$upn" -ItemType Directory -Force }
        $mobileAppConfigurationsForUser = $mobileAppConfigurations | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | ConvertFrom-Json
        $configs = $mobileAppConfigurationsForUser
        $deviceManagementScriptsForUser = $deviceManagementScripts | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | ConvertFrom-Json
        $scripts = $deviceManagementScriptsForUser
        $intuneApplicationsForUser = $intuneApplications | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | ConvertFrom-Json
        $applications = $intuneApplicationsForUser
        foreach($config in $configs)
        {
            if ($config.userStatuses)
            {
                $config.userStatuses = $config.userStatuses | Where-Object { $_.userPrincipalName -eq $upn}
            }
        }
        foreach($script in $scripts)
        {
            if ($script.userRunStates)
            {
                $script.userRunStates = $script.userRunStates | Where-Object { $_.userPrincipalName -eq $upn}
            }
        }
        foreach($application in $applications)
        {
            if ($application.userStatuses)
            {
                $application.userStatuses = $application.userStatuses | Where-Object { $_.userPrincipalName -eq $upn}
            }
        }
        try
        {
            #memberOf
            $uri = "/beta/users/$($user.id)/memberOf/Microsoft.Graph.group"
            $members = Get-MsGraphObject -Uri $uri
            $members | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("groups.json"))) -Force
            $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("groups.json")))
        } catch {
            Write-Warning "Could not export devicememberOf/Microsoft.Graph.group for user $upn"
            Write-Warning $_
        }
        try
        {
            #registeredDevices
            $uri = "/beta/users/$($user.id)/registeredDevices"
            $devices = Get-MsGraphObject -Uri $uri
            $devices | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("registered_devices.json"))) -Force
            $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("registered_devices.json")))
        } catch {
            Write-Warning "Could not export deviceregisteredDevices for user $upn"
            Write-Warning $_
        }
        try
        {
            #managedAppRegistrations
            $uri = "/beta/users/$($user.id)/managedAppRegistrations?`$expand=appliedPolicies,intendedPolicies,operations"
            $regs = Get-MsGraphObject -Uri $uri
            $regs | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("managedAppRegistrations.json"))) -Force
            $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("managedAppRegistrations.json")))
        } catch {
            Write-Warning "Could not export managedAppRegistrations for user $upn"
            Write-Warning $_
        }
        try
        {
            #managedAppStatuses
            $uri = "/beta/deviceAppManagement/managedAppStatuses('userstatus')?userId=$($user.id)"
            $managedAppStatuses = Get-MsGraphObject -Uri $uri
            $managedAppStatuses | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("managedAppStatuses_userstatus.json"))) -Force
            $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("managedAppStatuses_userstatus.json")))
        } catch {
            Write-Warning "Could not export managedAppStatuses userstatus for user $upn"
            Write-Warning $_
        }
        try
        {
            #managedAppStatuses
            $uri = "/beta/deviceAppManagement/managedAppStatuses('userconfigstatus')?userId=$($user.id)"
            $managedAppStatuses = Get-MsGraphObject -Uri $uri
            $managedAppStatuses | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("managedAppStatuses_userconfigstatus.json"))) -Force
            $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("managedAppStatuses_userconfigstatus.json")))
        } catch {
            Write-Warning "Could not export managedAppStatuses userconfigstatus for user $upn"
            Write-Warning $_
        }
        try
        {
            #deviceManagementTroubleshootingEvents
            $uri = "/beta/users/$($user.id)/deviceManagementTroubleshootingEvents"
            $deviceManagementTroubleshootingEvents = Get-MsGraphObject -Uri $uri
            $deviceManagementTroubleshootingEvents | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("deviceManagementTroubleshootingEvents.json"))) -Force
            $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("deviceManagementTroubleshootingEvents.json")))
        } catch {
            Write-Warning "Could not export deviceManagementTroubleshootingEvents for user $upn"
            Write-Warning $_
        }
        try
        {
            #termsAndConditionsAcceptanceStatuses
            $termsAndConditionsAcceptanceStatuses = @()
            foreach ($termsAndCondition in $termsAndConditions.value)
            {
                $uri = "/beta/deviceManagement/termsAndConditions/$($termsAndCondition.id)/acceptanceStatuses"
                $acceptanceStatuses = Get-MsGraphObject -Uri $uri
                $termsAndConditionsAcceptanceStatuses += ($acceptanceStatuses | Where-Object { $_.id.Contains($user.id) })
            }
            $termsAndConditionsAcceptanceStatuses | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("termsAndConditionsAcceptanceStatuses.json"))) -Force
            $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("termsAndConditionsAcceptanceStatuses.json")))
        } catch {
            Write-Warning "Could not export termsAndConditions acceptanceStatuses for user $upn"
            Write-Warning $_
        }
        try
        {
            #otherData
            $uri = "/beta/users/$($user.id)/exportDeviceAndAppManagementData()/content"
            $otherData = Get-MsGraphObject -Uri $uri -DontThrowIfStatusEquals 404
            $otherData | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("otherData.json"))) -Force
            $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("otherData.json")))
        } catch {
            Write-Warning "Could not export exportDeviceAndAppManagementData for user $upn"
            Write-Warning $_
        }
        try
        {
            #events
            #TODO
            #$uri = "/beta/deviceManagement/auditEvents?`$filter=actor/id eq '$($user.id)'"
            #$events = Get-MsGraphObject -Uri $uri
            #$events | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("events.json")) -Force
        } catch {
            Write-Warning "Could not export auditEvents for user $upn"
            Write-Warning $_
        }
        try
        {
            #iosUpdateStatuses
            $uri = "/beta/deviceManagement/iosUpdateStatuses"
            $iosUpdateStatuses = Get-MsGraphObject -Uri $uri | Where-Object { $_.userPrincipalName -ieq $upn }
            $iosUpdateStatuses | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("iosUpdateStatuses.json"))) -Force
            $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("iosUpdateStatuses.json")))
        } catch {
            Write-Warning "Could not export iosUpdateStatuses for user $upn"
            Write-Warning $_
        }
        try
        {
            #depOnboardingSettings
            $uri = "/beta/deviceManagement/depOnboardingSettings?`$filter=appleIdentifier eq '$([System.Web.HttpUtility]::UrlEncode($upn))'"
            $depOnboardingSettings = Get-MsGraphObject -Uri $uri
            $depOnboardingSettings | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("depOnboardingSettings.json"))) -Force
            $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("depOnboardingSettings.json")))
        } catch {
            Write-Warning "Could not export depOnboardingSettings for user $upn"
            Write-Warning $_
        }
        try
        {
            #remoteActionAudits
            $uri = "/beta/deviceManagement/remoteActionAudits?`$filter=initiatedByUserPrincipalName eq '$([System.Web.HttpUtility]::UrlEncode($upn))'"
            $remoteActionAudits = Get-MsGraphObject -Uri $uri
            $remoteActionAudits | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("remoteActionAudits.json"))) -Force
            $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("remoteActionAudits.json")))
        } catch {
            Write-Warning "Could not export remoteActionAudits for user $upn"
            Write-Warning $_
        }
        try
        {
            #managedDevices
            $devices = $null
            try
            {
                $uri = "/beta/users/$($user.id)/managedDevices"
                $devices = Get-MsGraphCollection -Uri $uri -DontThrowIfStatusEquals 404
                $devices | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("managed_devices.json"))) -Force
                $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("managed_devices.json")))
            } catch {
                Write-Warning "Could not export managedDevices for user $upn"
                Write-Warning $_
            }
            if ($devices -ne $null)
            {
                $devices = $devices
                foreach($config in $configs)
                {
                    $config | Add-Member -Name "deviceStatusesForDevice" -Value @() -MemberType NoteProperty
                }
                foreach($application in $applications)
                {
                    $application | Add-Member -Name "deviceStatusesForDevice" -Value @() -MemberType NoteProperty
                }
                foreach($device in $devices)
                {
                    try
                    {
                        Write-Host "  Device $($device.deviceName)"
                        foreach($config in $configs)
                        {
                            if ($config.deviceStatuses)
                            {
                                $config.deviceStatusesForDevice += $config.deviceStatuses | Where-Object { $_.id.Contains($device.id) }
                            }
                        }
                        foreach($application in $applications)
                        {
                            if ($application.deviceStatuses)
                            {
                                $application.deviceStatusesForDevice += $application.deviceStatuses | Where-Object { $_.id.Contains($device.id) }
                            }
                        }

                        $uri = "/beta/deviceManagement/managedDevices/$($device.Id)?`$expand=detectedApps"
                        $deviceData = Get-MsGraphObject -Uri $uri

                        $escapedDeviceName = $device.deviceName.Replace("'", "''")
                        $uri = "/beta/deviceAppManagement/windowsManagementApp/healthStates?`$filter=deviceName eq '$($escapedDeviceName)'"
                        $healthStates = Get-MsGraphObject -Uri $uri
                        Add-Member -InputObject $deviceData -MemberType NoteProperty -Name "healthStates" -Value $healthStates

                        $uri = "/beta/deviceManagement/managedDevices/$($device.Id)?`$expand=windowsProtectionState"
                        $windowsProtectionState = Get-MsGraphObject -Uri $uri
                        Add-Member -InputObject $deviceData -MemberType NoteProperty -Name "windowsProtectionState" -Value $windowsProtectionState

                        $uri = "/beta/deviceManagement/managedDevices/$($device.Id)/deviceCategory"
                        $deviceCategory = Get-MsGraphObject -Uri $uri
                        Add-Member -InputObject $deviceData -MemberType NoteProperty -Name "deviceCategory" -Value $deviceCategory

                        $uri = "/beta/deviceManagement/managedDevices/$($device.Id)/deviceConfigurationStates"
                        $deviceConfigurationStates = Get-MsGraphObject -Uri $uri
                        Add-Member -InputObject $deviceData -MemberType NoteProperty -Name "deviceConfigurationStates" -Value $deviceConfigurationStates
                        $states = $deviceData.deviceConfigurationStates
                        foreach($state in $states)
                        {
                            $uri = "/beta/deviceManagement/managedDevices/$($device.Id)/deviceConfigurationStates/$($state.id)/settingStates"
                            $settingStates = Get-MsGraphObject -Uri $uri
                            $state.settingStates = $settingStates
                        }

                        $uri = "/beta/deviceManagement/managedDevices/$($device.Id)/deviceCompliancePolicyStates"
                        $deviceCompliancePolicyStates = Get-MsGraphObject -Uri $uri
                        Add-Member -InputObject $deviceData -MemberType NoteProperty -Name "deviceCompliancePolicyStates" -Value $deviceCompliancePolicyStates
                        $states = $deviceData.deviceCompliancePolicyStates
                        foreach($state in $states)
                        {
                            $uri = "/beta/deviceManagement/managedDevices/$($device.Id)/deviceCompliancePolicyStates/$($state.id)/settingStates"
                            $settingStates = Get-MsGraphObject -Uri $uri
                            $state.settingStates = $settingStates
                        }

                        $uri = "/beta/deviceManagement/managedDevices/$($device.Id)?`$select=id,hardwareinformation,iccid,udid,ethernetMacAddress"
                        $deviceWithHardwareInfo = Get-MsGraphObject -Uri $uri
                        $deviceData.hardwareInformation = $deviceWithHardwareInfo

                        $deviceData | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("managedDevice_$($device.deviceName).json"))) -Force
                        $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("managedDevice_$($device.deviceName).json")))
                    } catch { 
					    try { Write-Host ($_.Exception | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 1) -ForegroundColor $CommandError } catch {}
					    try { Write-Host $_.Exception -ForegroundColor $CommandError } catch {}
				    }
                }
                foreach($config in $configs)
                {
                    $config.deviceStatuses = $config.deviceStatusesForDevice
                    $config.PSObject.Properties.Remove('deviceStatusesForDevice')
                }
                $mobileAppConfigurationsForUser | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("mobileAppConfigurations.json"))) -Force
                $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("mobileAppConfigurations.json")))
                foreach($application in $applications)
                {
                    $application.deviceStatuses = $application.deviceStatusesForDevice
                    $application.PSObject.Properties.Remove('deviceStatusesForDevice')
                }
                $intuneApplicationsForUser | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("intuneApplications.json"))) -Force
                $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("intuneApplications.json")))
                $deviceManagementScriptsForUser | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("deviceManagementScripts.json"))) -Force
                $GitReadyFiles += ("$DataRoot\IntuneDataExport\$($upn)\"+(MakeFsCompatiblePath("deviceManagementScripts.json")))
            }
	    } catch { 
		    try { Write-Host ($_.Exception | Sort-Object -Property "createdDateTime","displayName","name","id" | ConvertTo-Json -Depth 1) -ForegroundColor $CommandError } catch {}
		    try { Write-Host $_.Exception -ForegroundColor $CommandError } catch {}
	    }
    }
}

<#
if ((Test-Path "C:\AlyaExport"))
{
    cmd /c rmdir "C:\AlyaExport"
}
#>

# Make JSON git-ready if requested
if ($ExportGitFriendly -eq $true -and $GitReadyFiles.Count -gt 0)
{
    Write-Host "Making $($GitReadyFiles.Count) JSON file(s) git-ready" -ForegroundColor $CommandInfo
    Make-JsonGitReady -Path $GitReadyFiles
}

# Zipping export folder
if ($zipAllData -eq $true)
{
    Write-Host "Zipping export folder"
    Compress-Archive -Path $DataRoot\* -DestinationPath $IntuneRoot\Configuration.zip -CompressionLevel Optimal -Update
    Remove-Item -Path $DataRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# Stopping Transcript
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAy5+08advAVAHg
# z4l83kDG64hL8KxePPohPbUgukFx4qCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGju
# xOV7dX3H9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQT
# AxEACqVq4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f
# 46P2IukytvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdY
# TA3E3kMHBiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhD
# o6nZ2Iwj1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL
# 1yf/30OVyct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AH
# hviDcudo30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfd
# sbCXAJvYNCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx
# /j+7m9WSaK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cid
# mgdUVveoBPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgf
# tnoAWlVn8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vC
# oTANBgkqhkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQ
# ZpE364hOTSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTso
# VYpQr3IozYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yo
# DsPU9IHP/w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQ
# X6ibUXqjXk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNp
# HbGY6Eg0RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirM
# Jk0b9UF2hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnA
# mrVkGZj2a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj
# 3+nmvWbZfNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL
# /yMvbDOHhREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtH
# dwO39ACaudnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4Qh
# trofETAxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPHovpy/
# Qyl3UngL8fIpxfVGDTha7SADfRahoH1h2va8MA0GCSqGSIb3DQEBAQUABIICAD9D
# bnInl29RMwIRjsjI8cbNB12LPYRlsNx4kAZcvqaKm7rZex/RwgrpBtpGpWL0+uee
# S+SD08PLmExuPua9PSkn+IJIJsUETsQXfnZuKQx9wWHlWh2nOT8l6KE6M+Eu1pst
# 11rTIe150IMym1VSEUOCXwl2dFWRi9XoJXZflugo9t4eA7iK11Yr6OcAUwqPmYOf
# JxtKR+j2GJ8UBnid+J1m52HrGwg3K9Syy4bLZvL1oAjvs8OU9UDQlNqVr4iRaedU
# 7C/nBqw2rLg+Hq4CvlnI2Y1Ub42AKtVs9Ni+itBvU33NwPn5xjXJImx/b3YBxKKd
# r2xL4lXF/A6tBDGTcp1ZKFk+I7kqcxQ87MHbNaANpp9NQHBp/b1tX6heHfZ2PYGw
# SDza2CrS4NJbygLQI8srav4dixQKaloNLTjAZYy2fkbQnyc3DGAXdPi2XLnXBtdN
# sBIOeiNY5BLfWM1ubHicMmzBos0K3n28Hrg7kFhIZk4WCH6QDKGBwcr22iX/1PGE
# FjLhkK5fvNc6MDNijDb1BlfhcC1zyhBVTlsU5o4d8+lUMZVpK8EcgElAgQ72ptmN
# ilB8DOn3pBXfj34qQ0lc37e/M/Z+VxKwCfs/h5a315sCP8x0YPHAGwl610fS+CSg
# yselsvcGrmkSt4qgtPxppwf6+bFs4dhIzkGP8xnPoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCB4vV44DiwnVGc8PCWr4tVizAmVk2jObmahRkvUxuKBdgIUB5Mw
# rIFv61PGuOARYlaYhHHhqI8YDzIwMjYwODMxMTEwNDA5WjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
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
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDAbkAroB7YNUahqC6OvbvlMx0h41TpzRj94l0X9+o7KYFsGNlsjptxZfD/0
# yAh8z8YwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAnY9UAyz2839YqMkalkM+Qi9zpEc1P0+W0bH9I+MITHQi
# W/F3XnsXqFZ/86tGi4YLdJU443poptqlNNGKY2PN1v3V1VPkdtoAuskki2ePJb8G
# XtcqgCq7es3uaLZ0sdgW9DfHFt6Mw/S/gvpH9iFyN5Sbd7VrhUcGPb00tBbLqwkc
# ftpDt7GAfQLQYBymuTTkU5Q2koHEXiiAOYzzxrqjwQKfbmqZ+/wML65EIs5BRl1S
# 5MmHfrXzZA8an3Uwx14gT8S6rQUAA7hEvdfHfV3QtSKXC7qkXHjD9IE6mP8iUAeC
# 7np2txUEGgqos76wVBrauUOUOTsVe4rnLuO+ed0JoyRlN75AzMEBqHPVTEY9q1x9
# 6dV2tQ3nnBAqnVb0xddAFY0yBgcUA02K6AKTrt7RVA7JfJYvLj14tA4UdPP6WVYB
# JhT5sN730YzvP1CdmbF8MAAXVEd8vtvZoMTBPKrzkZGmXs4OGY/XS0ivX1Vavvt3
# VKwmT7IMsP2TNocksQKg
# SIG # End signature block
