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
    03.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [bool]$doUserDataExport = $false
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Export-IntuneConfiguration-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

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
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureADPreview"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-AD

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Export-IntuneConfiguration | Graph" -ForegroundColor $CommandInfo
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

##### Starting exports GeneralInformation
#####
Write-Host "Exporting GeneralInformation" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot")) { $tmp = New-Item -Path "$DataRoot" -ItemType Directory -Force }

#groups
$uri = "https://graph.microsoft.com/beta/groups"
$groups = Get-MsGraphObject -AccessToken $token -Uri $uri
while ($groups.'@odata.nextLink')
{
    $ngroups = Get-MsGraphObject -AccessToken $token -Uri $groups.'@odata.nextLink'
    $groups.value += $ngroups.value
    $groups.'@odata.nextLink' = $ngroups.'@odata.nextLink'
}
$groups | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\groups.json")) -Force

#users
$uri = "https://graph.microsoft.com/beta/users"
$users = Get-MsGraphObject -AccessToken $token -Uri $uri
while ($users.'@odata.nextLink')
{
    $nusers = Get-MsGraphObject -AccessToken $token -Uri $users.'@odata.nextLink'
    $users.value += $nusers.value
    $users.'@odata.nextLink' = $nusers.'@odata.nextLink'
}
$users | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\users.json")) -Force

#roles
$uri = "https://graph.microsoft.com/beta/directoryRoles"
$roles = Get-MsGraphObject -AccessToken $token -Uri $uri
while ($roles.'@odata.nextLink')
{
    $nroles = Get-MsGraphObject -AccessToken $token -Uri $roles.'@odata.nextLink'
    $roles.value += $nroles.value
    $roles.'@odata.nextLink' = $nroles.'@odata.nextLink'
}
$roles | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\directoryRoles.json")) -Force

#managedDeviceOverview
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDeviceOverview"
$managedDeviceOverview = Get-MsGraphObject -AccessToken $token -Uri $uri
$managedDeviceOverview | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\managedDeviceOverview.json")) -Force


##### Starting exports AndroidEnterprise
#####
Write-Host "Exporting AndroidEnterprise" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\AndroidEnterprise")) { $tmp = New-Item -Path "$DataRoot\AndroidEnterprise" -ItemType Directory -Force }

#deviceEnrollmentConfigurations
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations"
$deviceEnrollmentConfigurations = Get-MsGraphObject -AccessToken $token -Uri $uri
$deviceEnrollmentConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AndroidEnterprise\deviceEnrollmentConfigurations.json")) -Force
$androidEnterpriseConfig = $deviceEnrollmentConfigurations.value | ? { $_.androidForWorkRestriction.platformBlocked -eq $false } | Sort-Object priority
foreach($androidConfig in $androidEnterpriseConfig)
{
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$($androidConfig.id)/assignments"
    $assignments = Get-MsGraphObject -AccessToken $token -Uri $uri
    $assignments | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AndroidEnterprise\assignments_$($androidConfig.id).json")) -Force
}

#androidDeviceOwnerEnrollmentProfiles
$now = (Get-Date -Format s)    
$uri = "https://graph.microsoft.com/beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles?`$filter=tokenExpirationDateTime gt $($now)z"
$androidDeviceOwnerEnrollmentProfiles = Get-MsGraphObject -AccessToken $token -Uri $uri
$androidDeviceOwnerEnrollmentProfiles | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AndroidEnterprise\androidDeviceOwnerEnrollmentProfiles.json")) -Force
$profiles = $androidDeviceOwnerEnrollmentProfiles.value
foreach($profile in $profiles)
{
    $uri = "https://graph.microsoft.com/beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles/$($profile.id)?`$select=qrCodeImage"
    $qrCode = Get-MsGraphObject -AccessToken $token -Uri $uri
    $qrCode | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AndroidEnterprise\qrCode_$($profile.id).json")) -Force
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

#androidManagedStoreAccountEnterpriseSettings
$uri = "https://graph.microsoft.com/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings"
$androidManagedStoreAccountEnterpriseSettings = Get-MsGraphObject -AccessToken $token -Uri $uri
$androidManagedStoreAccountEnterpriseSettings | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AndroidEnterprise\androidManagedStoreAccountEnterpriseSettings.json")) -Force


##### Starting exports AppConfigurationPolicy
#####
Write-Host "Exporting AppConfigurationPolicy" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\AppConfigurationPolicy")) { $tmp = New-Item -Path "$DataRoot\AppConfigurationPolicy" -ItemType Directory -Force }

#targetedManagedAppConfigurations
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations?`$expand=apps"
$targetedManagedAppConfigurations = Get-MsGraphObject -AccessToken $token -Uri $uri
$targetedManagedAppConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppConfigurationPolicy\targetedManagedAppConfigurations.json")) -Force

#mobileAppConfigurations
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations"
$mobileAppConfigurations = Get-MsGraphObject -AccessToken $token -Uri $uri
$mobileAppConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppConfigurationPolicy\mobileAppConfigurations.json")) -Force
$configs = $mobileAppConfigurations.value
foreach($config in $configs)
{
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations/$($config.id)/deviceStatuses"
    $deviceStatuses = Get-MsGraphObject -AccessToken $token -Uri $uri
    $deviceStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppConfigurationPolicy\mobileAppConfiguration_deviceStatuses_$($config.id).json")) -Force
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations/$($config.id)/userStatuses"
    $userStatuses = Get-MsGraphObject -AccessToken $token -Uri $uri
    $userStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppConfigurationPolicy\mobileAppConfiguration_userStatuses_$($config.id).json")) -Force
}


##### Starting exports AppleEnrollment
#####
Write-Host "Exporting AppleEnrollment" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\AppleEnrollment")) { $tmp = New-Item -Path "$DataRoot\AppleEnrollment" -ItemType Directory -Force }

#applePushNotificationCertificateapplePushNotificationCertificate
$uri = "https://graph.microsoft.com/beta/devicemanagement/applePushNotificationCertificate"
$applePushNotificationCertificate = Get-MsGraphObject -AccessToken $token -Uri $uri
$applePushNotificationCertificate | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppleEnrollment\applePushNotificationCertificate.json")) -Force

#depOnboardingSettings
$uri = "https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings"
$depOnboardingSettings = Get-MsGraphObject -AccessToken $token -Uri $uri
$depOnboardingSettings | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppleEnrollment\depOnboardingSettings.json")) -Force
$profiles = $depOnboardingSettings.value
foreach($profile in $profiles)
{
    $uri = "https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings/$($profile.id)/enrollmentProfiles"
    $enrollmentProfile = Get-MsGraphObject -AccessToken $token -Uri $uri
    $enrollmentProfile | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppleEnrollment\enrollmentProfile_$($profile.id).json")) -Force
}

#managedEbooks
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/managedEbooks"
$managedEbooks = Get-MsGraphObject -AccessToken $token -Uri $uri
$managedEbooks | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppleEnrollment\managedEbooks.json")) -Force

#iosLobAppProvisioningConfigurations
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosLobAppProvisioningConfigurations?`$expand=assignments"
$iosLobAppProvisioningConfigurations = Get-MsGraphObject -AccessToken $token -Uri $uri
$iosLobAppProvisioningConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppleEnrollment\iosLobAppProvisioningConfigurations.json")) -Force


##### Starting exports Auditing
#####
Write-Host "Exporting Auditing" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\Auditing")) { $tmp = New-Item -Path "$DataRoot\Auditing" -ItemType Directory -Force }

#auditCategories
$uri = "https://graph.microsoft.com/beta/deviceManagement/auditEvents/getAuditCategories"
$auditCategories = Get-MsGraphObject -AccessToken $token -Uri $uri
$auditCategories | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Auditing\auditCategories.json")) -Force

#auditEvents
#TODO
#$daysago = "{0:s}" -f (get-date).AddDays(-30) + "Z"
#$uri = "https://graph.microsoft.com/beta/deviceManagement/auditEvents?`$filter=activityDateTime gt $daysago"
#$auditEvents = Get-MsGraphObject -AccessToken $token -Uri $uri
#$auditEvents | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Auditing\auditEvents.json")) -Force

#remoteActionAudits
$uri = "https://graph.microsoft.com/beta/deviceManagement/remoteActionAudits"
$remoteActionAudits = Get-MsGraphObject -AccessToken $token -Uri $uri
$remoteActionAudits | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Auditing\remoteActionAudits.json")) -Force

#iosUpdateStatuses
$uri = "https://graph.microsoft.com/beta/deviceManagement/iosUpdateStatuses"
$iosUpdateStatuses = Get-MsGraphObject -AccessToken $token -Uri $uri
$iosUpdateStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Auditing\iosUpdateStatuses.json")) -Force


##### Starting exports CertificationAuthority
#####
Write-Host "Exporting CertificationAuthority" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\CertificationAuthority")) { $tmp = New-Item -Path "$DataRoot\CertificationAuthority" -ItemType Directory -Force }

#ndesconnectors
$uri = "https://graph.microsoft.com/beta/deviceManagement/ndesconnectors"
$ndesconnectors = Get-MsGraphObject -AccessToken $token -Uri $uri
$ndesconnectors | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\CertificationAuthority\ndesconnectors.json")) -Force


##### Starting exports CompanyPortalBranding
#####
Write-Host "Exporting CompanyPortalBranding" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\CompanyPortalBranding")) { $tmp = New-Item -Path "$DataRoot\CompanyPortalBranding" -ItemType Directory -Force }

#intuneBrand
$uri = "https://graph.microsoft.com/beta/deviceManagement/intuneBrand"
$intuneBrand = Get-MsGraphObject -AccessToken $token -Uri $uri
$intuneBrand | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\CompanyPortalBranding\intuneBrand.json")) -Force

#intuneBrandingProfiles
$uri = "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles"
$intuneBrandingProfiles = Get-MsGraphObject -AccessToken $token -Uri $uri
$intuneBrandingProfiles | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\CompanyPortalBranding\intuneBrandingProfiles.json")) -Force


##### Starting exports CompliancePolicy
#####
Write-Host "Exporting CompliancePolicy" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\CompliancePolicy")) { $tmp = New-Item -Path "$DataRoot\CompliancePolicy" -ItemType Directory -Force }

#deviceCompliancePolicies
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
$deviceCompliancePolicies = Get-MsGraphObject -AccessToken $token -Uri $uri
$deviceCompliancePolicies | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\CompliancePolicy\deviceCompliancePolicies.json")) -Force
$policies = $deviceCompliancePolicies.value
foreach($policy in $policies)
{
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($policy.id)/assignments"
    $assignments = Get-MsGraphObject -AccessToken $token -Uri $uri
    $assignments | ConvertTo-Json | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\CompliancePolicy\deviceCompliancePolicy_assignment_$($policy.id).json")) -Force
}


##### Starting exports CorporateDeviceEnrollment
#####
Write-Host "Exporting CorporateDeviceEnrollment" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\CorporateDeviceEnrollment")) { $tmp = New-Item -Path "$DataRoot\CorporateDeviceEnrollment" -ItemType Directory -Force }

#importedDeviceIdentities
$uri = "https://graph.microsoft.com/beta/deviceManagement/importedDeviceIdentities"
$importedDeviceIdentities = Get-MsGraphObject -AccessToken $token -Uri $uri
$importedDeviceIdentities | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\CorporateDeviceEnrollment\importedDeviceIdentities.json")) -Force


##### Starting exports DeviceConfiguration
#####
Write-Host "Exporting DeviceConfiguration" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\DeviceConfiguration")) { $tmp = New-Item -Path "$DataRoot\DeviceConfiguration" -ItemType Directory -Force }

#deviceConfigurations
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
$deviceConfigurations = Get-MsGraphObject -AccessToken $token -Uri $uri
$deviceConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\DeviceConfiguration\deviceConfigurations.json")) -Force
$policies = $deviceConfigurations.value
foreach($policy in $policies)
{
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($policy.id)/groupAssignments"
    $assignments = Get-MsGraphObject -AccessToken $token -Uri $uri
    $assignments | ConvertTo-Json | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\DeviceConfiguration\deviceConfiguration_assignment_$($policy.id).json")) -Force
}

#deviceManagementScripts
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$expand=groupAssignments"
$deviceManagementScripts = Get-MsGraphObject -AccessToken $token -Uri $uri
$deviceManagementScripts | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\DeviceConfiguration\deviceManagementScripts.json")) -Force
$scripts = $deviceManagementScripts.value
foreach($script in $scripts)
{
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($script.id)"
    $scriptContent = Get-MsGraphObject -AccessToken $token -Uri $uri
    $fileName = $scriptContent.fileName
    $scriptContent = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($scriptContent.scriptContent))
    $scriptContent | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\DeviceConfiguration\$($fileName)")) -Force
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($script.id)/userRunStates"
    $userRunStates = Get-MsGraphObject -AccessToken $token -Uri $uri
    $userRunStates | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\DeviceConfiguration\userRunStates_$($script.id).json")) -Force
}


##### Starting exports EnrollmentRestrictions
#####
Write-Host "Exporting EnrollmentRestrictions" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\EnrollmentRestrictions")) { $tmp = New-Item -Path "$DataRoot\EnrollmentRestrictions" -ItemType Directory -Force }

#deviceEnrollmentConfigurations
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations"
$deviceEnrollmentConfigurations = Get-MsGraphObject -AccessToken $token -Uri $uri
$deviceEnrollmentConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\EnrollmentRestrictions\deviceEnrollmentConfigurations.json")) -Force


##### Starting exports Applications
#####
Write-Host "Exporting Applications" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\Applications")) { $tmp = New-Item -Path "$DataRoot\Applications" -ItemType Directory -Force }

#mobileAppCategories
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppCategories"
$mobileAppCategories = Get-MsGraphObject -AccessToken $token -Uri $uri
$mobileAppCategories | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\mobileAppCategories.json")) -Force

#intuneApplications
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
$intuneApplications = Get-MsGraphObject -AccessToken $token -Uri $uri
$intuneApplications | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplications.json")) -Force
$applications = $intuneApplications.value
if (-Not (Test-Path "$DataRoot\Applications\Data")) { $tmp = New-Item -Path "$DataRoot\Applications\Data" -ItemType Directory -Force }
foreach($application in $applications)
{
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($application.id)"
    $application = Get-MsGraphObject -AccessToken $token -Uri $uri
    $application | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_application.json")) -Force
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($application.id)/assignments"
    $applicationAssignments = Get-MsGraphObject -AccessToken $token -Uri $uri
    $applicationAssignments | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_applicationAssignments.json")) -Force
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($application.id)/installSummary"
    $installSummary = Get-MsGraphObject -AccessToken $token -Uri $uri
    $installSummary | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_installSummary.json")) -Force
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($application.id)/deviceStatuses"
    $deviceStatuses = Get-MsGraphObject -AccessToken $token -Uri $uri
    $deviceStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_deviceStatuses.json")) -Force
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($application.id)/userStatuses"
    $userStatuses = Get-MsGraphObject -AccessToken $token -Uri $uri
    $userStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_userStatuses.json")) -Force
}
$intuneApplications.value | where { ($_.'@odata.type').Contains("managed") } | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsMAM.json")) -Force
$intuneApplications.value | where { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) } | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsMDMfull.json")) -Force
$intuneApplications.value | where { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) -and (!($_.'@odata.type').Contains("#microsoft.graph.windowsAppX")) -and (!($_.'@odata.type').Contains("#microsoft.graph.androidForWorkApp")) -and (!($_.'@odata.type').Contains("#microsoft.graph.windowsMobileMSI")) -and (!($_.'@odata.type').Contains("#microsoft.graph.androidLobApp")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosLobApp")) -and (!($_.'@odata.type').Contains("#microsoft.graph.microsoftStoreForBusinessApp")) } | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsMDM.json")) -Force
$intuneApplications.value | where { ($_.'@odata.type').Contains("win32") } | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsWIN32.json")) -Force
$intuneApplications.value | where { ($_.'@odata.type').Contains("managedAndroidStoreApp") } | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsAndroid.json")) -Force
$intuneApplications.value | where { ($_.'@odata.type').Contains("managedIOSStoreApp") } | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsIos.json")) -Force

#mobileAppConfigurations
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations?`$expand=assignments"
$mobileAppConfigurations = Get-MsGraphObject -AccessToken $token -Uri $uri
$mobileAppConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\mobileAppConfigurations.json")) -Force

#targetedManagedAppConfigurations
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations"
$targetedManagedAppConfigurations = Get-MsGraphObject -AccessToken $token -Uri $uri
$targetedManagedAppConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\targetedManagedAppConfigurations.json")) -Force
$configurations = $targetedManagedAppConfigurations.value
foreach($configuration in $configurations)
{
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations('$($configuration.id)')?`$expand=apps,assignments"
    $configuration = Get-MsGraphObject -AccessToken $token -Uri $uri
    $configuration | ConvertTo-Json | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\targetedManagedAppConfiguration_$($configuration.id).json")) -Force
}

#appregistrationSummary
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppStatuses('appregistrationsummary')?fetch=6000&policyMode=0&columns=DisplayName,UserEmail,ApplicationName,ApplicationInstanceId,ApplicationVersion,DeviceName,DeviceType,DeviceManufacturer,DeviceModel,AndroidPatchVersion,AzureADDeviceId,MDMDeviceID,Platform,PlatformVersion,ManagementLevel,PolicyName,LastCheckInDate"
$appregistrationSummary = Get-MsGraphObject -AccessToken $token -Uri $uri
$appregistrationSummary | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\appregistrationSummary.json")) -Force

#windowsProtectionReport
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppStatuses('windowsprotectionreport')"
$windowsProtectionReport = Get-MsGraphObject -AccessToken $token -Uri $uri
$windowsProtectionReport | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\windowsProtectionReport.json")) -Force

#mdmWindowsInformationProtectionPolicies
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies"
$mdmWindowsInformationProtectionPolicies = Get-MsGraphObject -AccessToken $token -Uri $uri
$mdmWindowsInformationProtectionPolicies | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\mdmWindowsInformationProtectionPolicies.json")) -Force

#managedAppPolicies
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies"
$managedAppPolicies = Get-MsGraphObject -AccessToken $token -Uri $uri
$managedAppPolicies | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicies.json")) -Force
$policies = $managedAppPolicies.value
foreach($policy in $policies)
{
    $policy = $policies[0]
    try {
        #TODO
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policy.id)')?`$expand=apps"
        $policy = Get-MsGraphObject -AccessToken $token -Uri $uri
        $policy | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_android.json")) -Force
    } catch {}
    try {
        #TODO
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policy.id)')?`$expand=apps"
        $policy = Get-MsGraphObject -AccessToken $token -Uri $uri
        $policy | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_ios.json")) -Force
    } catch {}
    try {
        #TODO
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies('$($policy.id)')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
        $policy = Get-MsGraphObject -AccessToken $token -Uri $uri
        $policy | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_windows.json")) -Force
    } catch {}
    try {
        #TODO
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies('$($policy.id)')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
        $policy = Get-MsGraphObject -AccessToken $token -Uri $uri
        $policy | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_mdm.json")) -Force
    } catch {}
}


##### Starting exports ManagedDevices
#####
Write-Host "Exporting ManagedDevices" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\ManagedDevices")) { $tmp = New-Item -Path "$DataRoot\ManagedDevices" -ItemType Directory -Force }

#managedDevices
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
$managedDevices = Get-MsGraphObject -AccessToken $token -Uri $uri
while ($managedDevices.'@odata.nextLink')
{
    $nmanagedDevices = Get-MsGraphObject -AccessToken $token -Uri $managedDevices.'@odata.nextLink'
    $managedDevices.value += $nmanagedDevices.value
    $managedDevices.'@odata.nextLink' = $nmanagedDevices.'@odata.nextLink'
}
$devices = $managedDevices.value
foreach($device in $devices)
{
    $device | Add-Member -Name "managedDeviceUser" -Value @() -MemberType NoteProperty
    $uri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$($device.id)')?`$select=userId"
    $managedDeviceUser = Get-MsGraphObject -AccessToken $token -Uri $uri
    $device.managedDeviceUser = $managedDeviceUser
    $uri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$($device.id)')?`$select=hardwareinformation,iccid,udid,ethernetMacAddress"
    $hardwareinformation = Get-MsGraphObject -AccessToken $token -Uri $uri
    $device.hardwareinformation = $hardwareinformation
    $device | Add-Member -Name "primaryUsers" -Value @() -MemberType NoteProperty
    $uri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$($device.id)')/users"
    $primaryUsers = Get-MsGraphObject -AccessToken $token -Uri $uri
    $device.primaryUsers = $primaryUsers
    $device | Add-Member -Name "detectedApps" -Value @() -MemberType NoteProperty
    $uri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$($device.id)')?`$expand=detectedApps"
    $detectedApps = Get-MsGraphObject -AccessToken $token -Uri $uri
    $device.detectedApps = $detectedApps
}
$managedDevices | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\ManagedDevices\managedDevices.json")) -Force

#registeredDevices
$uri = "https://graph.microsoft.com/beta/devices"
$registeredDevices = Get-MsGraphObject -AccessToken $token -Uri $uri
while ($registeredDevices.'@odata.nextLink')
{
    $nregisteredDevices = Get-MsGraphObject -AccessToken $token -Uri $registeredDevices.'@odata.nextLink'
    $registeredDevices.value += $nregisteredDevices.value
    $registeredDevices.'@odata.nextLink' = $nregisteredDevices.'@odata.nextLink'
}
$devices = $registeredDevices.value
foreach($device in $devices)
{
    $device | Add-Member -Name "registeredOwners" -Value @() -MemberType NoteProperty
    $uri = "https://graph.microsoft.com/beta/devices/$($device.id)/registeredOwners"
    $registeredOwners = Get-MsGraphObject -AccessToken $token -Uri $uri
    $device.registeredOwners = $registeredOwners
    $device | Add-Member -Name "registeredUsers" -Value @() -MemberType NoteProperty
    $uri = "https://graph.microsoft.com/beta/devices/$($device.id)/registeredUsers"
    $registeredUsers = Get-MsGraphObject -AccessToken $token -Uri $uri
    $device.registeredUsers = $registeredUsers
}
$registeredDevices | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\ManagedDevices\registeredDevices.json")) -Force

#managedDeviceOverview
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDeviceOverview"
$managedDeviceOverview = Get-MsGraphObject -AccessToken $token -Uri $uri
$managedDeviceOverview | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\ManagedDevices\managedDeviceOverview.json")) -Force

#healthStates
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagementApp/healthStates"
$healthStates = Get-MsGraphObject -AccessToken $token -Uri $uri
$healthStates | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\ManagedDevices\healthStates.json")) -Force


##### Starting exports SoftwareUpdates
#####
Write-Host "Exporting SoftwareUpdates" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\SoftwareUpdates")) { $tmp = New-Item -Path "$DataRoot\SoftwareUpdates" -ItemType Directory -Force }

#softwareUpdatePoliciesWin
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&`$expand=groupAssignments"
$softwareUpdatePoliciesWin = Get-MsGraphObject -AccessToken $token -Uri $uri
$softwareUpdatePoliciesWin | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\SoftwareUpdates\softwareUpdatePoliciesWin.json")) -Force

#softwareUpdatePoliciesIos
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.iosUpdateConfiguration')&`$expand=groupAssignments"
$softwareUpdatePoliciesIos = Get-MsGraphObject -AccessToken $token -Uri $uri
$softwareUpdatePoliciesIos | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\SoftwareUpdates\softwareUpdatePoliciesIos.json")) -Force


##### Starting exports FeatureUpdateProfiles
#####
Write-Host "Exporting FeatureUpdateProfiles" -ForegroundColor $CommandInfo

#windowsFeatureUpdateProfiles
$uri = "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles"
$windowsFeatureUpdateProfilesWin = Get-MsGraphObject -AccessToken $token -Uri $uri
$windowsFeatureUpdateProfilesWin | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\SoftwareUpdates\windowsFeatureUpdateProfiles.json")) -Force


##### Starting exports QualityUpdateProfiles
#####
Write-Host "Exporting QualityUpdateProfiles" -ForegroundColor $CommandInfo

#windowsFeatureUpdateProfiles
$uri = "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles"
$windowsQualityUpdateProfilesWin = Get-MsGraphObject -AccessToken $token -Uri $uri
$windowsQualityUpdateProfilesWin | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\SoftwareUpdates\windowsQualityUpdateProfiles.json")) -Force


##### Starting exports TermsAndConditions
#####
Write-Host "Exporting TermsAndConditions" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\TermsAndConditions")) { $tmp = New-Item -Path "$DataRoot\TermsAndConditions" -ItemType Directory -Force }

#softwareUpdatePoliciesWin
$uri = "https://graph.microsoft.com/beta/deviceManagement/termsAndConditions"
$termsAndConditions = Get-MsGraphObject -AccessToken $token -Uri $uri
$termsAndConditions | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\TermsAndConditions\termsAndConditions.json")) -Force


##### Starting exports IntuneDataExport
#####
Write-Host "Exporting IntuneDataExport" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\IntuneDataExport")) { $tmp = New-Item -Path "$DataRoot\IntuneDataExport" -ItemType Directory -Force }

$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations"
$mobileAppConfigurations = Get-MsGraphObject -AccessToken $token -Uri $uri
$configs = $mobileAppConfigurations.value
foreach($config in $configs)
{
    $config | Add-Member -Name "deviceStatuses" -Value @() -MemberType NoteProperty
    $config | Add-Member -Name "userStatuses" -Value @() -MemberType NoteProperty
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations/$($config.id)/deviceStatuses"
    $deviceStatuses = Get-MsGraphCollection -AccessToken $token -Uri $uri
    $config.deviceStatuses = $deviceStatuses
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations/$($config.id)/userStatuses"
    $userStatuses = Get-MsGraphCollection -AccessToken $token -Uri $uri
    $config.userStatuses = $userStatuses
}
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$expand=groupAssignments"
$deviceManagementScripts = Get-MsGraphObject -AccessToken $token -Uri $uri
$scripts = $deviceManagementScripts.value
foreach($script in $scripts)
{
    $script | Add-Member -Name "userRunStates" -Value @() -MemberType NoteProperty
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($script.id)/userRunStates"
    $userRunStates = Get-MsGraphCollection -AccessToken $token -Uri $uri
    $script.userRunStates = $userStatuses
}
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
$intuneApplications = Get-MsGraphObject -AccessToken $token -Uri $uri
$applications = $intuneApplications.value
foreach($application in $applications)
{
    $application | Add-Member -Name "deviceStatuses" -Value @() -MemberType NoteProperty
    $application | Add-Member -Name "userStatuses" -Value @() -MemberType NoteProperty
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($application.id)/deviceStatuses"
    $deviceStatuses = Get-MsGraphCollection -AccessToken $token -Uri $uri
    $application.deviceStatuses = $deviceStatuses
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($application.id)/userStatuses"
    $userStatuses = Get-MsGraphCollection -AccessToken $token -Uri $uri
    $application.userStatuses = $userStatuses
}
if ($doUserDataExport)
{
    foreach ($user in $users.value)
    {
        $upn = $user.userPrincipalName
        Write-Host "Exporting user $upn"
        $token = Get-AdalAccessToken
        if (-Not (Test-Path "$DataRoot\IntuneDataExport\$upn")) { $tmp = New-Item -Path "$DataRoot\IntuneDataExport\$upn" -ItemType Directory -Force }
        $mobileAppConfigurationsForUser = $mobileAppConfigurations | ConvertTo-Json -Depth 50 | ConvertFrom-Json
        $configs = $mobileAppConfigurationsForUser.value
        $deviceManagementScriptsForUser = $deviceManagementScripts | ConvertTo-Json -Depth 50 | ConvertFrom-Json
        $scripts = $deviceManagementScriptsForUser.value
        $intuneApplicationsForUser = $intuneApplications | ConvertTo-Json -Depth 50 | ConvertFrom-Json
        $applications = $intuneApplicationsForUser.value
        foreach($config in $configs)
        {
            if ($config.userStatuses)
            {
                $config.userStatuses = $config.userStatuses | where { $_.userPrincipalName -eq $upn}
            }
        }
        foreach($script in $scripts)
        {
            if ($script.userRunStates)
            {
                $script.userRunStates = $script.userRunStates | where { $_.userPrincipalName -eq $upn}
            }
        }
        foreach($application in $applications)
        {
            if ($application.userStatuses)
            {
                $application.userStatuses = $application.userStatuses | where { $_.userPrincipalName -eq $upn}
            }
        }
        try
        {
            #memberOf
            $uri = "https://graph.microsoft.com/beta/users/$($user.id)/memberOf/microsoft.graph.group"
            $members = Get-MsGraphObject -AccessToken $token -Uri $uri
            $members | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\groups.json")) -Force
        } catch {}
        try
        {
            #registeredDevices
            $uri = "https://graph.microsoft.com/beta/users/$($user.id)/registeredDevices"
            $devices = Get-MsGraphObject -AccessToken $token -Uri $uri
            $devices | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\registered_devices.json")) -Force
        } catch {}
        try
        {
            #managedAppRegistrations
            $uri = "https://graph.microsoft.com/beta/users/$($user.id)/managedAppRegistrations?`$expand=appliedPolicies,intendedPolicies,operations"
            $regs = Get-MsGraphObject -AccessToken $token -Uri $uri
            $regs | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\managedAppRegistrations.json")) -Force
        } catch { }
        try
        {
            #managedAppStatuses
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppStatuses('userstatus')?userId=$($user.id)"
            $managedAppStatuses = Get-MsGraphObject -AccessToken $token -Uri $uri
            $managedAppStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\managedAppStatuses_userstatus.json")) -Force
        } catch { }
        try
        {
            #managedAppStatuses
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppStatuses('userconfigstatus')?userId=$($user.id)"
            $managedAppStatuses = Get-MsGraphObject -AccessToken $token -Uri $uri
            $managedAppStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\managedAppStatuses_userconfigstatus.json")) -Force
        } catch { }
        try
        {
            #deviceManagementTroubleshootingEvents
            $uri = "https://graph.microsoft.com/beta/users/$($user.id)/deviceManagementTroubleshootingEvents"
            $deviceManagementTroubleshootingEvents = Get-MsGraphObject -AccessToken $token -Uri $uri
            $deviceManagementTroubleshootingEvents | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\deviceManagementTroubleshootingEvents.json")) -Force
        } catch { }
        try
        {
            #termsAndConditionsAcceptanceStatuses
            $uri = "https://graph.microsoft.com/beta/deviceManagement/termsAndConditions"
            $termsAndConditions = Get-MsGraphCollection -AccessToken $token -Uri $uri
            $termsAndConditionsAcceptanceStatuses = @()
            foreach ($termsAndCondition in $termsAndConditions)
            {
                $uri = "https://graph.microsoft.com/beta/deviceManagement/termsAndConditions/$($termsAndCondition.id)/acceptanceStatuses"
                $acceptanceStatuses = Get-MsGraphCollection -AccessToken $token -Uri $uri
                $termsAndConditionsAcceptanceStatuses += ($acceptanceStatuses | Where-Object { $_.id.Contains($user.id) })
            }
            $termsAndConditionsAcceptanceStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\termsAndConditionsAcceptanceStatuses.json")) -Force
        } catch { }
        try
        {
            #otherData
            $uri = "https://graph.microsoft.com/beta/users/$($user.id)/exportDeviceAndAppManagementData()/content"
            $otherData = Get-MsGraphObject -AccessToken $token -Uri $uri -DontThrowIfStatusEquals 404
            $otherData | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\otherData.json")) -Force
        } catch { }
        try
        {
            #events
            #TODO
            #$uri = "https://graph.microsoft.com/beta/deviceManagement/auditEvents?`$filter=actor/id eq '$($user.id)'"
            #$events = Get-MsGraphObject -AccessToken $token -Uri $uri
            #$events | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\events.json")) -Force
        } catch { }
        try
        {
            #iosUpdateStatuses
            $uri = "https://graph.microsoft.com/beta/deviceManagement/iosUpdateStatuses"
            $iosUpdateStatuses = Get-MsGraphObject -AccessToken $token -Uri $uri | where { $_.userPrincipalName -ieq $upn }
            $iosUpdateStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\iosUpdateStatuses.json")) -Force
        } catch { }
        try
        {
            #depOnboardingSettings
            $uri = "https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings?`$filter=appleIdentifier eq '$([System.Web.HttpUtility]::UrlEncode($upn))'"
            $depOnboardingSettings = Get-MsGraphObject -AccessToken $token -Uri $uri
            $depOnboardingSettings | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\depOnboardingSettings.json")) -Force
        } catch { }
        try
        {
            #remoteActionAudits
            $uri = "https://graph.microsoft.com/beta/deviceManagement/remoteActionAudits?`$filter=initiatedByUserPrincipalName eq '$([System.Web.HttpUtility]::UrlEncode($upn))'"
            $remoteActionAudits = Get-MsGraphObject -AccessToken $token -Uri $uri
            $remoteActionAudits | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\remoteActionAudits.json")) -Force
        } catch { }
        try
        {
            #managedDevices
            $devices = $null
            try
            {
                $uri = "https://graph.microsoft.com/beta/users/$($user.id)/managedDevices"
                $devices = Get-MsGraphObject -AccessToken $token -Uri $uri -DontThrowIfStatusEquals 404
                $devices | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\managed_devices.json")) -Force
            } catch { }
            if ($devices -ne $null)
            {
                $devices = $devices.value
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
                                $config.deviceStatusesForDevice += $config.deviceStatuses | where { $_.id.Contains($device.id) }
                            }
                        }
                        foreach($application in $applications)
                        {
                            if ($application.deviceStatuses)
                            {
                                $application.deviceStatusesForDevice += $application.deviceStatuses | where { $_.id.Contains($device.id) }
                            }
                        }

                        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.Id)?`$expand=detectedApps"
                        $deviceData = Get-MsGraphObject -AccessToken $token -Uri $uri

                        $escapedDeviceName = $device.deviceName.Replace("'", "''")
                        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagementApp/healthStates?`$filter=deviceName eq '$($escapedDeviceName)'"
                        $healthStates = Get-MsGraphObject -AccessToken $token -Uri $uri
                        Add-Member -InputObject $deviceData -MemberType NoteProperty -Name "healthStates" -Value $healthStates

                        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.Id)?`$expand=windowsProtectionState"
                        $windowsProtectionState = Get-MsGraphObject -AccessToken $token -Uri $uri
                        Add-Member -InputObject $deviceData -MemberType NoteProperty -Name "windowsProtectionState" -Value $windowsProtectionState

                        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.Id)/deviceCategory"
                        $deviceCategory = Get-MsGraphObject -AccessToken $token -Uri $uri
                        Add-Member -InputObject $deviceData -MemberType NoteProperty -Name "deviceCategory" -Value $deviceCategory

                        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.Id)/deviceConfigurationStates"
                        $deviceConfigurationStates = Get-MsGraphCollection -AccessToken $token -Uri $uri
                        Add-Member -InputObject $deviceData -MemberType NoteProperty -Name "deviceConfigurationStates" -Value $deviceConfigurationStates
                        $states = $deviceData.deviceConfigurationStates
                        foreach($state in $states)
                        {
                            $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.Id)/deviceConfigurationStates/$($state.id)/settingStates"
                            $settingStates = Get-MsGraphCollection -AccessToken $token -Uri $uri
                            $state.settingStates = $settingStates
                        }

                        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.Id)/deviceCompliancePolicyStates"
                        $deviceCompliancePolicyStates = Get-MsGraphCollection -AccessToken $token -Uri $uri
                        Add-Member -InputObject $deviceData -MemberType NoteProperty -Name "deviceCompliancePolicyStates" -Value $deviceCompliancePolicyStates
                        $states = $deviceData.deviceCompliancePolicyStates
                        foreach($state in $states)
                        {
                            $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.Id)/deviceCompliancePolicyStates/$($state.id)/settingStates"
                            $settingStates = Get-MsGraphCollection -AccessToken $token -Uri $uri
                            $state.settingStates = $settingStates
                        }

                        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.Id)?`$select=id,hardwareinformation,iccid,udid,ethernetMacAddress"
                        $deviceWithHardwareInfo = Get-MsGraphObject -AccessToken $token -Uri $uri
                        $deviceData.hardwareInformation = $deviceWithHardwareInfo

                        $deviceData | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\managedDevice_$($device.deviceName).json")) -Force
                    } catch { 
					    try { Write-Host ($_.Exception | ConvertTo-Json -Depth 3) -ForegroundColor $CommandError } catch {}
					    try { Write-Host $_.Exception -ForegroundColor $CommandError } catch {}
				    }
                }
                foreach($config in $configs)
                {
                    $config.deviceStatuses = $config.deviceStatusesForDevice
                    $config.PSObject.Properties.Remove('deviceStatusesForDevice')
                }
                $mobileAppConfigurationsForUser | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\mobileAppConfigurations.json")) -Force
                foreach($application in $applications)
                {
                    $application.deviceStatuses = $application.deviceStatusesForDevice
                    $application.PSObject.Properties.Remove('deviceStatusesForDevice')
                }
                $intuneApplicationsForUser | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\intuneApplications.json")) -Force
                $deviceManagementScriptsForUser | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\deviceManagementScripts.json")) -Force
            }
	    } catch { 
		    try { Write-Host ($_.Exception | ConvertTo-Json -Depth 2) -ForegroundColor $CommandError } catch {}
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

#Stopping Transscript
Stop-Transcript