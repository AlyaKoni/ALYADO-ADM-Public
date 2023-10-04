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
    03.09.2020 Konrad Brunner       Initial Version
    23.11.2021 Konrad Brunner       Group policies
    24.04.2023 Konrad Brunner       Switched to Graph

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
    while ($rep.status -eq "inProgress" || $rep.status -eq "notStarted")
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

#groups
$uri = "/beta/groups"
$groups = Get-MsGraphCollection -Uri $uri
$groups | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\groups.json")) -Force

#users
$uri = "/beta/users"
$users = Get-MsGraphCollection -Uri $uri
$users | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\users.json")) -Force

#roles
$uri = "/beta/directoryRoles"
$roles = Get-MsGraphCollection -Uri $uri
$roles | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\directoryRoles.json")) -Force

#managedDeviceOverview
$uri = "/beta/deviceManagement/managedDeviceOverview"
$managedDeviceOverview = Get-MsGraphCollection -Uri $uri
$managedDeviceOverview | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\managedDeviceOverview.json")) -Force


##### Starting exports AndroidEnterprise
#####
Write-Host "Exporting AndroidEnterprise" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\AndroidEnterprise")) { $null = New-Item -Path "$DataRoot\AndroidEnterprise" -ItemType Directory -Force }

#deviceEnrollmentConfigurations
$uri = "/beta/deviceManagement/deviceEnrollmentConfigurations"
$deviceEnrollmentConfigurations = Get-MsGraphCollection -Uri $uri
$deviceEnrollmentConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AndroidEnterprise\deviceEnrollmentConfigurations.json")) -Force
$androidEnterpriseConfig = $deviceEnrollmentConfigurations | ? { $_.androidForWorkRestriction.platformBlocked -eq $false } | Sort-Object priority
foreach($androidConfig in $androidEnterpriseConfig)
{
    $uri = "/beta/deviceManagement/deviceEnrollmentConfigurations/$($androidConfig.id)/assignments"
    $assignments = Get-MsGraphObject -Uri $uri
    $assignments | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AndroidEnterprise\assignments_$($androidConfig.id).json")) -Force
}

#androidDeviceOwnerEnrollmentProfiles
$now = (Get-Date -Format s)
$uri = "/beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles?`$filter=tokenExpirationDateTime gt $($now)z"
$androidDeviceOwnerEnrollmentProfiles = Get-MsGraphCollection -Uri $uri
$androidDeviceOwnerEnrollmentProfiles | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AndroidEnterprise\androidDeviceOwnerEnrollmentProfiles.json")) -Force
$profiles = $androidDeviceOwnerEnrollmentProfiles
foreach($profile in $profiles)
{
    $uri = "/beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles/$($profile.id)?`$select=qrCodeImage"
    $qrCode = Get-MsGraphObject -Uri $uri
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
$uri = "/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings"
$androidManagedStoreAccountEnterpriseSettings = Get-MsGraphObject -Uri $uri
$androidManagedStoreAccountEnterpriseSettings | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AndroidEnterprise\androidManagedStoreAccountEnterpriseSettings.json")) -Force


##### Starting exports AppConfigurationPolicy
#####
Write-Host "Exporting AppConfigurationPolicy" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\AppConfigurationPolicy")) { $null = New-Item -Path "$DataRoot\AppConfigurationPolicy" -ItemType Directory -Force }

#targetedManagedAppConfigurations
$uri = "/beta/deviceAppManagement/targetedManagedAppConfigurations?`$expand=apps"
$targetedManagedAppConfigurations = Get-MsGraphObject -Uri $uri
$targetedManagedAppConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppConfigurationPolicy\targetedManagedAppConfigurations.json")) -Force

#mobileAppConfigurations
$uri = "/beta/deviceAppManagement/mobileAppConfigurations"
$mobileAppConfigurations = Get-MsGraphCollection -Uri $uri
$mobileAppConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppConfigurationPolicy\mobileAppConfigurations.json")) -Force
foreach($config in $mobileAppConfigurations)
{
    $uri = "/beta/deviceAppManagement/mobileAppConfigurations/$($config.id)/deviceStatuses"
    $deviceStatuses = Get-MsGraphObject -Uri $uri
    $deviceStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppConfigurationPolicy\mobileAppConfiguration_deviceStatuses_$($config.id).json")) -Force
    $uri = "/beta/deviceAppManagement/mobileAppConfigurations/$($config.id)/userStatuses"
    $userStatuses = Get-MsGraphObject -Uri $uri
    $userStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppConfigurationPolicy\mobileAppConfiguration_userStatuses_$($config.id).json")) -Force
}


##### Starting exports AppleEnrollment
#####
Write-Host "Exporting AppleEnrollment" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\AppleEnrollment")) { $null = New-Item -Path "$DataRoot\AppleEnrollment" -ItemType Directory -Force }

#applePushNotificationCertificateapplePushNotificationCertificate
#TODO $uri = "/beta/devicemanagement/applePushNotificationCertificate"
#TODO $applePushNotificationCertificate = Get-MsGraphObject -Uri $uri
#TODO $applePushNotificationCertificate | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppleEnrollment\applePushNotificationCertificate.json")) -Force

#depOnboardingSettings
$uri = "/beta/deviceManagement/depOnboardingSettings"
$depOnboardingSettings = Get-MsGraphCollection -Uri $uri
$depOnboardingSettings | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppleEnrollment\depOnboardingSettings.json")) -Force
foreach($profile in $depOnboardingSettings)
{
    $uri = "/beta/deviceManagement/depOnboardingSettings/$($profile.id)/enrollmentProfiles"
    $enrollmentProfile = Get-MsGraphObject -Uri $uri
    $enrollmentProfile | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppleEnrollment\enrollmentProfile_$($profile.id).json")) -Force
}

#managedEbooks
$uri = "/beta/deviceAppManagement/managedEbooks"
$managedEbooks = Get-MsGraphObject -Uri $uri
$managedEbooks | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppleEnrollment\managedEbooks.json")) -Force

#iosLobAppProvisioningConfigurations
$uri = "/beta/deviceAppManagement/iosLobAppProvisioningConfigurations?`$expand=assignments"
$iosLobAppProvisioningConfigurations = Get-MsGraphObject -Uri $uri
$iosLobAppProvisioningConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\AppleEnrollment\iosLobAppProvisioningConfigurations.json")) -Force


##### Starting exports Auditing
#####
Write-Host "Exporting Auditing" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\Auditing")) { $null = New-Item -Path "$DataRoot\Auditing" -ItemType Directory -Force }

#auditCategories
$uri = "/beta/deviceManagement/auditEvents/getAuditCategories"
$auditCategories = Get-MsGraphObject -Uri $uri
$auditCategories | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Auditing\auditCategories.json")) -Force

#auditEvents
#TODO
#$daysago = "{0:s}" -f (get-date).AddDays(-30) + "Z"
#$uri = "/beta/deviceManagement/auditEvents?`$filter=activityDateTime gt $daysago"
#$auditEvents = Get-MsGraphObject -Uri $uri
#$auditEvents | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Auditing\auditEvents.json")) -Force

#remoteActionAudits
$uri = "/beta/deviceManagement/remoteActionAudits"
$remoteActionAudits = Get-MsGraphObject -Uri $uri
$remoteActionAudits | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Auditing\remoteActionAudits.json")) -Force

#iosUpdateStatuses
$uri = "/beta/deviceManagement/iosUpdateStatuses"
$iosUpdateStatuses = Get-MsGraphObject -Uri $uri
$iosUpdateStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Auditing\iosUpdateStatuses.json")) -Force


##### Starting exports CertificationAuthority
#####
Write-Host "Exporting CertificationAuthority" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\CertificationAuthority")) { $null = New-Item -Path "$DataRoot\CertificationAuthority" -ItemType Directory -Force }

#ndesconnectors
$uri = "/beta/deviceManagement/ndesconnectors"
$ndesconnectors = Get-MsGraphObject -Uri $uri
$ndesconnectors | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\CertificationAuthority\ndesconnectors.json")) -Force


##### Starting exports CompanyPortalBranding
#####
Write-Host "Exporting CompanyPortalBranding" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\CompanyPortalBranding")) { $null = New-Item -Path "$DataRoot\CompanyPortalBranding" -ItemType Directory -Force }

#intuneBrand
$uri = "/beta/deviceManagement/intuneBrand"
$intuneBrand = Get-MsGraphObject -Uri $uri
$intuneBrand | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\CompanyPortalBranding\intuneBrand.json")) -Force

#intuneBrandingProfiles
$uri = "/beta/deviceManagement/intuneBrandingProfiles"
$intuneBrandingProfiles = Get-MsGraphObject -Uri $uri
$intuneBrandingProfiles | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\CompanyPortalBranding\intuneBrandingProfiles.json")) -Force


##### Starting exports CompliancePolicy
#####
Write-Host "Exporting CompliancePolicy" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\CompliancePolicy")) { $null = New-Item -Path "$DataRoot\CompliancePolicy" -ItemType Directory -Force }

#deviceCompliancePolicies
$uri = "/beta/deviceManagement/deviceCompliancePolicies"
$deviceCompliancePolicies = Get-MsGraphCollection -Uri $uri
$deviceCompliancePolicies | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\CompliancePolicy\deviceCompliancePolicies.json")) -Force
foreach($policy in $deviceCompliancePolicies)
{
    $uri = "/beta/deviceManagement/deviceCompliancePolicies/$($policy.id)/assignments"
    $assignments = Get-MsGraphObject -Uri $uri
    $assignments | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\CompliancePolicy\deviceCompliancePolicy_assignment_$($policy.id).json")) -Force
}


##### Starting exports CorporateDeviceEnrollment
#####
Write-Host "Exporting CorporateDeviceEnrollment" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\CorporateDeviceEnrollment")) { $null = New-Item -Path "$DataRoot\CorporateDeviceEnrollment" -ItemType Directory -Force }

#importedDeviceIdentities
$uri = "/beta/deviceManagement/importedDeviceIdentities"
$importedDeviceIdentities = Get-MsGraphObject -Uri $uri
$importedDeviceIdentities | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\CorporateDeviceEnrollment\importedDeviceIdentities.json")) -Force


##### Starting exports GroupPolicyConfiguration
#####
Write-Host "Exporting GroupPolicyConfiguration" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\GroupPolicyConfiguration")) { $null = New-Item -Path "$DataRoot\GroupPolicyConfiguration" -ItemType Directory -Force }

#groupPolicyDefinitions
$uri = "/beta/deviceManagement/groupPolicyDefinitions"
$groupPolicyDefinitions = Get-MsGraphObject -Uri $uri
$groupPolicyDefinitions | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\GroupPolicyConfiguration\groupPolicyDefinitions.json")) -Force

#groupPolicyCategories
$uri = "/beta/deviceManagement/groupPolicyCategories"
$groupPolicyCategories = Get-MsGraphObject -Uri $uri
$groupPolicyCategories | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\GroupPolicyConfiguration\groupPolicyCategories.json")) -Force

#groupPolicyUploadedDefinitionFiles
$uri = "/beta/deviceManagement/groupPolicyUploadedDefinitionFiles"
$groupPolicyUploadedDefinitionFiles = Get-MsGraphObject -Uri $uri
$groupPolicyUploadedDefinitionFiles | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\GroupPolicyConfiguration\groupPolicyUploadedDefinitionFiles.json")) -Force

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
$groupPolicyConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\GroupPolicyConfiguration\groupPolicyConfigurations.json")) -Force


##### Starting exports DeviceConfiguration
#####
Write-Host "Exporting DeviceConfiguration" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\DeviceConfiguration")) { $null = New-Item -Path "$DataRoot\DeviceConfiguration" -ItemType Directory -Force }

#deviceConfigurations
$uri = "/beta/deviceManagement/deviceConfigurations"
$deviceConfigurations = Get-MsGraphCollection -Uri $uri
$deviceConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\DeviceConfiguration\deviceConfigurations.json")) -Force
foreach($policy in $deviceConfigurations)
{
    $uri = "/beta/deviceManagement/deviceConfigurations/$($policy.id)/groupAssignments"
    $assignments = Get-MsGraphObject -Uri $uri
    $assignments | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\DeviceConfiguration\deviceConfiguration_assignment_$($policy.id).json")) -Force
}

#deviceManagementScripts
$uri = "/beta/deviceManagement/deviceManagementScripts?`$expand=groupAssignments"
$deviceManagementScripts = Get-MsGraphCollection -Uri $uri
$deviceManagementScripts | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\DeviceConfiguration\deviceManagementScripts.json")) -Force
foreach($script in $deviceManagementScripts)
{
    $uri = "/beta/deviceManagement/deviceManagementScripts/$($script.id)"
    $scriptContent = Get-MsGraphObject -Uri $uri
    $fileName = $scriptContent.fileName
    $scriptContent = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($scriptContent.scriptContent))
    $scriptContent | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\DeviceConfiguration\$($fileName)")) -Force
    $uri = "/beta/deviceManagement/deviceManagementScripts/$($script.id)/userRunStates"
    $userRunStates = Get-MsGraphObject -Uri $uri
    $userRunStates | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\DeviceConfiguration\userRunStates_$($script.id).json")) -Force
}


##### Starting exports EnrollmentRestrictions
#####
Write-Host "Exporting EnrollmentRestrictions" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\EnrollmentRestrictions")) { $null = New-Item -Path "$DataRoot\EnrollmentRestrictions" -ItemType Directory -Force }

#deviceEnrollmentConfigurations
$uri = "/beta/deviceManagement/deviceEnrollmentConfigurations"
$deviceEnrollmentConfigurations = Get-MsGraphObject -Uri $uri
$deviceEnrollmentConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\EnrollmentRestrictions\deviceEnrollmentConfigurations.json")) -Force


##### Starting exports Applications
#####
Write-Host "Exporting Applications" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\Applications")) { $null = New-Item -Path "$DataRoot\Applications" -ItemType Directory -Force }

#mobileAppCategories
$uri = "/beta/deviceAppManagement/mobileAppCategories"
$mobileAppCategories = Get-MsGraphObject -Uri $uri
$mobileAppCategories | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\mobileAppCategories.json")) -Force

#intuneApplications
$uri = "/beta/deviceAppManagement/mobileApps"
$intuneApplications = Get-MsGraphCollection -Uri $uri
$intuneApplications | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplications.json")) -Force
if (-Not (Test-Path "$DataRoot\Applications\Data")) { $null = New-Item -Path "$DataRoot\Applications\Data" -ItemType Directory -Force }
$DeviceInstallStatusByAppUris = @()
$UserInstallStatusAggregateByAppUris = @()
foreach($application in $intuneApplications)
{
    $uri = "/beta/deviceAppManagement/mobileApps/$($application.id)"
    $application = Get-MsGraphObject -Uri $uri
    $application | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_application.json")) -Force

    $uri = "/beta/deviceAppManagement/mobileApps/$($application.id)/assignments"
    $applicationAssignments = Get-MsGraphObject -Uri $uri
    if ($applicationAssignments -and $applicationAssignments.value.Count -gt 0)
    {
        $applicationAssignments | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_applicationAssignments.json")) -Force
        $uri = GetReportUri -reportname "DeviceInstallStatusByApp" -filter "ApplicationId eq '$($application.id)'"
        $DeviceInstallStatusByAppUris += @{app=$application.id;uri=$uri}
        $uri = GetReportUri -reportname "UserInstallStatusAggregateByApp" -filter "ApplicationId eq '$($application.id)'"
        $UserInstallStatusAggregateByAppUris += @{app=$application.id;uri=$uri}
    }
    
    <#
    $uri = "/beta/deviceManagement/reports/getAppStatusOverviewReport"
    $getAppStatusOverviewReport = Post-MsGraph -Uri $uri -Body "{`"filter`":`"(ApplicationId eq '$($application.id)')`"}" -OutputFile (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_appStatusOverviewReport.json"))
    
    $uri = "/beta/deviceManagement/reports/getAppsInstallSummaryReport"
    $getAppStatusOverviewReport = Post-MsGraph -Uri $uri -Body "{`"filter`":`"(ApplicationId eq '$($application.id)')`"}" -OutputFile (MakeFsCompatiblePath("$DataRoot\Applications\Data\app_$($application.id)_appsInstallSummaryReport.json"))
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

$intuneApplications | Where-Object { ($_.'@odata.type').Contains("managed") } | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsMAM.json")) -Force
$mdmApps | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsMDMfull.json")) -Force
$intuneApplications | Where-Object { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.winGetApp")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.iosVppApp")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.windowsAppX")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.androidForWorkApp")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.windowsMobileMSI")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.androidLobApp")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.iosLobApp")) -and (!($_.'@odata.type').Contains("#Microsoft.Graph.microsoftStoreForBusinessApp")) } | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsMDM.json")) -Force
$intuneApplications | Where-Object { ($_.'@odata.type').Contains("win32") } | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsWIN32.json")) -Force
$intuneApplications | Where-Object { ($_.'@odata.type').Contains("winGetApp") } | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsWinGet.json")) -Force
$intuneApplications | Where-Object { ($_.'@odata.type').Contains("managedAndroidStoreApp") } | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsAndroid.json")) -Force
$intuneApplications | Where-Object { ($_.'@odata.type').Contains("managedIOSStoreApp") } | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\intuneApplicationsIos.json")) -Force

#mobileAppConfigurations
$uri = "/beta/deviceAppManagement/mobileAppConfigurations?`$expand=assignments"
$mobileAppConfigurations = Get-MsGraphObject -Uri $uri
$mobileAppConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\mobileAppConfigurations.json")) -Force

#targetedManagedAppConfigurations
$uri = "/beta/deviceAppManagement/targetedManagedAppConfigurations"
$targetedManagedAppConfigurations = Get-MsGraphCollection -Uri $uri
$targetedManagedAppConfigurations | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\targetedManagedAppConfigurations.json")) -Force
foreach($configuration in $targetedManagedAppConfigurations)
{
    $uri = "/beta/deviceAppManagement/targetedManagedAppConfigurations('$($configuration.id)')?`$expand=apps,assignments"
    $configuration = Get-MsGraphObject -Uri $uri
    $configuration | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\targetedManagedAppConfiguration_$($configuration.id).json")) -Force
}

#appregistrationSummary
$uri = "/beta/deviceAppManagement/managedAppStatuses('appregistrationsummary')?fetch=6000&policyMode=0&columns=DisplayName,UserEmail,ApplicationName,ApplicationInstanceId,ApplicationVersion,DeviceName,DeviceType,DeviceManufacturer,DeviceModel,AndroidPatchVersion,AzureADDeviceId,MDMDeviceID,Platform,PlatformVersion,ManagementLevel,PolicyName,LastCheckInDate"
$appregistrationSummary = Get-MsGraphObject -Uri $uri
$appregistrationSummary | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\appregistrationSummary.json")) -Force

#windowsProtectionReport
$uri = "/beta/deviceAppManagement/managedAppStatuses('windowsprotectionreport')"
$windowsProtectionReport = Get-MsGraphObject -Uri $uri
$windowsProtectionReport | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\windowsProtectionReport.json")) -Force

#mdmWindowsInformationProtectionPolicies
$uri = "/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies"
$mdmWindowsInformationProtectionPolicies = Get-MsGraphObject -Uri $uri
$mdmWindowsInformationProtectionPolicies | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\mdmWindowsInformationProtectionPolicies.json")) -Force

#managedAppPolicies
$uri = "/beta/deviceAppManagement/managedAppPolicies"
$managedAppPolicies = Get-MsGraphCollection -Uri $uri
$managedAppPolicies | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicies.json")) -Force
foreach($managedAppPolicy in $managedAppPolicies)
{
    try {
        #TODO
        $uri = "/beta/deviceAppManagement/androidManagedAppProtections('$($managedAppPolicy.id)')?`$expand=apps"
        $policy = Get-MsGraphObject -Uri $uri
        $policy | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_android.json")) -Force
    } catch {}
    try {
        #TODO
        $uri = "/beta/deviceAppManagement/iosManagedAppProtections('$($managedAppPolicy.id)')?`$expand=apps"
        $policy = Get-MsGraphObject -Uri $uri
        $policy | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_ios.json")) -Force
    } catch {}
    try {
        #TODO
        $uri = "/beta/deviceAppManagement/windowsInformationProtectionPolicies('$($managedAppPolicy.id)')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
        $policy = Get-MsGraphObject -Uri $uri
        $policy | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_windows.json")) -Force
    } catch {}
    try {
        #TODO
        $uri = "/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies('$($managedAppPolicy.id)')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
        $policy = Get-MsGraphObject -Uri $uri
        $policy | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\Applications\managedAppPolicy_$($policy.id)_mdm.json")) -Force
    } catch {}
}

##### Starting exports Reports
#####
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

#TODO
#$DeviceRunStatesByProactiveRemediationUri = GetReportUri -reportname "DeviceRunStatesByProactiveRemediation"
#$DevicesByAppInvUri = GetReportUri -reportname "DevicesByAppInv"
#$AppInvByDeviceUri = GetReportUri -reportname "AppInvByDevice"

##### Starting exports ManagedDevices
#####
Write-Host "Exporting ManagedDevices" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\ManagedDevices")) { $null = New-Item -Path "$DataRoot\ManagedDevices" -ItemType Directory -Force }

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
$managedDevices | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\ManagedDevices\managedDevices.json")) -Force

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
$registeredDevices | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\ManagedDevices\registeredDevices.json")) -Force

#managedDeviceOverview
$uri = "/beta/deviceManagement/managedDeviceOverview"
$managedDeviceOverview = Get-MsGraphObject -Uri $uri
$managedDeviceOverview | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\ManagedDevices\managedDeviceOverview.json")) -Force

#healthStates
$uri = "/beta/deviceAppManagement/windowsManagementApp/healthStates"
$healthStates = Get-MsGraphObject -Uri $uri
$healthStates | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\ManagedDevices\healthStates.json")) -Force


##### Starting exports SoftwareUpdates
#####
Write-Host "Exporting SoftwareUpdates" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\SoftwareUpdates")) { $null = New-Item -Path "$DataRoot\SoftwareUpdates" -ItemType Directory -Force }

#softwareUpdatePoliciesWin
$uri = "/beta/deviceManagement/deviceConfigurations?`$filter=isof('Microsoft.Graph.windowsUpdateForBusinessConfiguration')&`$expand=groupAssignments"
$softwareUpdatePoliciesWin = Get-MsGraphObject -Uri $uri
$softwareUpdatePoliciesWin | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\SoftwareUpdates\softwareUpdatePoliciesWin.json")) -Force

#softwareUpdatePoliciesIos
$uri = "/beta/deviceManagement/deviceConfigurations?`$filter=isof('Microsoft.Graph.iosUpdateConfiguration')&`$expand=groupAssignments"
$softwareUpdatePoliciesIos = Get-MsGraphObject -Uri $uri
$softwareUpdatePoliciesIos | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\SoftwareUpdates\softwareUpdatePoliciesIos.json")) -Force


##### Starting exports FeatureUpdateProfiles
#####
Write-Host "Exporting FeatureUpdateProfiles" -ForegroundColor $CommandInfo

#windowsFeatureUpdateProfiles
$uri = "/beta/deviceManagement/windowsFeatureUpdateProfiles"
$windowsFeatureUpdateProfilesWin = Get-MsGraphObject -Uri $uri
$windowsFeatureUpdateProfilesWin | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\SoftwareUpdates\windowsFeatureUpdateProfiles.json")) -Force


##### Starting exports QualityUpdateProfiles
#####
Write-Host "Exporting QualityUpdateProfiles" -ForegroundColor $CommandInfo

#QualityUpdateProfiles
$uri = "/beta/deviceManagement/windowsQualityUpdateProfiles"
$windowsQualityUpdateProfilesWin = Get-MsGraphObject -Uri $uri
$windowsQualityUpdateProfilesWin | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\SoftwareUpdates\windowsQualityUpdateProfiles.json")) -Force

##### Starting exports DriverUpdateProfiles
#####
Write-Host "Exporting DriverUpdateProfiles" -ForegroundColor $CommandInfo

#DriverUpdateProfiles
$uri = "/beta/deviceManagement/windowsDriverUpdateProfiles"
$windowsDriverUpdateProfilesWin = Get-MsGraphObject -Uri $uri
$windowsDriverUpdateProfilesWin | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\SoftwareUpdates\windowsDriverUpdateProfiles.json")) -Force

##### Starting exports TermsAndConditions
#####
Write-Host "Exporting TermsAndConditions" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\TermsAndConditions")) { $null = New-Item -Path "$DataRoot\TermsAndConditions" -ItemType Directory -Force }

#termsAndConditions
$uri = "/beta/deviceManagement/termsAndConditions"
$termsAndConditions = Get-MsGraphObject -Uri $uri
$termsAndConditions | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\TermsAndConditions\termsAndConditions.json")) -Force


#termsAndConditionsAcceptanceStatuses
foreach ($termsAndCondition in $termsAndConditions.value)
{
    $uri = "/beta/deviceManagement/termsAndConditions/$($termsAndCondition.id)/acceptanceStatuses"
    $acceptanceStatuses = Get-MsGraphObject -Uri $uri
    $acceptanceStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\TermsAndConditions\termsAndConditionsAcceptanceStatuses_$($termsAndCondition.id).json")) -Force
}


##### Starting exports IntuneDataExport
#####
Write-Host "Exporting IntuneDataExport" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$DataRoot\IntuneDataExport")) { $null = New-Item -Path "$DataRoot\IntuneDataExport" -ItemType Directory -Force }

$uri = "/beta/deviceAppManagement/mobileAppConfigurations"
$mobileAppConfigurations = Get-MsGraphCollection -Uri $uri
foreach($config in $mobileAppConfigurations)
{
    $config | Add-Member -Name "deviceStatuses" -Value @() -MemberType NoteProperty
    $config | Add-Member -Name "userStatuses" -Value @() -MemberType NoteProperty
    $uri = "/beta/deviceAppManagement/mobileAppConfigurations/$($config.id)/deviceStatuses"
    $deviceStatuses = Get-MsGraphObject -Uri $uri
    $config.deviceStatuses = $deviceStatuses
    $uri = "/beta/deviceAppManagement/mobileAppConfigurations/$($config.id)/userStatuses"
    $userStatuses = Get-MsGraphObject -Uri $uri
    $config.userStatuses = $userStatuses
}
$uri = "/beta/deviceManagement/deviceManagementScripts?`$expand=groupAssignments"
$deviceManagementScripts = Get-MsGraphCollection -Uri $uri
foreach($script in $deviceManagementScripts)
{
    $script | Add-Member -Name "userRunStates" -Value @() -MemberType NoteProperty
    $uri = "/beta/deviceManagement/deviceManagementScripts/$($script.id)/userRunStates"
    $userRunStates = Get-MsGraphObject -Uri $uri
    $script.userRunStates = $userStatuses
}
$uri = "/beta/deviceAppManagement/mobileApps"
$intuneApplications = Get-MsGraphCollection -Uri $uri
if ($doUserDataExport)
{
    foreach ($user in $users)
    {
        $upn = $user.userPrincipalName
        Write-Host "Exporting user $upn"
        if (-Not (Test-Path "$DataRoot\IntuneDataExport\$upn")) { $null = New-Item -Path "$DataRoot\IntuneDataExport\$upn" -ItemType Directory -Force }
        $mobileAppConfigurationsForUser = $mobileAppConfigurations | ConvertTo-Json -Depth 50 | ConvertFrom-Json
        $configs = $mobileAppConfigurationsForUser
        $deviceManagementScriptsForUser = $deviceManagementScripts | ConvertTo-Json -Depth 50 | ConvertFrom-Json
        $scripts = $deviceManagementScriptsForUser
        $intuneApplicationsForUser = $intuneApplications | ConvertTo-Json -Depth 50 | ConvertFrom-Json
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
            $members | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\groups.json")) -Force
        } catch {}
        try
        {
            #registeredDevices
            $uri = "/beta/users/$($user.id)/registeredDevices"
            $devices = Get-MsGraphObject -Uri $uri
            $devices | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\registered_devices.json")) -Force
        } catch {}
        try
        {
            #managedAppRegistrations
            $uri = "/beta/users/$($user.id)/managedAppRegistrations?`$expand=appliedPolicies,intendedPolicies,operations"
            $regs = Get-MsGraphObject -Uri $uri
            $regs | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\managedAppRegistrations.json")) -Force
        } catch { }
        try
        {
            #managedAppStatuses
            $uri = "/beta/deviceAppManagement/managedAppStatuses('userstatus')?userId=$($user.id)"
            $managedAppStatuses = Get-MsGraphObject -Uri $uri
            $managedAppStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\managedAppStatuses_userstatus.json")) -Force
        } catch { }
        try
        {
            #managedAppStatuses
            $uri = "/beta/deviceAppManagement/managedAppStatuses('userconfigstatus')?userId=$($user.id)"
            $managedAppStatuses = Get-MsGraphObject -Uri $uri
            $managedAppStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\managedAppStatuses_userconfigstatus.json")) -Force
        } catch { }
        try
        {
            #deviceManagementTroubleshootingEvents
            $uri = "/beta/users/$($user.id)/deviceManagementTroubleshootingEvents"
            $deviceManagementTroubleshootingEvents = Get-MsGraphObject -Uri $uri
            $deviceManagementTroubleshootingEvents | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\deviceManagementTroubleshootingEvents.json")) -Force
        } catch { }
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
            $termsAndConditionsAcceptanceStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\termsAndConditionsAcceptanceStatuses.json")) -Force
        } catch { }
        try
        {
            #otherData
            $uri = "/beta/users/$($user.id)/exportDeviceAndAppManagementData()/content"
            $otherData = Get-MsGraphObject -Uri $uri -DontThrowIfStatusEquals 404
            $otherData | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\otherData.json")) -Force
        } catch { }
        try
        {
            #events
            #TODO
            #$uri = "/beta/deviceManagement/auditEvents?`$filter=actor/id eq '$($user.id)'"
            #$events = Get-MsGraphObject -Uri $uri
            #$events | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\events.json")) -Force
        } catch { }
        try
        {
            #iosUpdateStatuses
            $uri = "/beta/deviceManagement/iosUpdateStatuses"
            $iosUpdateStatuses = Get-MsGraphObject -Uri $uri | Where-Object { $_.userPrincipalName -ieq $upn }
            $iosUpdateStatuses | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\iosUpdateStatuses.json")) -Force
        } catch { }
        try
        {
            #depOnboardingSettings
            $uri = "/beta/deviceManagement/depOnboardingSettings?`$filter=appleIdentifier eq '$([System.Web.HttpUtility]::UrlEncode($upn))'"
            $depOnboardingSettings = Get-MsGraphObject -Uri $uri
            $depOnboardingSettings | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\depOnboardingSettings.json")) -Force
        } catch { }
        try
        {
            #remoteActionAudits
            $uri = "/beta/deviceManagement/remoteActionAudits?`$filter=initiatedByUserPrincipalName eq '$([System.Web.HttpUtility]::UrlEncode($upn))'"
            $remoteActionAudits = Get-MsGraphObject -Uri $uri
            $remoteActionAudits | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\remoteActionAudits.json")) -Force
        } catch { }
        try
        {
            #managedDevices
            $devices = $null
            try
            {
                $uri = "/beta/users/$($user.id)/managedDevices"
                $devices = Get-MsGraphCollection -Uri $uri -DontThrowIfStatusEquals 404
                $devices | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\managed_devices.json")) -Force
            } catch { }
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

                        $deviceData | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path (MakeFsCompatiblePath("$DataRoot\IntuneDataExport\$($upn)\managedDevice_$($device.deviceName).json")) -Force
                    } catch { 
					    try { Write-Host ($_.Exception | ConvertTo-Json -Depth 1) -ForegroundColor $CommandError } catch {}
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
