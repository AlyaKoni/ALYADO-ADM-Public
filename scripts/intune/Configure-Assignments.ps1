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
    08.07.2022 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
    [string]$ConfigurationProfileFile = $null, #defaults to $($AlyaData)\intune\deviceConfigurationProfiles.json
    [string]$CompliancePolicyFile = $null, #defaults to $($AlyaData)\intune\deviceCompliancePolicies.json
    [string]$FeatureProfileFile = $null, #defaults to $($AlyaData)\intune\deviceFeatureUpdateProfiles.json
    [string]$QualityProfileFile = $null, #defaults to $($AlyaData)\intune\deviceQualityUpdateProfiles.json
    [string]$UpdateProfileFile = $null, #defaults to $($AlyaData)\intune\deviceUpdateProfiles.json
    [string]$GrouPolicyProfileFile = $null, #defaults to $($AlyaData)\intune\deviceGroupPolicyProfiles.json
    [string]$ScriptDir = $null #defaults to $($AlyaData)\intune\Scripts
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-Assignments-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
if (-Not $ConfigurationProfileFile)
{
    $ConfigurationProfileFile = "$($AlyaData)\intune\deviceConfigurationProfiles.json"
}
if (-Not $CompliancePolicyFile)
{
    $CompliancePolicyFile = "$($AlyaData)\intune\deviceCompliancePolicies.json"
}
if (-Not $FeatureProfileFile)
{
    $FeatureProfileFile = "$($AlyaData)\intune\deviceFeatureUpdateProfiles.json"
}
if (-Not $QualityProfileFile)
{
    $QualityProfileFile = "$($AlyaData)\intune\deviceQualityUpdateProfiles.json"
}
if (-Not $UpdateProfileFile)
{
    $UpdateProfileFile = "$($AlyaData)\intune\deviceUpdateProfiles.json"
}
if (-Not $GrouPolicyProfileFile)
{
    $GrouPolicyProfileFile = "$($AlyaData)\intune\deviceGroupPolicyProfiles.json"
}
if (-Not $ScriptDir)
{
    $ScriptDir = "$($AlyaData)\intune\Scripts"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "Directory.Read.All",
    "DeviceManagementServiceConfig.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementApps.ReadWrite.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Configure-Assignments | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$compliancePolicies = Get-Content -Path $CompliancePolicyFile -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json
$configurationProfiles = Get-Content -Path $ConfigurationProfileFile -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json
$featureProfiles = Get-Content -Path $FeatureProfileFile -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json
$qualityProfiles = Get-Content -Path $QualityProfileFile -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json
$updateProfiles = Get-Content -Path $UpdateProfileFile -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json
$grouPolicyProfiles = Get-Content -Path $GrouPolicyProfileFile -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json
$scripts = Get-ChildItem -Path $ScriptDir -Filter "*.ps1"

Write-Host "Configuring assignments for compliance policies" -ForegroundColor $CommandInfo
foreach($policy in $compliancePolicies)
{
    if ($policy.Comment1 -and $policy.Comment2 -and $policy.Comment3) { continue }
    if ($policy.displayName.EndsWith("_unused")) { continue }
    Write-Host "$($policy.displayName)"
    switch($policy.displayName)
    {
        'WIN Compliance Policy' { $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM" }
        'AND Enterprise Personal Compliance Policy' { $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-ANDROIDMDMPERSONAL" }
        'AND Enterprise Owned Compliance Policy' { $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-ANDROIDMDMOWNED" }
        'IOS Compliance Policy' { $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-IOSMDM" }
        'MAC Compliance Policy' { $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-MACMDM" }
    }
    $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($assGrp)'"
    if (-Not $exGrp){
        Write-Error "Can't find group $assGrp"
    }

    $searchValue = [System.Web.HttpUtility]::UrlEncode($policy.displayName)
    $uri = "/beta/deviceManagement/deviceCompliancePolicies?`$filter=displayName eq '$searchValue'"
    $actPolicy = (Get-MsGraphObject -Uri $uri).value
    if (-Not $actPolicy){
        Write-Error "Can't find policy $($policy.displayName)"
    }

    $assignment = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#Microsoft.Graph.groupAssignmentTarget"
                    groupId  = $exGrp.Id          
                }
            }
        )
    }
    $uri = "/beta/deviceManagement/deviceCompliancePolicies/$($actPolicy.id)/assign"
    $assignment = Post-MsGraph -Uri $uri -Body $assignment
}

Write-Host "Configuring assignments for configuration profiles" -ForegroundColor $CommandInfo
foreach($profile in $configurationProfiles)
{
    if ($profile.Comment1 -and $profile.Comment2 -and $profile.Comment3) { continue }
    if ($profile.displayName.EndsWith("_unused")) { continue }
    Write-Host "$($profile.displayName)"
    if ($profile.displayName.StartsWith("WIN "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM"
    }
    if ($profile.displayName.StartsWith("WIN10 "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM10"
    }
    if ($profile.displayName.StartsWith("WIN11 "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM11"
    }
    if ($profile.displayName.StartsWith("MAC "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-MACMDM"
    }
    if ($profile.displayName.StartsWith("AND ") -and $profile.displayName -like "*Personal*")
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-ANDROIDMDMPERSONAL"
    }
    if ($profile.displayName.StartsWith("AND ") -and $profile.displayName -like "*Owned*")
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-ANDROIDMDMOWNED"
    }
    if ($profile.displayName.StartsWith("IOS "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-IOSMDM"
    }
    $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($assGrp)'"
    if (-Not $exGrp){
        Write-Error "Can't find group $assGrp"
    }

    $searchValue = [System.Web.HttpUtility]::UrlEncode($profile.displayName)
    $uri = "/beta/deviceManagement/deviceConfigurations?`$filter=displayName eq '$searchValue'"
    $actProfile = (Get-MsGraphObject -Uri $uri).value
    if (-Not $actProfile){
        Write-Error "Can't find profile $($profile.displayName)"
    }

    $assignment = @{
        deviceConfigurationGroupAssignments = @(
            @{
                "@odata.type" = "#Microsoft.Graph.deviceConfigurationGroupAssignment"
                targetGroupId = $exGrp.Id
                excludeGroup = $false
            }
        )
    }
    $uri = "/beta/deviceManagement/deviceConfigurations/$($actProfile.id)/assign"
    $assignment = Post-MsGraph -Uri $uri -Body $assignment
}

Write-Host "Configuring assignments for feature profiles" -ForegroundColor $CommandInfo
foreach($profile in $featureProfiles)
{
    if ($profile.Comment1 -and $profile.Comment2 -and $profile.Comment3) { continue }
    if ($profile.displayName.EndsWith("_unused")) { continue }
    Write-Host "$($profile.displayName)"
    if ($profile.displayName.StartsWith("WIN "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM"
    }
    if ($profile.displayName.StartsWith("WIN10 "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM10"
    }
    if ($profile.displayName.StartsWith("WIN11 "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM11"
    }
    $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($assGrp)'"
    if (-Not $exGrp){
        Write-Error "Can't find group $assGrp"
    }

    $uri = "/beta/deviceManagement/windowsFeatureUpdateProfiles"
    $actProfiles = (Get-MsGraphObject -Uri $uri).value
    $actProfile = $actProfiles | Where-Object { $_.displayName -eq $profile.displayName }
    if (-Not $actProfile){
        Write-Error "Can't find profile $($profile.displayName)"
    }

    $assignment = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#Microsoft.Graph.groupAssignmentTarget"
                    groupId = $exGrp.Id
                    deviceAndAppManagementAssignmentFilterId = $null
                }
            }
        )
    }
    $uri = "/beta/deviceManagement/windowsFeatureUpdateProfiles/$($actProfile.id)/assign"
    $assignment = Post-MsGraph -Uri $uri -Body $assignment
}

Write-Host "Configuring assignments for quality profiles" -ForegroundColor $CommandInfo
foreach($profile in $qualityProfiles)
{
    if ($profile.Comment1 -and $profile.Comment2 -and $profile.Comment3) { continue }
    if ($profile.displayName.EndsWith("_unused")) { continue }
    Write-Host "$($profile.displayName)"
    if ($profile.displayName.StartsWith("WIN "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM"
    }
    if ($profile.displayName.StartsWith("WIN10 "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM10"
    }
    if ($profile.displayName.StartsWith("WIN11 "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM11"
    }
    $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($assGrp)'"
    if (-Not $exGrp){
        Write-Error "Can't find group $assGrp"
    }

    $uri = "/beta/deviceManagement/windowsQualityUpdateProfiles"
    $actProfiles = (Get-MsGraphObject -Uri $uri).value
    $actProfile = $actProfiles | Where-Object { $_.displayName -eq $profile.displayName }
    $assignment = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#Microsoft.Graph.groupAssignmentTarget"
                    groupId = $exGrp.Id
                    deviceAndAppManagementAssignmentFilterId = $null
                }
            }
        )
    }
    $uri = "/beta/deviceManagement/windowsQualityUpdateProfiles/$($actProfile.id)/assign"
    $assignment = Post-MsGraph -Uri $uri -Body $assignment
}

Write-Host "Configuring assignments for update profiles" -ForegroundColor $CommandInfo
foreach($profile in $updateProfiles)
{
    if ($profile.Comment1 -and $profile.Comment2 -and $profile.Comment3) { continue }
    if ($profile.displayName.EndsWith("_unused")) { continue }
    Write-Host "$($profile.displayName)"
    if ($profile.displayName.StartsWith("WIN "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM"
    }
    if ($profile.displayName.StartsWith("WIN10 "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM10"
    }
    if ($profile.displayName.StartsWith("WIN11 "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM11"
    }
    if ($profile.displayName.StartsWith("IOS "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-IOSMDM"
    }
    $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($assGrp)'"
    if (-Not $exGrp){
        Write-Error "Can't find group $assGrp"
    }

    $uri = "/beta/deviceManagement/deviceConfigurations"
    $actProfiles = (Get-MsGraphObject -Uri $uri).value
    $actProfile = $actProfiles | Where-Object { $_.displayName -eq $profile.displayName }
    if (-Not $actProfile){
        Write-Error "Can't find profile $($profile.displayName)"
    }

    $assignment = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#Microsoft.Graph.groupAssignmentTarget"
                    groupId = $exGrp.Id
                    deviceAndAppManagementAssignmentFilterId = $null
                }
            }
        )
    }
    $uri = "/beta/deviceManagement/deviceConfigurations/$($actProfile.id)/assign"
    $assignment = Post-MsGraph -Uri $uri -Body $assignment
}

Write-Host "Configuring assignments for group policy profiles" -ForegroundColor $CommandInfo
foreach($profile in $grouPolicyProfiles)
{
    if ($profile.Comment1 -and $profile.Comment2 -and $profile.Comment3) { continue }
    if ($profile.displayName.EndsWith("_unused")) { continue }
    Write-Host "$($profile.displayName)"
    if ($profile.displayName.StartsWith("WIN "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM"
    }
    if ($profile.displayName.StartsWith("WIN10 "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM10"
    }
    if ($profile.displayName.StartsWith("WIN11 "))
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM11"
    }
    $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($assGrp)'"
    if (-Not $exGrp){
        Write-Error "Can't find group $assGrp"
    }

    $searchValue = [System.Web.HttpUtility]::UrlEncode($profile.displayName)
    $uri = "/beta/deviceManagement/groupPolicyConfigurations?`$filter=displayName eq '$searchValue'"
    $actProfile = (Get-MsGraphObject -Uri $uri).value
    if (-Not $actProfile){
        Write-Error "Can't find profile $($profile.displayName)"
    }

    $assignment = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#Microsoft.Graph.groupAssignmentTarget"
                    groupId  = $exGrp.Id          
                }
            }
        )
    }
    $uri = "/beta/deviceManagement/groupPolicyConfigurations/$($actProfile.id)/assign"
    $assignment = Post-MsGraph -Uri $uri -Body $assignment
}

Write-Host "Configuring assignments for scripts" -ForegroundColor $CommandInfo
foreach($script in $scripts)
{
    if ($script.Name.IndexOf("_unused") -gt -1) { continue }
    Write-Host "$($script.Name)"
    if ($script.Name  -eq "ConfigureFirewallForTeamsInProfiles.ps1")
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM"
    }
    if ($script.Name  -eq "ConfigureFirewallForClickShareInProfiles.ps1")
    {
        $assGrp = "$($AlyaCompanyNameShortM365)SG-DEV-WINMDM"
    }
    $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($assGrp)'"
    if (-Not $exGrp){
        Write-Error "Can't find group $assGrp"
    }

    $uri = "/beta/deviceManagement/deviceManagementScripts"
    $actScripts = (Get-MsGraphObject -Uri $uri).value
    $actScript = $actScripts | Where-Object { $_.fileName -eq $script.Name }
    if (-Not $actScript){
        Write-Error "Can't find script $($script.Name)"
    }

    $assignment = @{
        deviceManagementScriptGroupAssignments = @(
            @{
                "@odata.type" = "#Microsoft.Graph.deviceManagementScriptGroupAssignment"
                targetGroupId = $exGrp.Id
                id = $actScript.id
            }
        )
    }
    $uri = "/beta/deviceManagement/deviceManagementScripts/$($actScript.id)/assign"
    $assignment = Post-MsGraph -Uri $uri -Body $assignment
}

#Stopping Transscript
Stop-Transcript
