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
    27.02.2020 Konrad Brunner       Initial Version
    30.06.2022 Konrad Brunner       Change from REST to AzureAdPreview
    24.04.2023 Konrad Brunner       Switched to Graph, removed MSOL
    27.04.2023 Konrad Brunner       Calling script to disable security defaults
    23.07.2023 Konrad Brunner       Power BI Administrator sometimes not there
    13.09.2023 Konrad Brunner       Handling OnPrem groups
    08.11.2023 Konrad Brunner       Key Authentication

#>

[CmdletBinding()]
Param(
    [bool]$ReportOnly = $true
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Set-ConditionalAccessPolicies-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.Governance"


# Logins
LoginTo-MgGraph -Scopes @("Directory.ReadWrite.All","Policy.ReadWrite.ConditionalAccess","Policy.Read.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-ConditionalAccessPolicies | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking no mfa group
Write-Host "Checking MFA exclude group" -ForegroundColor $CommandInfo
if (-Not $AlyaMfaDisabledGroupName -or $AlyaMfaDisabledGroupName -eq "PleaseSpecify")
{
    Write-Host "Please specify the AlyaMfaDisabledGroupName variable in data\ConfigureEnv.ps1" -ForegroundColor $CommandError
    exit 1
}

$GrpRslt = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaMfaDisabledGroupName)'"
if (-Not $GrpRslt)
{
    Write-Host "No MFA group '$AlyaMfaDisabledGroupName' not found" -ForegroundColor $CommandError
    exit 2
}
$ExcludeGroupIdNoMfaCloud = $GrpRslt.Id

$ExcludeGroupIdNoMfaOnPrem = $null
if ($AlyaMfaDisabledGroupNameOnPrem -and $AlyaMfaDisabledGroupNameOnPrem -ne "PleaseSpecify")
{
    $GrpRslt = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaMfaDisabledGroupNameOnPrem)'"
    if (-Not $GrpRslt)
    {
        Write-Host "No MFA group '$AlyaMfaDisabledGroupNameOnPrem' not found" -ForegroundColor $CommandError
        exit 2
    }
    $ExcludeGroupIdNoMfaOnPrem = $GrpRslt.Id
}

$GroupIdMfa = $null
if ($AlyaMfaEnabledGroupName -and $AlyaMfaEnabledGroupName -ne "PleaseSpecify")
{
    $GrpRslt = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaMfaEnabledGroupName)'"
    if (-Not $GrpRslt)
    {
        Write-Host "No MFA group '$AlyaMfaEnabledGroupName' not found" -ForegroundColor $CommandError
        exit 2
    }
    $GroupIdMfa = $GrpRslt.Id
}

$GroupIdMfaOnPrem = $null
if ($AlyaMfaEnabledGroupNameOnPrem -and $AlyaMfaEnabledGroupNameOnPrem -ne "PleaseSpecify")
{
    $GrpRslt = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaMfaEnabledGroupNameOnPrem)'"
    if (-Not $GrpRslt)
    {
        Write-Host "No MFA group '$AlyaMfaEnabledGroupNameOnPrem' not found" -ForegroundColor $CommandError
        exit 2
    }
    $GroupIdMfaOnPrem = $GrpRslt.Id
}

# Getting role assignments
Write-Host "Getting role assignments" -ForegroundColor $CommandInfo
$roleDefs = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Application Administrator",
    "Azure AD Joined Device Local Administrator",
    "Azure DevOps Administrator",
    "Compliance Administrator",
    "Conditional Access Administrator",
    "Dynamics 365 Administrator",
    "Exchange Administrator",
    "Intune Administrator",
    "Windows 365 Administrator",
    "Edge Administrator",
    "Kaizala Administrator",
    "License Administrator",
    "Groups Administrator",
    "Office Apps Administrator",
    "Power Platform Administrator",
    "Printer Administrator",
    "Privileged Authentication Administrator",
    "Search Administrator",
    "Search Administrator",
    "Service Support Administrator",
    "Skype for Business Administrator",
    "SharePoint Administrator",
    "Teams Administrator",
    "User Administrator",
    "Application Developer",
    "Attack Payload Author",
    "Attack Simulation Administrator",
    "Authentication Policy Administrator",
    "Authentication Administrator",
    "Azure Information Protection Administrator"
)
$IncludeRoleIds = @()
$ExcludeRoleIds = @()
$allRoles = Get-MgBetaRoleManagementDirectoryRoleDefinition -All
foreach($roleName in $roleDefs)
{
    $role = $allRoles | Where-Object { $_.Displayname -eq $roleName }
    if (-Not $role)
    {
        Write-Warning "Role $roleName not found!"
    }
    else {
        $IncludeRoleIds += $role.Id
    }
}
$ExcludeRoleIds = $IncludeRoleIds
$syncrole = $allRoles | Where-Object { $_.Displayname -eq "Directory Synchronization Accounts" }
$ExcludeRoleIds += $syncrole.Id

# Getting actual access policies
Write-Host "Getting actual access policies" -ForegroundColor $CommandInfo
$ActPolicies = Get-MgBetaIdentityConditionalAccessPolicy -All

# Specifying processing state
$procState = "Enabled"
if ($ReportOnly) { $procState = "EnabledForReportingButNotEnforced" }

# Checking groups to exclude
Write-Host "Checking groups to exclude" -ForegroundColor $CommandInfo
$ExcludeGroupIds = @()
foreach($groupName in $AlyaMfaDisabledForGroups)
{
    if ($groupName -eq "PleaseSpecify") { continue }
    $GrpRslt = Get-MgBetaGroup -Filter "DisplayName eq '$($groupName)'"
    if (-Not $GrpRslt)
    {
        throw "Group $groupName not found!"
    }
    $ExcludeGroupIds += $GrpRslt.Id
}
$ExcludeGroupIds += $ExcludeGroupIdNoMfaCloud
if ($null -ne $ExcludeGroupIdNoMfaOnPrem) { $ExcludeGroupIds += $ExcludeGroupIdNoMfaOnPrem }

# Checking key group to exclude
Write-Host "Checking key group to exclude" -ForegroundColor $CommandInfo
$IncludeKeyGroupIds = @()
if ($null -ne $AlyaKeyAuthEnabledGroupName -and $AlyaKeyAuthEnabledGroupName -ne "PleaseSpecify")
{
    $GrpRslt = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaKeyAuthEnabledGroupName)'"
    if (-Not $GrpRslt)
    {
        throw "Group $AlyaKeyAuthEnabledGroupName not found!"
    }
    $ExcludeGroupIds += $GrpRslt.Id
    $IncludeKeyGroupIds += $GrpRslt.Id
}

# Getting AuthenticationStrengthPolicy
Write-Host "Getting AuthenticationStrengthPolicy" -ForegroundColor $CommandInfo
$authenticationStrengthPolicy = Get-MgBetaPolicyAuthenticationStrengthPolicy | Where-Object { $_.DisplayName -eq "Phishing-resistant MFA or TAP" }
if (-Not $authenticationStrengthPolicy)
{
    $authenticationStrengthPolicy = Get-MgBetaPolicyAuthenticationStrengthPolicy | Where-Object { $_.DisplayName -eq "Phishing-resistant MFA" }
    if (-Not $authenticationStrengthPolicy) {
        throw "AuthenticationStrengthPolicy 'Phishing-resistant MFA or TAP' nor 'Phishing-resistant MFA' found!"
    }
    else {
        Write-Warning "Authentication strength 'Phishing-resistant MFA or TAP' not found. Using 'Phishing-resistant MFA' instead."
    }
}

# Checking specific key access policy
Write-Host "Checking specific key access policy" -ForegroundColor $CommandInfo
if ($null -ne $AlyaKeyAuthEnabledGroupName -and $AlyaKeyAuthEnabledGroupName -ne "PleaseSpecify")
{
    $conditions = @{ 
        Applications = @{
            includeApplications = "All"
        }
        Users = @{
            includeGroups = $IncludeKeyGroupIds
        }
        Platforms = @{
            includePlatforms = @("windows", "macOS", "linux")
        }
    }
    $grantcontrols  = @{
        AuthenticationStrength = @{
            Id = $authenticationStrengthPolicy.Id
        }
        Operator = "OR"
    }
    $policyObj = $ActPolicies | Where-Object { $_.DisplayName -eq "KEY: Required for specific users" }
    if (-Not $policyObj)
    {
        Write-Warning "Conditional access policy not found. Creating the policy 'KEY: Required for specific users'"
        $policyObj = New-MgBetaIdentityConditionalAccessPolicy `
            -DisplayName "KEY: Required for specific users" `
            -State $procState `
            -Conditions $conditions `
            -GrantControls $grantcontrols
    }
    else
    {
        Write-Host "Updating policy $PolicyName"
        $policyObj = Update-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyObj.Id `
            -DisplayName "KEY: Required for specific users" `
            -Conditions $conditions `
            -GrantControls $grantcontrols
    }
}
else
{
    Write-Warning "$AlyaKeyAuthEnabledGroupName`is not set in ConfigureEnv.ps1. Skipping!"
}

# Checking all admins access policy
Write-Host "Checking all admins MFA access policy" -ForegroundColor $CommandInfo
$conditions = @{ 
    Applications = @{
        includeApplications = "All"
    }
    Users = @{
        includeRoles = $IncludeRoleIds
        excludeGroups = $ExcludeGroupIds
    }
}
$grantcontrols  = @{
    BuiltInControls = @("mfa")
    Operator = "OR"
}
$policyObj = $ActPolicies | Where-Object { $_.DisplayName -eq "MFA: Required for all admins" }
if (-Not $policyObj)
{
    Write-Warning "Conditional access policy not found. Creating the policy 'MFA: Required for all admins'"
    $policyObj = New-MgBetaIdentityConditionalAccessPolicy `
        -DisplayName "MFA: Required for all admins" `
        -State $procState `
        -Conditions $conditions `
        -GrantControls $grantcontrols
}
else
{
    Write-Host "Updating policy $PolicyName"
    $policyObj = Update-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyObj.Id `
        -DisplayName "MFA: Required for all admins" `
        -Conditions $conditions `
        -GrantControls $grantcontrols
}

# Checking all users access policy
Write-Host "Checking all users MFA access policy" -ForegroundColor $CommandInfo
if ($null -eq $GroupIdMfa)
{
    $conditions = @{ 
        Applications = @{
            includeApplications = "All"
        }
        Users = @{
            includeUsers = "All"
            excludeRoles = $ExcludeRoleIds
            excludeGroups = $ExcludeGroupIds
        }
    }
}
else
{
    $IncludeGroupIds = @()
    $IncludeGroupIds += $GroupIdMfa
    if ($null -ne $GroupIdMfaOnPrem) { $IncludeGroupIds += $GroupIdMfaOnPrem }
    $conditions = @{ 
        Applications = @{
            includeApplications = "All"
        }
        Users = @{
            includeGroups = $IncludeGroupIds
            excludeRoles = $ExcludeRoleIds
            excludeGroups = $ExcludeGroupIds
        }
    }
}
$grantcontrols  = @{
    BuiltInControls = @("mfa")
    Operator = "OR"
}
$policyObj = $ActPolicies | Where-Object { $_.DisplayName -eq "MFA: Required for all users" }
if (-Not $policyObj)
{
    Write-Warning "Conditional access policy not found. Creating the policy 'MFA: Required for all users'"
    $policyObj = New-MgBetaIdentityConditionalAccessPolicy `
        -DisplayName "MFA: Required for all users" `
        -State $procState `
        -Conditions $conditions `
        -GrantControls $grantcontrols
}
else
{
    Write-Host "Updating policy $PolicyName"
    $policyObj = Update-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyObj.Id `
        -DisplayName "MFA: Required for all users" `
        -Conditions $conditions `
        -GrantControls $grantcontrols
}

# Checking all admins session policy
Write-Host "Checking all admins session policy" -ForegroundColor $CommandInfo
$excludeGroups = @($ExcludeGroupIdNoMfaCloud)
if ($null -ne $ExcludeGroupIdNoMfaOnPrem) { $excludeGroups += $ExcludeGroupIdNoMfaOnPrem }
$conditions = @{ 
    Applications = @{
        includeApplications = "All"
    }
    Users = @{
        includeRoles = $IncludeRoleIds
        excludeGroups = $excludeGroups
    }
}
$sessioncontrols  = @{
    SignInFrequency = @{
        isEnabled = $true
        type = "days"
        value = "1"
    }
    PersistentBrowser = @{
        isEnabled = $true
        mode = "Always"
    }
}
$policyObj = $ActPolicies | Where-Object { $_.DisplayName -eq "SESSION: For all admins" }
if (-Not $policyObj)
{
    Write-Warning "Conditional access policy not found. Creating the policy 'SESSION: For all admins'"
    $policyObj = New-MgBetaIdentityConditionalAccessPolicy `
        -DisplayName "SESSION: For all admins" `
        -State $procState `
        -Conditions $conditions `
        -SessionControls $sessioncontrols
}
else
{
    Write-Host "Updating policy $PolicyName"
    $policyObj = Update-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyObj.Id `
        -DisplayName "SESSION: For all admins" `
        -Conditions $conditions `
        -SessionControls $sessioncontrols
}

# Checking all users session policy
Write-Host "Checking all users session policy" -ForegroundColor $CommandInfo
$conditions = @{ 
    Applications = @{
        includeApplications = "All"
    }
    Users = @{
        includeUsers = "All"
        excludeRoles = $ExcludeRoleIds
        excludeGroups = $ExcludeGroupIds
    }
}
$sessioncontrols  = @{
    SignInFrequency = @{
        isEnabled = $true
        type = "days"
        value = "30"
    }
    PersistentBrowser = @{
        isEnabled = $true
        mode = "Always"
    }
}
$policyObj = $ActPolicies | Where-Object { $_.DisplayName -eq "SESSION: For all users" }
if (-Not $policyObj)
{
    Write-Warning "Conditional access policy not found. Creating the policy 'SESSION: For all users'"
    $policyObj = New-MgBetaIdentityConditionalAccessPolicy `
        -DisplayName "SESSION: For all users" `
        -State $procState `
        -Conditions $conditions `
        -SessionControls $sessioncontrols
}
else
{
    Write-Host "Updating policy $PolicyName"
    $policyObj = Update-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyObj.Id `
        -DisplayName "SESSION: For all users" `
        -Conditions $conditions `
        -SessionControls $sessioncontrols
}

# Disabling security defaults
Write-Host "Disabling security defaults" -ForegroundColor $CommandInfo
& "$AlyaScripts\tenant\Set-SecurityDefaultsDisabled.ps1"

#Stopping Transscript
Stop-Transcript
