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
    27.02.2020 Konrad Brunner       Initial Version
    30.06.2022 Konrad Brunner       Change from REST to AzureAdPreview
    24.04.2023 Konrad Brunner       Switched to Graph, removed MSOL
    27.04.2023 Konrad Brunner       Calling script to disable security defaults
    23.07.2023 Konrad Brunner       Power BI Administrator sometimes not there
    13.09.2023 Konrad Brunner       Handling OnPrem groups
    08.11.2023 Konrad Brunner       Key Authentication
    05.03.2024 Konrad Brunner       Excluding Intune Apps
    26.08.2025 Konrad Brunner       Get-MgBetaIdentityConditionalAccessPolicy fix

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
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.Governance"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Applications"

# Logins
LoginTo-MgGraph -Scopes @("Directory.ReadWrite.All","Policy.ReadWrite.ConditionalAccess","Policy.Read.All","Application.Read.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-ConditionalAccessPolicies | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Get-MgBetaIdentityConditionalAccessPolicy fix
# This cmdlet is sometimes there and sometimes not. If not, we use Get-MgIdentityConditionalAccessPolicy
$GetMgCAP = "Get-MgBetaIdentityConditionalAccessPolicy"
$NewMgCAP = "New-MgBetaIdentityConditionalAccessPolicy"
$UpdMgCAP = "Update-MgBetaIdentityConditionalAccessPolicy"
$cmd = Get-Command -Name $GetMgCAP -ErrorAction SilentlyContinue
if (-Not $cmd)
{
    Install-ModuleIfNotInstalled "Microsoft.Graph.Identity.SignIns"
    $GetMgCAP = "Get-MgIdentityConditionalAccessPolicy"
    $NewMgCAP = "New-MgIdentityConditionalAccessPolicy"
    $UpdMgCAP = "Update-MgIdentityConditionalAccessPolicy"
}

# Checking intune apps
Write-Host "Checking intune apps" -ForegroundColor $CommandInfo
$IntuneApp = Get-MgBetaServicePrincipal -Filter "DisplayName eq 'Microsoft Intune'"
if (-Not $IntuneApp) { $IntuneApp = Get-MgBetaServicePrincipal -Filter "DisplayName eq 'Microsoft.Intune'" }
$EnrollmentApp = Get-MgBetaServicePrincipal -Filter "DisplayName eq 'Microsoft Intune Enrollment'"
$ExcludeApps = @($IntuneApp.AppId)
if ($EnrollmentApp) { $ExcludeApps += $EnrollmentApp.AppId }

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
$ActPolicies = & $GetMgCAP -All

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
            excludeApplications = $ExcludeApps
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
        $policyObj = & $NewMgCAP `
            -DisplayName "KEY: Required for specific users" `
            -State $procState `
            -Conditions $conditions `
            -GrantControls $grantcontrols
    }
    else
    {
        Write-Host "Updating policy $PolicyName"
        $policyObj = & $UpdMgCAP -ConditionalAccessPolicyId $policyObj.Id `
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
        excludeApplications = $ExcludeApps
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
    $policyObj = & $NewMgCAP `
        -DisplayName "MFA: Required for all admins" `
        -State $procState `
        -Conditions $conditions `
        -GrantControls $grantcontrols
}
else
{
    Write-Host "Updating policy $PolicyName"
    $policyObj = & $UpdMgCAP -ConditionalAccessPolicyId $policyObj.Id `
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
            excludeApplications = $ExcludeApps
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
            excludeApplications = $ExcludeApps
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
    $policyObj = & $NewMgCAP `
        -DisplayName "MFA: Required for all users" `
        -State $procState `
        -Conditions $conditions `
        -GrantControls $grantcontrols
}
else
{
    Write-Host "Updating policy $PolicyName"
    $policyObj = & $UpdMgCAP -ConditionalAccessPolicyId $policyObj.Id `
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
    $policyObj = & $NewMgCAP `
        -DisplayName "SESSION: For all admins" `
        -State $procState `
        -Conditions $conditions `
        -SessionControls $sessioncontrols
}
else
{
    Write-Host "Updating policy $PolicyName"
    $policyObj = & $UpdMgCAP -ConditionalAccessPolicyId $policyObj.Id `
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
    $policyObj = & $NewMgCAP `
        -DisplayName "SESSION: For all users" `
        -State $procState `
        -Conditions $conditions `
        -SessionControls $sessioncontrols
}
else
{
    Write-Host "Updating policy $PolicyName"
    $policyObj = & $UpdMgCAP -ConditionalAccessPolicyId $policyObj.Id `
        -DisplayName "SESSION: For all users" `
        -Conditions $conditions `
        -SessionControls $sessioncontrols
}

# Checking risky sign-in session policy
<#
Write-Host "Checking risky sign-in session policy" -ForegroundColor $CommandInfo
$conditions = @{ 
    Applications = @{
        includeApplications = "All"
    }
    Users = @{
        includeUsers = "All"
    }
    SignInRiskLevels = @("high")
}
$sessioncontrols  = @{
    SignInFrequency = @{
        isEnabled = $true
        frequencyInterval = "everyTime"
    }
}
$policyObj = $ActPolicies | Where-Object { $_.DisplayName -eq "SESSION: Reauthenticate risky sign-in" }
if (-Not $policyObj)
{
    Write-Warning "Conditional access policy not found. Creating the policy 'SESSION: Reauthenticate risky sign-in'"
    $policyObj = & $NewMgCAP `
        -DisplayName "SESSION: Reauthenticate risky sign-in" `
        -State $procState `
        -Conditions $conditions `
        -SessionControls $sessioncontrols
}
else
{
    Write-Host "Updating policy $PolicyName"
    $policyObj = & $UpdMgCAP -ConditionalAccessPolicyId $policyObj.Id `
        -DisplayName "SESSION: Reauthenticate risky sign-in" `
        -Conditions $conditions `
        -SessionControls $sessioncontrols
}
#>

# Disabling security defaults
Write-Host "Disabling security defaults" -ForegroundColor $CommandInfo
& "$AlyaScripts\tenant\Set-SecurityDefaultsDisabled.ps1"

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBYRZj23+KBNWcP
# 0Htm7mIZMUDI6v1YckrTVL5XHdZMKqCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAwRA3kUTFBorykz
# k1Xbv4Gniuy41Cq121YKzkC3ZhKTMA0GCSqGSIb3DQEBAQUABIICAHgBrhDrBMTo
# bONi62Xi1RWBFJsMeywc2o5C+58PypEk1gzwOo0GfOdRoyZ6V9t7N8/KmRVFZeB1
# Wocy3656ta24yyQCZyLIzPAG7/FSvBSMrWOlDIDYEmdMCKq+dtzfCmNtmEXL48Sf
# w92erIMkCI4Bw54ZZhqnY1u4WrhuHXWltA/Ppn3nG6ntdvEb460ixwJB6vEB0tkv
# v92Q5flzoYDDnTZp8NWb9s3KEbblR8FHFb90jI7Ml7ncuwyTKp1YutYBhiwVO9DD
# WfevmwengfzKi0W9OOLHB2GNh3p7bVoWwJGcdkQlwWenEmEhF0/hZRLkr34u9AxF
# FaSNwVfSd+FQMDfX/Y0SMbWy+KEb/ogwIj7Z9PpSDaHjVq3uzDXt859u1QmkJivI
# Kzz7kwi7iZN2oAlMmhRFR+HsAnbRK0QERQOgDwJWl2T4Gg8YInQugTqw6EJaU2ZJ
# I0fthvV9p03GT/ZB9BsrFcVXkoaYdvO1SsVpp8byEptVZPtO+yheawPHcEKdHJvw
# f5Pde9814jIOk8E4TGxQ5K2vblQEo0nnsLy7GRiPC8Xwow5QLzUwIzL+fq3rCjnI
# ll04FbFcEeyyq9IWt8gHEdNFIFtF28quL6WHaNuj7pvp3NPVtVGgbYtbeo5tIKhv
# 5Y3ilbAU7JLk5T0kBtvb6gfDoD6VJ3FmoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCCI9vsJZ5T++zwLcKFEtNz4+L3ApfTHyNCO2r0sUPXrIwIUGuoXiK42eW1P
# f8PliK/QMuwzeYYYDzIwMjUwODI2MTI0NDAxWjADAgEBoFikVjBUMQswCQYDVQQG
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
# IM3yAokTh5a7TsgyMcfH5VA/751vd17R+LdPpHbbXHXoMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAE1wygBk7HaNN
# jdOVYfgu90Fu0RMepL0nuoYMEOkRhXFR7Fch2fX+Od+Ncu314j57VIWKufpRxvsg
# H2ioyjMMCbCIjl4obGIQgZJFSPnEws5N9QwGqguLWW9hQHZLQnTDNMwDdOg+q3Mq
# sPe+QVZuf2d0v1ar2MpWem9bikqowp70wsA+dPDuoI24QpWVGg28HJbjvoTzQk77
# OUM4X0YBVtH3I3bUHMxYgiXzHczKZBnhsRr0H8dBTotlueafrbhB2+YxSkc4p15Y
# a4w+c5+qIPqN0r9LGq6mwCSYm+9EV4ShRqmULysud78hmSVjHjhXPyxw+z4UVu4H
# 7IiCzVR/oKqBa1fnrwlpqwcytrFFUPkbZd8ctlFc+tFVStw1ihuvZ/RS4Me8FgaL
# s1pnhFqbKHuQ+OLhnXprTdCzOq53eAq/kaR0F6P3/1YMscEQz3fx7AlwkYUc5S5n
# Ag8DVSUsxLiTvOSAdJWtL+giev7vyXALbzOLdfMei4LcD3bBBZIn
# SIG # End signature block
