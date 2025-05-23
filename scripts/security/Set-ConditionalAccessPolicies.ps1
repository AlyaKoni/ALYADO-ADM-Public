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
    05.03.2024 Konrad Brunner       Excluding Intune Apps

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

# Checking risky sign-in session policy
Write-Host "Checking risky sign-in session policy" -ForegroundColor $CommandInfo
$conditions = @{ 
    Applications = @{
        includeApplications = "All"
    }
    Users = @{
        includeUsers = "All"
    }
    SignInRiskLevels = "high"
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
    $policyObj = New-MgBetaIdentityConditionalAccessPolicy `
        -DisplayName "SESSION: Reauthenticate risky sign-in" `
        -State $procState `
        -Conditions $conditions `
        -SessionControls $sessioncontrols
}
else
{
    Write-Host "Updating policy $PolicyName"
    $policyObj = Update-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyObj.Id `
        -DisplayName "SESSION: Reauthenticate risky sign-in" `
        -Conditions $conditions `
        -SessionControls $sessioncontrols
}

# Disabling security defaults
Write-Host "Disabling security defaults" -ForegroundColor $CommandInfo
& "$AlyaScripts\tenant\Set-SecurityDefaultsDisabled.ps1"

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpdQYJKoZIhvcNAQcCoIIpZjCCKWICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDiPlm2tTFFwCNF
# onT4X02/R1GgqAWGM+W6ydXbmhfzC6CCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# ghnmMIIZ4gIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIP9/p9C7Hqbz2RzA
# Ron04rGVZX3eeKFs6cUWz8XeDY/hMA0GCSqGSIb3DQEBAQUABIICAD67ENgHKWPd
# t6m3o/iNO4ryQKup5cW45koYLSyB2SY4xWt9b288S3ekgAV5ssDQk9TX3KlEhsXC
# 3hCqgfPaEYIChg78KxCx5hf3Ft7NnY1+tk3XNTPSe9mrlmGi3ZQMCeq13xaZMaBu
# pK/2KlgO83dwVsEbU+xwXabFWfugv2b+ytxJbNU6HHE6XQiELFiC716Qw3Bl/hyY
# +D6sz/klECx2UebOn1KZa/oLb1JI0+q60UsP9zT1NcuVvcUv1kr2kTIOSQKG8vZA
# Jnn49Xx6AdukmMb7P1kVIEL5rY3MbGm0QoMgOStqPl7ANKY74FbpBWznTGWAMv95
# RcDy2n9eHd5TJ9/46SxD1lTz18Fi39x0Nznyeq1sW9W/xFsda0gENOakILy2rNMg
# HSPDvcYxYQ3o7beckMdZaC1/rR29mxsjZYC+Ku1C9zM+8z9tI8oXgRilrrFlwimv
# O7wBwzHpq3aSR7g0XPEVAxl7/42o2tBCd+Uc/iFV3ctjkhgednLnceh1xWDQs3HQ
# js5KAjRp83ccqEG++hzDgSpH/Obk9WVeG9UpGNvC2tJ0mfPAdVzzbGu14YvpcqcP
# 9BkEAcB9q7vEKyRBa0qnrwPxtb6zvCD+LfudoXUB5Rke0lJ4b70Shck5Qwb1h9ZD
# KJxMEkgikBBfR7bFzryY3EflDGK+Ff6HoYIWzTCCFskGCisGAQQBgjcDAwExgha5
# MIIWtQYJKoZIhvcNAQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEwgegGCyqG
# SIb3DQEJEAEEoIHYBIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCCQ+Xh4e7qwst9sO3LacfYC5bhkChny1DqdVlyHNNIl9wIUTWYDQgvlm7HA
# tO5yNaqKwkWnEWwYDzIwMjUwMzE5MTEyMTQxWjADAgEBoGGkXzBdMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwqR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2IC0gMjAyMzExoIISVDCCBmwwggRU
# oAMCAQICEAGb6t7ITWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2Jh
# bFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjMxMTA3MTcx
# MzQwWhcNMzQxMjA5MTcxMzQwWjBdMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xv
# YmFsU2lnbiBudi1zYTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVT
# aWduMSAtIFI2IC0gMjAyMzExMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKC
# AYEA6oQ3UGg8lYW1SFRxl/OEcsmdgNMI3Fm7v8tNkGlHieUs2PGoan5gN0lzm7iY
# sxTg74yTcCC19SvXZgV1P3qEUKlSD+DW52/UHDUu4C8pJKOOdyUn4LjzfWR1DJpC
# 5cad4tiHc4vvoI2XfhagxLJGz2DGzw+BUIDdT+nkRqI0pz4Yx2u0tvu+2qlWfn+c
# XTY9YzQhS8jSoxMaPi9RaHX5f/xwhBFlMxKzRmUohKAzwJKd7bgfiWPQHnssW7AE
# 9L1yY86wMSEBAmpysiIs7+sqOxDV8Zr0JqIs/FMBBHkjaVHTXb5zhMubg4htINIg
# zoGraiJLeZBC5oJCrwPr1NDag3rDLUjxzUWRtxFB3RfvQPwSorLAWapUl05tw3rd
# hobUOzdHOOgDPDG/TDN7Q+zw0P9lpp+YPdLGulkibBBYEcUEzOiimLAdM9DzlR34
# 7XG0C0HVZHmivGAuw3rJ3nA3EhY+Ao9dOBGwBIlni6UtINu41vWc9Q+8iL8nLMP5
# IKLBAgMBAAGjggGoMIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYI
# KwYBBQUHAwgwHQYDVR0OBBYEFPlOq764+Fv/wscD9EHunPjWdH0/MFYGA1UdIARP
# ME0wCAYGZ4EMAQQCMEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQ
# BggrBgEFBQcBAQSBgzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFs
# c2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8v
# c2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0
# MB8GA1UdIwQYMBaAFOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0
# oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0
# LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAlfRnz5OaQ5KDF3bWIFW8if/kX7LlFRq3
# lxFALgBBvsU/JKAbRwczBEy0tGL/xu7TDMI0oJRcN5jrRPhf+CcKAr4e0SQdI8sv
# HKsnerOpxS8M5OWQ8BUkHqMVGfjvg+hPu2ieI299PQ1xcGEyfEZu8o/RnOhDTfqD
# 4f/E4D7+3lffBmvzagaBaKsMfCr3j0L/wHNp2xynFk8mGVhz7ZRe5BqiEIIHMjvK
# nr/dOXXUvItUP35QlTSfkjkkUxiDUNRbL2a0e/5bKesexQX9oz37obDzK3kPsUus
# w6PZo9wsnCsjlvZ6KrutxVe2hLZjs2CYEezG1mZvIoMcilgD9I/snE7Q3+7OYSHT
# tZVUSTshUT2hI4WSwlvyepSEmAqPJFYiigT6tJqJSDX4b+uBhhFTwJN7OrTUNMxi
# 1jVhjqZQ+4h0HtcxNSEeEb+ro2RTjlTic2ak+2Zj4TfJxGv7KzOLEcN0kIGDyE+G
# yt1Kl9t+kFAloWHshps2UgfLPmJV7DOm5bga+t0kLgz5MokxajWV/vbR/xeKriMJ
# KyGuYu737jfnsMmzFe12mrf95/7haN5EwQp04ZXIV/sU6x5a35Z1xWUZ9/TVjSGv
# Y7br9OIXRp+31wduap0r/unScU7Svk9i00nWYF9A43aZIETYSlyzXRrZ4qq/TVkA
# F55gZzpHEqAwggZZMIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEB
# DAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQK
# EwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAw
# MFoXDTM0MTIxMDAwMDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2Jh
# bFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENB
# IC0gU0hBMzg0IC0gRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDw
# AuIwI/rgG+GadLOvdYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PE
# Ne2zNMeswwzrgGZt0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39
# eE5DiP6TGRfZ7jHPvIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b
# 7Lbv0mXPRQtUPbFUUweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKW
# O/ELsX9/RpgOhz16ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZ
# uT/0TzXxnA/TNxNS2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7
# vSqbu4ThDqxvDbm19m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9
# bpHFu7FMCEue1EIGbxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUln
# EYuC5a1ahqdm/TMDAd6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKs
# DlcMCdFhniaI/MiyTdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkd
# Zqs0c48efXxeltY9GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYD
# VR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1Og
# MD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2Jh
# bHNpZ24uY29tL3Jvb3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIG
# CCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5
# LzANBgkqhkiG9w0BAQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG
# +wsJrQA6YDMfOcYWaxlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5L
# FST5GETsH8KkrNCyz+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRI
# RVXd7OlKn14U7XIQcXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dI
# ZGkv0pqhcvb3JEt0Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5q
# ucqIwxIwTrIIc59eodaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+I
# Lj198fKRMAWcznt8oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI8
# 5Zse46qEgok+wEr1If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7
# qMnmvkiqK1XZjbclIA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgU
# QGwgHcIt6AvGjW2MtnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZ
# HL9TTaRHWXyVxENB+SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjG
# pGqqIpswggWDMIIDa6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwF
# ADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMK
# R2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBa
# Fw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAt
# IFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRF
# CyyCtEjG61s8roO4QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5N
# OhUG7WRmC5KAykTec5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8
# ZEwhHENo1z08isWyZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXq
# oh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBh
# d8hYdLDUIzr3XTrKotudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw
# 77YcE1eTtt6y+OKFt3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5a
# C0fzBjZJdzC8cTflpuwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL
# 6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl
# +dwFnidZTHY5W+r5paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk9
# 9bOMylitnEJFeW4OhxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HU
# Gie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB
# /wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQY
# MBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o
# 0f2VUs2ewASgkWnmXNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7B
# zeIRka0jGD3d4XJElrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RD
# N3kyvrXnnCxMvEMpmY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QM
# RGby0uO9RgAabQK6JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWp
# b+Gm+99wMOnD7kJG7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEozi
# QRpIenOgd2nHtlx/gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzw
# UHXSNmmc5nsE324GabbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7P
# VMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyd
# uu33H68klQR4qAO77oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1h
# ASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbW
# SUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEds
# b2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP
# 92w6ny4BJBYwCwYJYIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwKwYJKoZIhvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQEL
# BQAwLwYJKoZIhvcNAQkEMSIEIIABvzMmO9YFXvrhlaFch+J1/sgBUwXoFZ7gpKyd
# 1q5tMIGwBgsqhkiG9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe4U9su3aC
# N6VF0BBb8EURveJfgqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJKoZIhvcN
# AQELBQAEggGAAvcUO6UGx7RbquoVjbFqcF9VaR/zMwE0Z9lKG0JB4DAL1bmD3713
# QZJqUMQEtD/6TMdJPocLiwyYm7fNBsexiqJpI8ZPxyspvBOqGlKmUxoSn8astWew
# XucQ/khFP/v4gQdzT/rGFjH//nY1vkGSom8WFqTPJt5Pbsv+Ohmyn+J1tCgic2YI
# X0Md845fZvdeIEuJqA7OqFY8kp8D4d/KqQpYFFi5V0HxRv1SUUXZyqdL/tHSte47
# xMCmNYM+ci4qe+kmZoHo56PBtvoJPDdMP74uNZNicltCgr2iNDgLrPORX1YT3XpQ
# FsY0KgSKRbndJTm6YfgHfqfVubwGs+ZQ5h6JXZb9ntE+EZuCb8oSgVeGQTbpT7rm
# d5P7yKJ+Amc26wYs3wYawcVSjh3U4nNr1VKyMEwHegjotiNFxRN12mQFdaWQcGUB
# Hc5V1m9Q9Ts1HRqwTZV1PFz2nV6apBKewauYIXavUQ+pZhMCTMW681Kcko+Fu7UY
# JZXrgj9CcPAv
# SIG # End signature block
