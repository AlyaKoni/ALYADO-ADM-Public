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
    07.11.2023 Konrad Brunner       Initial Version
    19.03.2025 Konrad Brunner       New param configureAllowedKeys

#>

[CmdletBinding()]
Param(
    [bool]$minimalConfig = $true,
    [bool]$conditionalAccessEnabled = $true,
    [bool]$configureAllowedKeys = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Set-AuthenticationMethods-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Reports"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"

# Logins
LoginTo-MgGraph -Scopes @("Directory.ReadWrite.All","Policy.Read.All","Policy.ReadWrite.AuthenticationMethod")

# =============================================================
# Graph stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-AuthenticationMethods | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking configuration
if ($null -eq $AlyaKeyAuthEnabledKeys -or $AlyaKeyAuthEnabledKeys -eq "PleaseSpecify")
{
    $AlyaKeyAuthEnabledKeys = @("d8522d9f-575b-4866-88a9-ba99fa02f35b")
}

# Getting AuthenticationMethodPolicy
Write-Host "Getting AuthenticationMethodPolicy" -ForegroundColor $CommandInfo
$authenticationMethodPolicy = Get-MgBetaPolicyAuthenticationMethodPolicy
$Fido2AMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Fido2" }
$MicrosoftAuthenticatorAMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "MicrosoftAuthenticator" }
$SmsAMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Sms" }
$TemporaryAccessPassAMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "TemporaryAccessPass" }
$VoiceAMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Voice" }
$EmailAMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Email" }
$HardwareOathAMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "HardwareOath" }
$SoftwareOathAMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "SoftwareOath" }

# Checking mail policy
if (-Not $minimalConfig)
{
    Write-Host "Checking mail policy" -ForegroundColor $CommandInfo
    $params = @{
        "@odata.type" = "#microsoft.graph.emailAuthenticationMethodConfiguration"
        State = "enabled"
        AllowExternalIdToUseEmailOtp = "enabled"
    }
    $dirty = $false
    if ($EmailAMC.State -ne "enabled") {
        Write-Warning "  mail policy wasn't enabled. Enabling it now."
        $dirty = $true
    } else {
        Write-Host "  mail policy was already enabled."
    }
    if ($EmailAMC.AdditionalProperties.allowExternalIdToUseEmailOtp -ne "enabled") {
        Write-Warning "  mail policy setting allowExternalIdToUseEmailOtp wasn't enabled. Enabling it now."
        $dirty = $true
    } else {
        Write-Host "  mail policy setting allowExternalIdToUseEmailOtp was already enabled."
    }
    if ($dirty) {
        Update-MgBetaPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration  `
            -AuthenticationMethodConfigurationId $EmailAMC.Id `
            -BodyParameter $params
    }
}
# Checking fido2 policy
Write-Host "Checking fido2 policy" -ForegroundColor $CommandInfo
$params = @{
    "@odata.type" = "#microsoft.graph.fido2AuthenticationMethodConfiguration"
    State = "enabled"
    IsAttestationEnforced = $true
    IsSelfServiceRegistrationAllowed = $true
    KeyRestrictions = @{
        "@odata.type" = "#microsoft.graph.fido2KeyRestrictions"
        IsEnforced = $true
        EnforcementType = "allow"
        AaGuids = $AlyaKeyAuthEnabledKeys
    }
}
$dirty = $false
if ($Fido2AMC.State -ne "enabled") {
    Write-Warning "  fido2 policy wasn't enabled. Enabling it now."
    $dirty = $true
} else {
    Write-Host "  fido2 policy was already enabled."
}
if ($Fido2AMC.AdditionalProperties.isAttestationEnforced -ne $true) {
    Write-Warning "  fido2 policy configuration isAttestationEnforced wasn't enabled. Enabling it now."
    $dirty = $true
} else {
    Write-Host "  fido2 policy configuration isAttestationEnforced was already enabled."
}
if ($Fido2AMC.AdditionalProperties.isSelfServiceRegistrationAllowed -ne $true) {
    Write-Warning "  fido2 policy configuration isSelfServiceRegistrationAllowed wasn't enabled. Enabling it now."
    $dirty = $true
} else {
    Write-Host "  fido2 policy configuration isSelfServiceRegistrationAllowed was already enabled."
}
foreach($key in $AlyaKeyAuthEnabledKeys)
{
    if ($Fido2AMC.AdditionalProperties.keyRestrictions.aaGuids -notcontains $key) {
        Write-Warning "  fido2 aaGuid $key was missing in aaGuids. Added now."
        $dirty = $true
    }
}
foreach($key in $Fido2AMC.AdditionalProperties.keyRestrictions.aaGuids)
{
    $params.KeyRestrictions.AaGuids = $Fido2AMC.AdditionalProperties.keyRestrictions.aaGuids
    if ($params.KeyRestrictions.AaGuids -notcontains $key) {
        $params.KeyRestrictions.AaGuids += $key
    }
}
if ($configureAllowedKeys)
{
    if ($Fido2AMC.AdditionalProperties.keyRestrictions.isEnforced -ne $true) {
        Write-Warning "  fido2 policy configuration keyRestrictions.isEnforced wasn't enabled. Enabling it now."
        $dirty = $true
    } else {
        Write-Host "  fido2 policy configuration keyRestrictions.isEnforced was already enabled."
    }
    if ($Fido2AMC.AdditionalProperties.keyRestrictions.enforcementType -ne "allow") {
        Write-Warning "  fido2 policy configuration keyRestrictions.enforcementType wasn't allowed. Allowing it now."
        $dirty = $true
    } else {
        Write-Host "  fido2 policy configuration keyRestrictions.enforcementType was already allowed."
    }
}
else
{
    if ($Fido2AMC.AdditionalProperties.keyRestrictions.isEnforced -ne $false) {
        Write-Warning "  fido2 policy configuration keyRestrictions.isEnforced wasn't disabled. Disabling it now."
        $dirty = $true
        $params.KeyRestrictions.IsEnforced = $false
    } 
}
if ($dirty) {
    Update-MgBetaPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration  `
        -AuthenticationMethodConfigurationId $Fido2AMC.Id `
        -BodyParameter $params
}

# Checking authenticator policy
Write-Host "Checking authenticator policy" -ForegroundColor $CommandInfo
$params = @{
    "@odata.type" = "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration"
    State = "enabled"
    IsSoftwareOathEnabled = $true
    FeatureSettings = @{
        "@odata.type" = "#microsoft.graph.microsoftAuthenticatorFeatureSettings"
        DisplayAppInformationRequiredState = @{
            "@odata.type" = "microsoft.graph.authenticationMethodFeatureConfiguration"
            State = "enabled"
            IncludeTarget = @{ #TODO take it from actual value better?
                "@odata.type" = "#microsoft.graph.featureTarget"
                TargetType = "group"
                Id = "all_users"
            }
        }
        DisplayLocationInformationRequiredState = @{
            "@odata.type" = "microsoft.graph.authenticationMethodFeatureConfiguration"
            State = "enabled"
            IncludeTarget = @{ #TODO take it from actual value better?
                "@odata.type" = "#microsoft.graph.featureTarget"
                TargetType = "group"
                Id = "all_users"
            }
        }
    }
}
$dirty = $false
if ($MicrosoftAuthenticatorAMC.State -ne "enabled") {
    Write-Warning "  authenticator policy wasn't enabled. Enabling it now."
    $dirty = $true
} else {
    Write-Host "  authenticator policy was already enabled."
}
if ($MicrosoftAuthenticatorAMC.AdditionalProperties.featureSettings.displayAppInformationRequiredState.state -ne "enabled") {
    Write-Warning "  authenticator policy setting displayAppInformationRequiredState wasn't enabled. Enabling it now."
    $dirty = $true
} else {
    Write-Host "  authenticator policy setting displayAppInformationRequiredState was already enabled."
}
if ($MicrosoftAuthenticatorAMC.AdditionalProperties.featureSettings.displayLocationInformationRequiredState.state -ne "enabled") {
    Write-Warning "  authenticator policy setting displayLocationInformationRequiredState wasn't enabled. Enabling it now."
    $dirty = $true
} else {
    Write-Host "  authenticator policy setting displayLocationInformationRequiredState was already enabled."
}
if ($dirty) {
    Update-MgBetaPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration  `
        -AuthenticationMethodConfigurationId $MicrosoftAuthenticatorAMC.Id `
        -BodyParameter $params
}

# Checking SoftwareOath policy
Write-Host "Checking SoftwareOath policy" -ForegroundColor $CommandInfo
$params = @{
    "@odata.type" = "#microsoft.graph.softwareOathAuthenticationMethodConfiguration"
    State = "enabled"
}
$dirty = $false
if ($SoftwareOathAMC.State -ne "enabled") {
    Write-Warning "  SoftwareOath policy wasn't enabled. Enabling it now."
    $dirty = $true
} else {
    Write-Host "  SoftwareOath policy was already enabled."
}
if ($dirty) {
    Update-MgBetaPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration  `
        -AuthenticationMethodConfigurationId $SoftwareOathAMC.Id `
        -BodyParameter $params
}

# Checking HardwareOath policy
Write-Host "Checking HardwareOath policy" -ForegroundColor $CommandInfo
$params = @{
    "@odata.type" = "#microsoft.graph.hardwareOathAuthenticationMethodConfiguration"
    State = "enabled"
}
$dirty = $false
if ($SoftwareOathAMC.State -ne "enabled") {
    Write-Warning "  HardwareOath policy wasn't enabled. Enabling it now."
    $dirty = $true
} else {
    Write-Host "  HardwareOath policy was already enabled."
}
if ($dirty) {
    Update-MgBetaPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration  `
        -AuthenticationMethodConfigurationId $HardwareOathAMC.Id `
        -BodyParameter $params
}

# Checking sms policy
if (-Not $minimalConfig)
{
    Write-Host "Checking sms policy" -ForegroundColor $CommandInfo
    $params = @{
        "@odata.type" = "#microsoft.graph.smsAuthenticationMethodConfiguration"
        State = "enabled"
    }
    $dirty = $false
    if ($SmsAMC.State -ne "enabled") {
        Write-Warning "  sms policy wasn't enabled. Enabling it now."
        $dirty = $true
    } else {
        Write-Host "  sms policy was already enabled."
    }
    if ($dirty) {
        Update-MgBetaPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration  `
            -AuthenticationMethodConfigurationId $SmsAMC.Id `
            -BodyParameter $params
    }
}

# Checking voice policy
Write-Host "Checking voice policy" -ForegroundColor $CommandInfo
if (-Not $minimalConfig)
{
    $params = @{
        "@odata.type" = "#microsoft.graph.voiceAuthenticationMethodConfiguration"
        State = "enabled"
        IsOfficePhoneAllowed = $true
    }
    $dirty = $false
    if ($VoiceAMC.State -ne "enabled") {
        Write-Warning "  voice policy wasn't enabled. Enabling it now."
        $dirty = $true
    } else {
        Write-Host "  voice policy was already enabled."
    }
    if ($VoiceAMC.AdditionalProperties.isOfficePhoneAllowed -ne $true) {
        Write-Warning "  voice policy setting isOfficePhoneAllowed wasn't enabled. Enabling it now."
        $dirty = $true
    } else {
        Write-Host "  voice policy setting isOfficePhoneAllowed was already enabled."
    }
    if ($dirty) {
        Update-MgBetaPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration  `
            -AuthenticationMethodConfigurationId $VoiceAMC.Id `
            -BodyParameter $params
    }
}

# Checking temp acc pass policy
Write-Host "Checking temp acc pass policy" -ForegroundColor $CommandInfo
$params = @{
    "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration"
    State = "enabled"
}
$dirty = $false
if ($TemporaryAccessPassAMC.State -ne "enabled") {
    Write-Warning "  temp acc pass policy wasn't enabled. Enabling it now."
    $dirty = $true
} else {
    Write-Host "  temp acc pass policy was already enabled."
}
if ($dirty) {
    Update-MgBetaPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration  `
        -AuthenticationMethodConfigurationId $TemporaryAccessPassAMC.Id `
        -BodyParameter $params
}

# Checking SystemCredentialPreferences exludes non mfa groups
if ($conditionalAccessEnabled)
{
    Write-Host "Checking SystemCredentialPreferences" -ForegroundColor $CommandInfo
    if ($authenticationMethodPolicy.SystemCredentialPreferences.State -ne "disabled") {
        $exlMfaDefaultsGroup = $null
        if ($null -ne $AlyaNoMfaDefaultsGroupName -and $AlyaNoMfaDefaultsGroupName -ne "PleaseSpecify") {
            $exlMfaDefaultsGroup = Get-MgBetaGroup -Filter "displayName eq '$AlyaNoMfaDefaultsGroupName'"
            if (-Not $exlMfaDefaultsGroup)
            {
                $exGrp = New-MgBetaGroup -Description "Users of this group do not get security defaults" -DisplayName $AlyaNoMfaDefaultsGroupName -GroupTypes @() -MailNickname $AlyaNoMfaDefaultsGroupName -MailEnabled:$false -SecurityEnabled:$true
                $exlMfaDefaultsGroup = Get-MgBetaGroup -Filter "displayName eq '$AlyaNoMfaDefaultsGroupName'"
                if (-Not $exlMfaDefaultsGroup)
                {
                    throw "Group `$AlyaNoMfaDefaultsGroupName='$AlyaNoMfaDefaultsGroupName' not found!"
                }
            }
        } else {
            if ($null -ne $AlyaMfaDisabledGroupName -and $AlyaMfaDisabledGroupName -ne "PleaseSpecify") {
                $exlMfaDefaultsGroup = Get-MgBetaGroup -Filter "displayName eq '$AlyaMfaDisabledGroupName'"
                if (-Not $exlMfaDefaultsGroup)
                {
                    $exGrp = New-MgBetaGroup -Description "Users of this group do not get MFA prompts" -DisplayName $AlyaMfaDisabledGroupName -GroupTypes @() -MailNickname $AlyaMfaDisabledGroupName -MailEnabled:$false -SecurityEnabled:$true
                    $exlMfaDefaultsGroup = Get-MgBetaGroup -Filter "displayName eq '$AlyaNoMfaDefaultsGroupName'"
                    if (-Not $exlMfaDefaultsGroup)
                    {
                        throw "Group `$AlyaNoMfaDefaultsGroupName='$AlyaNoMfaDefaultsGroupName' not found!"
                    }
                }
            } else {
                Write-Warning "No group to exlude!"
            }
        }
        $params = @{
            SystemCredentialPreferences = @{
                ExcludeTargets = @(@{
                    "@odata.type" = "#microsoft.graph.featureTarget"
                    Id = $exlMfaDefaultsGroup.Id
                    TargetType = "group"
                })
            }
        }
        Update-MgBetaPolicyAuthenticationMethodPolicy -BodyParameter $params
    }

}

# Checking migration state
Write-Host "Checking migration state" -ForegroundColor $CommandInfo
if ($authenticationMethodPolicy.policyMigrationState -ne "migrationComplete") {
    Write-Warning "Please migrate to authentication policies!"
}

# Checking Authentication strengths
Write-Host "Checking Authentication strengths" -ForegroundColor $CommandInfo
$asPolicies = Get-MgBetaPolicyAuthenticationStrengthPolicy
$prmfaPolicy = $asPolicies | Where-Object { $_.DisplayName -eq "Phishing-resistant MFA" }
if (-Not $prmfaPolicy)
{
    throw "Authentication strengths 'Phishing-resistant MFA' not found!"
}
$prmfatapPolicyName = "Phishing-resistant MFA or TAP"
$prmfatapPolicy = $asPolicies | Where-Object { $_.DisplayName -eq $prmfatapPolicyName }
if (-Not $prmfatapPolicy)
{
    Write-Warning "  Authentication strength '$prmfatapPolicyName' not found. Creating it now."
    $prmfaPolicy.AllowedCombinations += "temporaryAccessPassOneTime"
    $params = @{
        DisplayName = $prmfatapPolicyName
        Description = "Include authentication methods that are phishing-resistant and the Temporary Access Pass (TAP)"
        AllowedCombinations = $prmfaPolicy.AllowedCombinations
        CombinationConfigurations = $prmfaPolicy.CombinationConfigurations
        PolicyType = $prmfaPolicy.PolicyType
        RequirementsSatisfied = $prmfaPolicy.RequirementsSatisfied
    }
    New-MgBetaPolicyAuthenticationStrengthPolicy -BodyParameter $params
}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC3ffnaDtRw7He5
# NG6lTRisDGwVQilFexnEH3pxzsDlAaCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILGG5UjqUQ/dYtpE
# d6GGyzFR3rNIRgf2cXzhF02sX4QxMA0GCSqGSIb3DQEBAQUABIICAJtU0+G0GvjU
# zI9EF8H2ey/gZLK6qlxIS4E9DwdpU4zktmt+VKLRvhoUro80lzxWebrl2t/OZ95Z
# 9/bgYGxwsxbQAriA1y5HbuZJdY3naQ0lkB3HWNgeWh5AiHyZQF8veArE/bKaBt9C
# vATG9kPg/Ewc1k4OttL/2kMvuh0Rw/6UQB42z8UqdzTZGUxxg2hKvzIdYaV9YMX7
# 1IOLVfJfpfLZNpUaEXLUXNDWlgKwwSGNYGCptY31ZybxYa8CwOnLE1MeW6rZohg/
# dntJr+W+uvCXlJQ8BON10h90CYG4AHcchb/PYPS8cKOccN59NCXOLUisv3GoRZmv
# HYgJP3+yoV4i/4rMCLvDMFghaVjFPSsUaZhK6RuhJcacYijrSOJvjqN9UA2R5tmF
# YVAbsbj7Nyh9DB2j37qrXZR/XZGADwvSpt/tqJXLSrSGYJ8jZ6ZyM0QutL7G4XLz
# 34Of9q694kRfYsfJm9XO2EXA8cFrQFX2JE1yqgaB1j+Uvw1JrCMmziUOLtHxwbRC
# tK6u6ewPIq5ONHtdFOR2ZCEfGkIapQrbR9PXjPN+HCzTzudkWpTfOoGqpjN9l4Ti
# pjhDXrwlARPPRR3p1r3nFa8U1nkF4Z6p630YSN8zZAON1tQQeBodmLON2D5MVR4a
# bZeKOtOWF4VZWcWDYlDqhqPtqOJB508YoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCAYun1DBSH7toumRVz/Za24VYMlilVjbq9A2TYqwclxlgIUDW9x9QZgHlZQ
# y9l3A5C38uDItBIYDzIwMjUwNjIyMTUyOTQ0WjADAgEBoFikVjBUMQswCQYDVQQG
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
# IIlJe5YCniEGIORDwtcbr2j7Jud6+7q46MOV9AhqtIcNMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAAYamx22dgcaR
# VJVzb4DG+ukl8O0RcgK4UPX+hjhy6T8aMNNQa7NqreQLOd50S4uS+mIFKJfPxc25
# oqIid/fibCtejlFW+WvVAFvP5e5g0hKTSVYuQ1j6bTWBTP/4vVlF72T05JXWA5VJ
# J178t/lV3a3NXm3ehyBWpk88T9/AjeVvMnIOyZ/LRW6dYqv0IROsHipxn4x0/DUu
# CS2Eo/ln5UaKiouiXKw92nmh8HSt/MGkY12xct3/fOkoVHPPLz5Js5UNoMX3yNA9
# wsJqM20GenxSd4tX6ITkdg0QOembK6uk73vK3zuTGqfjGk76/mFysWwfumJ0BGl6
# X+QHzi+ZyRndo9DSD1pfF4qoil73uvqIDDjVTJSlUwrU70WWywex7eIEx+PIbgCu
# KgcGMAcDUQEeHEjOI9uVfBR5zu/aK0Vy9jJD8fXgWqHxxWBoXfH09xPx1KaqY5FD
# LrDjPh3kXSQkpNE6tcANWQaGGKVMSPYbShYf4LuVFWSWl2e7qeQL
# SIG # End signature block
