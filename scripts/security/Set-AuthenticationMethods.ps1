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
foreach($key in $AlyaKeyAuthEnabledKeys)
{
    if ($Fido2AMC.AdditionalProperties.keyRestrictions.aaGuids -notcontains $key) {
        Write-Warning "  fido2 aaGuid $key was missing in aaGuids. Added now."
        $dirty = $true
    }
}
foreach($key in $Fido2AMC.AdditionalProperties.keyRestrictions.aaGuids)
{
    if ($params.KeyRestrictions.AaGuids -notcontains $key) {
        $params.KeyRestrictions.AaGuids += $key
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
# MIIvCQYJKoZIhvcNAQcCoIIu+jCCLvYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAGPNm6bPMJ8/eu
# KE2O5mfu+pG8xVRb8UpKCbceu/0ALqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMQxau/5
# +h30tXSphskr5WBt+Zg44EgroSAMHtxOj68PMA0GCSqGSIb3DQEBAQUABIICAEQS
# 95SbWB4KQHyoUHS1g5Fn6F9dXbi6+Ki0oxpoGPlKkhfVxPm7bOWyud4k35FNPmMr
# AGb8TCZO/aSY3xQJBUOWiS3txiyDy8Gpl1kM7ApsxouZDAr7FPSlpGafIqKFiRdA
# X+g9e0hBATnBilOFNQXStUIA6HNg4M1EH3ed6F8qG4DFLvG4FdmGOlpmhPNFHysv
# Niw4Hy4/QASzkf0HgrcqZ4Fl99DQAPMs4gb2VpqsGYp32Ay4TU9+aVgKEzRLgwSJ
# 1TLyxEu9LUuu7JjfYcgZ7HiBrF24ArJhKIVr6sFoHfzMJptBjPIAqzhubOfE2RkJ
# 7tDgNsjflo+Y4IA7I5ZbPZiCmDtjSwIUqTXbMWbj0ivjIeA3OyvIC055SgAelC1N
# RyapbdmoJlqnpawzlr+2/i4oqB4N2TI65zayGfti/Tbq7Czb1o/x/TfFnDLEN7zY
# We4nEm4MAFdzLcGRor6Bg2n7zqSEXTImT4tnmpKZwjPxGWmtOtzFM2jjwfO1g8QW
# CoSk7IFhLy2QKdpO90XwZWL0Kj13CepxOguLQib3sdbZVztEcFSwfP+GMA3R0SK2
# cbxuNWnU1xjqzBrE++3NxTTKZNZgTNwVeqkoV4AGvszrFTYCsAkeKTL8IccUijvo
# F81rUZYUyVEd4f1SuLlUkyRt9qAKpFRN/mQidCJmoYIWuzCCFrcGCisGAQQBgjcD
# AwExghanMIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEw
# gd8GCyqGSIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCBSqEH6zKNs3ZWsW2vnGY02UrROHI0ttk9caAoTZCQg+gIUHrHq
# hGzI/NyFUcPz9Osaec6xbPoYDzIwMjUwNTIxMjEyNzU4WjADAgEBoFikVjBUMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwh
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMC
# AQICEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNp
# Z24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5
# WhcNMzQxMjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFs
# U2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWdu
# MSAtIFI2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4
# PuCF6+aqCj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb
# 5gk0Xydy3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJSc
# RV1W6/6efi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy
# 5RJY+o1NWhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY
# 0Lie04DuKbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2Z
# wbI6yiFHaS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYh
# KUlrMH9+2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5s
# WtX1qvCzk6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGo
# MIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYD
# VR0OBBYEFIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQC
# MEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSB
# gzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2Ev
# Z3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2Jh
# bHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaA
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9j
# cmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG
# 9w0BAQwFAAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26
# IFq7fQMIrN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76Tkv
# L+v2f4mHolGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftP
# ttS+G/MhNUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIl
# S3Ki74CU15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt
# 8DT4RQj9LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5
# lgJkgXEc1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD
# 9hQchjiGkyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71
# yzGKWnbAWQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGL
# ZtJFJzGJD7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVA
# GXCqHsh62QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZ
# MIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAw
# MDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOv
# dYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt
# 0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHP
# vIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFU
# UweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16
# ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS
# 2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm1
# 9m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIG
# bxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMD
# Ad6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/Miy
# Tdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9
# GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGG
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDD
# vWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEB
# BDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jv
# b3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29t
# L3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0B
# AQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYW
# axlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCy
# z+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQ
# cXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0
# Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59e
# odaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8
# oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1
# If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbcl
# IA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2M
# tnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB
# +SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIID
# a6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQL
# ExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjET
# MBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAw
# MDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQK
# EwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4
# QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTe
# c5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWy
# ZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7tt
# U+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrK
# otudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKF
# t3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTfl
# puwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2Fm
# CWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5
# paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4O
# hxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwo
# TK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki
# 5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnm
# XNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJE
# lrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMp
# mY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6
# JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG
# 7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/
# gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324G
# abbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5
# MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO7
# 7oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4st
# Q1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjx
# guhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJ
# YIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZI
# hvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcN
# AQkEMSIEIHh8OfCnnPXSJkb5KzPPMRFxSSlZWS06ojI2lfeb9PLpMIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1or
# d69gXP0wczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAILR8
# 5D829bj8nBl2FgcsajUJrHae/WgBHq1+OFhE7tWemI3YyL8OyOgojeB4i4o2Cao9
# 0JIXjJQ5eVlu3XIMrUO+6q4ABVO6/CQU71bbRuVpCfqoe9iUKaoFpyEn3Jo27phE
# cQ2NmNkRF4xh1GwlvmD276FeL1AvqPhXadxABQmwVIcYHtcdxH1wr1X2Qz0xlilb
# yUYJQNeyeB6i/MP9hrFUnYpuWzo5rwMrxUZQRu1vW4o9hrsLk3gLEfcrzkjFbvYT
# aZ6i/InWXmkgYfkcEiWI6G4Dswgkdu9dxrcfc6UyG5R5vyTKjHFqKIG95MThZBK/
# H+rHut/KQF4I4iAEsTCBhgzyyA174PVx30YQMeSPfHA+FnH/W7tZkBapuZUQtj9g
# Q45L75LHkH7wmeG3Jdlou8mq6YjppLgPLdGl9bxvK/mA+AH9dkj4mIom7YamCHST
# wdE6AibLXgWloaL3rRwFIveMwwCaf9WYY/9rX7NLZ8m7vEouE85kSg7UR67W
# SIG # End signature block
