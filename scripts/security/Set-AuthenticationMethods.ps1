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

#>

[CmdletBinding()]
Param(
    [bool]$minimalConfig = $true,
    [bool]$conditionalAccessEnabled = $true
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
