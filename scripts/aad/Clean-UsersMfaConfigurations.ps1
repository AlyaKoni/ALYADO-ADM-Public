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
    17.08.2026 Konrad Brunner       Initial Version

#>

<#
.SYNOPSIS
Cleans the Multi-Factor Authentication (MFA) configuration of all Azure AD users.

.DESCRIPTION
The Clean-UsersMfaConfigurations.ps1 script connects to Microsoft Graph, retrieves a list of all Azure Active Directory users, and collects detailed information about their MFA registration, authentication methods, and sign-in preferences. The gathered data is then used to clean configured methods. The script ensures that all required modules are installed, handles authentication, and logs its operations.

.INPUTS
None. The script does not take pipeline input.

.OUTPUTS
None. The script does not produce any output.

.EXAMPLE
PS> .\Clean-UsersMfaConfigurations.ps1

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Clean-UsersMfaConfigurations-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ImportExcel"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Reports"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Directory.ReadWrite.All", "Policy.Read.All", "UserAuthenticationMethod.ReadWrite.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Clean-UsersMfaConfigurations | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting AuthenticationMethodPolicies
Write-Host "Getting AuthenticationMethodPolicies" -ForegroundColor $CommandInfo
$authenticationMethodPolicy = Get-MgBetaPolicyAuthenticationMethodPolicy
$Fido2AMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Fido2" }
$MicrosoftAuthenticatorAMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "MicrosoftAuthenticator" }
$SmsAMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Sms" }
$VoiceAMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Voice" }
$EmailAMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Email" }
$HardwareOathAMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "HardwareOath" }
$SoftwareOathAMC = $authenticationMethodPolicy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "SoftwareOath" }

# Getting users
Write-Host "Getting users" -ForegroundColor $CommandInfo
$users = Get-MgBetaUser -Property "*" -All

# Cleaning unused methods
Write-Host "Cleaning unused methods" -ForegroundColor $CommandInfo
foreach($user in $users)
{
    Write-Host "$($user.UserPrincipalName)"
    try {
        $methods = Get-MgBetaUserAuthenticationMethod -UserId $user.Id
    }
    catch {
        Write-Warning "  Failed to get user authentication methods for $($user.UserPrincipalName): $($_.Exception.Message)"
        continue
    }
    try {
        $signInPref = Get-MsGraphObject -Uri "https://graph.microsoft.com/beta/users/$($user.Id)/authentication/signInPreferences"
    }
    catch {
        Write-Warning "  Failed to get user signin preferences for $($user.UserPrincipalName): $($_.Exception.Message)"
        continue
    }
    $prefMethUser = $signInPref["userPreferredMethodForSecondaryAuthentication"]
    $prefMethSystem = $signInPref["systemPreferredAuthenticationMethod"]
    $confMethSms = $methods | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.smsAuthenticationMethod"}
    $confMethPhoneOffice = $methods | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.phoneAuthenticationMethod" -and $_.AdditionalProperties.phoneType -eq "office" }
    $confMethPhoneMobile = $methods | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.phoneAuthenticationMethod" -and $_.AdditionalProperties.phoneType -eq "mobile"}
    $confMethPhoneMobileAlt = $methods | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.phoneAuthenticationMethod" -and $_.AdditionalProperties.phoneType -eq "alternateMobile"}
    $confMethEmail = $methods | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.emailAuthenticationMethod"}
    $confMethVoice = $methods | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.voiceAuthenticationMethod"}
    $confMethFido2 = $methods | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.fido2AuthenticationMethod"}
    $confMethSoftwareOath = $methods | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.softwareOathAuthenticationMethod"}
    $confMethMicrosoftAuthenticator = $methods | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"}

    if ($Fido2AMC.State -ne "enabled" -and $confMethFido2)
    {
        Write-Host "  Removing FIDO2 method"
        try {
            Remove-MgBetaUserAuthenticationFido2Method -UserId $user.Id -Fido2AuthenticationMethodId $confMethFido2.Id
        }
        catch {
            Write-Warning "  Failed to remove FIDO2 method for $($user.UserPrincipalName): $($_.Exception.Message)"
        }
    }
    if ($MicrosoftAuthenticatorAMC.State -ne "enabled" -and $confMethMicrosoftAuthenticator)
    {
        Write-Host "  Removing Microsoft Authenticator method"
        try {
            Remove-MgBetaUserAuthenticationMicrosoftAuthenticatorMethod -UserId $user.Id -MicrosoftAuthenticatorAuthenticationMethodId $confMethMicrosoftAuthenticator.Id
        }
        catch {
            Write-Warning "  Failed to remove Microsoft Authenticator method for $($user.UserPrincipalName): $($_.Exception.Message)"
        }
    }
    if ($SmsAMC.State -ne "enabled" -and ($confMethSms -or $confMethPhoneMobile))
    {
        if ($prefMethUser -eq "sms")
        {
            Write-Host "  Trying to set preferred method to push"
            try {
                Update-MgBetaUserAuthenticationSignInPreference -UserId $user.Id -BodyParameter @{ userPreferredMethodForSecondaryAuthentication = "push"; }
            }
            catch {
                Write-Host "  Trying to set preferred method to oath"
                try {
                    Update-MgBetaUserAuthenticationSignInPreference -UserId $user.Id -BodyParameter @{ userPreferredMethodForSecondaryAuthentication = "oath"; }
                }
                catch {
                    Write-Host "  Resetting preferred method to system preferred"
                    try {
                        Update-MgBetaUserAuthenticationSignInPreference -UserId $user.Id -BodyParameter @{ isSystemPreferredAuthenticationMethodEnabled = $true; userPreferredMethodForSecondaryAuthentication = $prefMethUser; }
                    }
                    catch {
                        Write-Warning "  Failed to reset preferred method for $($user.UserPrincipalName): $($_.Exception.Message)"
                    }
                }
            }
        }
        if ($confMethSms) {
            Write-Host "  Removing SMS method"
            try {
                Remove-MgBetaUserAuthenticationPhoneMethod -UserId $user.Id -PhoneAuthenticationMethodId $confMethSms.Id
            }
            catch {
                Write-Warning "  Failed to remove SMS method for $($user.UserPrincipalName): $($_.Exception.Message)"
            }
        }
        if ($confMethPhoneMobileAlt) {
            Write-Host "  Removing Alt Phone method"
            try {
                Remove-MgBetaUserAuthenticationPhoneMethod -UserId $user.Id -PhoneAuthenticationMethodId $confMethPhoneMobileAlt.Id
            }
            catch {
                Write-Warning "  Failed to remove alternate mobile phone method for $($user.UserPrincipalName): $($_.Exception.Message)"
            }
            $confMethPhoneMobileAlt = $null
        }
        if ($confMethPhoneMobile) {
            Write-Host "  Removing Phone method"
            try {
                Remove-MgBetaUserAuthenticationPhoneMethod -UserId $user.Id -PhoneAuthenticationMethodId $confMethPhoneMobile.Id
            }
            catch {
                Write-Warning "  Failed to remove mobile phone method for $($user.UserPrincipalName): $($_.Exception.Message)"
            }
            $confMethPhoneMobile = $null
        }
    }
    if ($VoiceAMC.State -ne "enabled" -and ($confMethVoice -or $confMethPhoneOffice -or $confMethPhoneMobileAlt))
    {
        if ($prefMethUser -eq "voiceMobile" -or $prefMethUser -eq "voiceAlternateMobile" -or $prefMethUser -eq "voiceOffice")
        {
            Write-Host "  Trying to set preferred method to push"
            try {
                Update-MgBetaUserAuthenticationSignInPreference -UserId $user.Id -BodyParameter @{ userPreferredMethodForSecondaryAuthentication = "push"; }
            }
            catch {
                Write-Host "  Trying to set preferred method to oath"
                try {
                    Update-MgBetaUserAuthenticationSignInPreference -UserId $user.Id -BodyParameter @{ userPreferredMethodForSecondaryAuthentication = "oath"; }
                }
                catch {
                    Write-Host "  Resetting preferred method to system preferred"
                    try {
                        Update-MgBetaUserAuthenticationSignInPreference -UserId $user.Id -BodyParameter @{ isSystemPreferredAuthenticationMethodEnabled = $true; userPreferredMethodForSecondaryAuthentication = $prefMethUser; }
                    }
                    catch {
                        Write-Warning "  Failed to reset preferred method for $($user.UserPrincipalName): $($_.Exception.Message)"
                    }
                }
            }
        }
        if ($confMethVoice) {
            Write-Host "  Removing Voice method"
            try {
                Remove-MgBetaUserAuthenticationPhoneMethod -UserId $user.Id -PhoneAuthenticationMethodId $confMethVoice.Id
            }
            catch {
                Write-Warning "  Failed to remove voice method for $($user.UserPrincipalName): $($_.Exception.Message)"
            }
        }
        if ($confMethPhoneOffice) {
            Write-Host "  Removing Phone method"
            try {
                Remove-MgBetaUserAuthenticationPhoneMethod -UserId $user.Id -PhoneAuthenticationMethodId $confMethPhoneOffice.Id
            }
            catch {
                Write-Warning "  Failed to remove office phone method for $($user.UserPrincipalName): $($_.Exception.Message)"
            }
        }
        if ($confMethPhoneMobileAlt) {
            Write-Host "  Removing Alt Phone method"
            try {
                Remove-MgBetaUserAuthenticationPhoneMethod -UserId $user.Id -PhoneAuthenticationMethodId $confMethPhoneMobileAlt.Id
            }
            catch {
                Write-Warning "  Failed to remove alternate mobile phone method for $($user.UserPrincipalName): $($_.Exception.Message)"
            }
        }
    }
    if ($SoftwareOathAMC.State -ne "enabled" -and $confMethSoftwareOath)
    {
        Write-Host "  Removing Software OATH method"
        try {
            Remove-MgBetaUserAuthenticationSoftwareOathMethod -UserId $user.Id -SoftwareOathAuthenticationMethodId $confMethSoftwareOath.Id
        }
        catch {
            Write-Warning "  Failed to remove software OATH method for $($user.UserPrincipalName): $($_.Exception.Message)"
        }
    }
    if ($HardwareOathAMC.State -ne "enabled" -and $confMethHardwareOath)
    {
        Write-Host "  Removing Hardware OATH method"
        try {
            Remove-MgBetaUserAuthenticationHardwareOathMethod -UserId $user.Id -HardwareOathAuthenticationMethodId $confMethHardwareOath.Id
        }
        catch {
            Write-Warning "  Failed to remove hardware OATH method for $($user.UserPrincipalName): $($_.Exception.Message)"
        }
    }
    if ($EmailAMC.State -ne "enabled" -and $confMethEmail)
    {
        Write-Host "  Removing Email method"
        try {
            Remove-MgBetaUserAuthenticationEmailMethod -UserId $user.Id -EmailAuthenticationMethodId $confMethEmail.Id
        }
        catch {
            Write-Warning "  Failed to remove email method for $($user.UserPrincipalName): $($_.Exception.Message)"
        }
    }
}

# Stopping Transcript
Stop-Transcript

# SIG # Begin signature block
# MII2OgYJKoZIhvcNAQcCoII2KzCCNicCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBmtlSzwXBEEqn/
# HFkTyNJfUb93viS94eJCcPnu+X1eP6CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# trofETAxgiEFMIIhAQIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMr5xikJ
# k/n3u67R0mEY46AHbUn23Zk2U94mC5R3O9r7MA0GCSqGSIb3DQEBAQUABIICACqx
# b2fcm0/j6n5v/nY9tFvBp7+v5+L8eIaRfv47Tha10Rd3ZK0PglrxxnIFxlo24VNH
# QA8fsfbHrj4LFPjL9PzPKN9J5YsTYk1magPrEvyACPS9PInLDgLpA/TeMMpozp6S
# q6jJSXHvaHLlJIRlUeyAqVxFfczfbvWJGpmxj9klJyvHxl90p92Pvv2aPiCwnAK8
# r7c15+vmVPPquwISyexLVN9aItVJKYarhSv1p+WyILCxKxgaCdiSBqHoI5UMqwYK
# o0ym4TISecmcMLTXrJSuVb2Q6pzNFm1cUmZTA9NuJm/i1EWTJepnqgsEy4npFznC
# ScM+SMYeAGnwFuWm6j7hRszOvZAwjRs38ANiRdCqMCjr6ZLQAIwUYcbzEDbZW/7b
# VWsIjrchnrl6OuwOEBnec/lHSRLbeWYXffns2RvN8VFWGQa7x/IqBWCaLfy3su6b
# 3Rx3udJJRscTnE1G0WpZEjDSN+hqpcBVgBqgascHUJNhiWndb+Gh+eXUCOimWkOA
# NbV3cIVbpvfeBhdapBXeIzKAip4+1S/0QNxbogYIJJ+jRvk6a5l1QoH7QWZA5m4z
# 6y2QsLBP6gaYXYSBweXqDyKbfAKicnAeDsLs+6f16jRzpUfdUX6UtHgfDW0qJQuC
# sjmDjHNg7jMz/xUFQLXD8SOjXi/J1wMawUPN5NEhoYId7DCCHegGCisGAQQBgjcD
# AwExgh3YMIId1AYJKoZIhvcNAQcCoIIdxTCCHcECAQMxDTALBglghkgBZQMEAgIw
# geMGCyqGSIb3DQEJEAEEoIHTBIHQMIHNAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCAe6TGjYkXEy7i+S4yYMgi7zjW8XobC3owSBsYRu45PsgITBRxh
# 1fUbg5fGdaRyb+PuwvmzBxgPMjAyNjA4MTcxNDMwMzZaMAMCAQGgXaRbMFkxCzAJ
# BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS8wLQYDVQQDEyZH
# bG9iYWxzaWduIFI0NSBUU0EgZm9yIENvZGVTaWduIDIwMjUxMKCCGWAwggaKMIIE
# cqADAgECAhEAhHI/wZXMFvHbK6L2YN8r5DANBgkqhkiG9w0BAQwFADBeMQswCQYD
# VQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xv
# YmFsU2lnbiBPZmZsaW5lIFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNTAeFw0yNTEw
# MTUwNzI1MDRaFw0zNzAxMTAwMDAwMDBaMFkxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMS8wLQYDVQQDEyZHbG9iYWxzaWduIFI0NSBUU0Eg
# Zm9yIENvZGVTaWduIDIwMjUxMDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoC
# ggGBANFKjaGNhkBIKKMJBJzZExA88qiMT/F/hSKNrYmewntKeXaAOjEqND0dxTqt
# UPymDLWwEp1XG0ssWFjeDNj88DaLAizpnMKfGyG2NKGw3VHLNGvNzgWr7TFDHqoA
# NQyf3qaocT/SiTncM9uakGSRQPK0Yzv2dB/D1ZXKZiAD5ORsDT9A6Y800khnoKNf
# S3fAl+EvRxqJe2EEEwRYrFPm/ZTtlFsKr8NUNcD2hfWIVUFVoGnHnswsvTSfIe7H
# QidhLtGvngze02Gbv7SZrGnJMVrnW5jU8e1Mky6n+XdEaihDljB4IfaEOhQ3Ao4L
# tCQVuSWE92rbsReS56Dyos6dEOZU7Wv4HXIwBuXpC5XQv448HVIoEA+mYgWSWYnR
# KiJttSrGxPN6ON0j7LBAtRxeKWiDApawnjqHrCOVTkBWpPsUQFjNYJO3qF/tItBs
# 8azTYFryhpo1+jRIv5oCk33iW4QH/C4TWWCm2tyQvNtCUKnno6CQAlimpi66L5N+
# 54IhTQIDAQABo4IBxjCCAcIwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoG
# CCsGAQUFBwMIMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDL60+EHaCeQawjSPx08
# jGU2KAYZMB8GA1UdIwQYMBaAFHcCOwExDx50d8NIyMMHY1WIpTuiMIGlBggrBgEF
# BQcBAQSBmDCBlTBCBggrBgEFBQcwAYY2aHR0cDovL29jc3AuZ2xvYmFsc2lnbi5j
# b20vZ3NvZmZsaW5lcjQ1dGltZXN0YW1wY2EyMDI1ME8GCCsGAQUFBzAChkNodHRw
# Oi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc29mZmxpbmVyNDV0aW1l
# c3RhbXBjYTIwMjUuY3J0MEoGA1UdHwRDMEEwP6A9oDuGOWh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vZ3NvZmZsaW5lcjQ1dGltZXN0YW1wY2EyMDI1LmNybDBWBgNV
# HSAETzBNMAgGBmeBDAEEAjBBBgkrBgEEAaAyAR4wNDAyBggrBgEFBQcCARYmaHR0
# cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQEM
# BQADggIBAI6ucKaPR4aRim6eLPr9YWb3WzoqOeGQwpiVtx+2CkwG2WHKxWeIQ58G
# +Fy+gVDDgA4cb01FW9mmQGdqDkO3UczcmDbWBFUIHAXI/URPwgPGh+VjHk4PhII0
# sezq8KDqsWQ1PzW/1nLy7TFfLdZug3mIr9JtOYsaoKsAYmKEsut8iG913BWt0HKI
# e14vGCO6BPolCiAJKgEXYmqYfRkEKXnXlu1tO5ZkutBSzm++Xaj3wx2O73LIlFYv
# M9VxSRGT13zEEGLrfwUE4C6jd9zJOEZyd7vBQ5r5OCGHAgdtnenFNimCjlwLERmw
# fwRfCJNRPAd/Sp6yyyD/Zd1wYfuzQBHhPI4nZCcBrJg4Az9c4HE3NRFCDiaEx08v
# 8XxUIwqPeSglpVzHZqSHQHzaV79oFTyrY5r747A7CIcXl75/2b7KHJhvAZKiBYhX
# eGBGX5XIqtyHyC/fkUev9xXPyfT8I8ZFcaJglns/XA46Bh2QwPaIMpVhBvLkjH/E
# IHT+VIoueoSgV7N+acIlsaAAJWzAyzGEkRSO3ERxBz1p9qWd74g62zS//IJGKQmy
# eZVtLTHnQOTY4f5UKJT2z9fLOB8LtbOu1Dl2Ih1zYqyLckxMmbhrQuIQhlaK0Pn7
# o+iQ6RDz7flOwc7BSGzzsj/LImOUhmkBXg5/X8k3xtZUHcR2bhbOMIIGoDCCBIig
# AwIBAgIRAIPahje3nwyEDJR7hApSeB8wDQYJKoZIhvcNAQEMBQAwUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gVGltZXN0YW1waW5nIFJvb3QgUjQ1MB4XDTI1MDcxNjAzMDUwNFoXDTQx
# MDcxNjAwMDAwMFowXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1w
# aW5nIENBIDIwMjUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCkdxb4
# 7X2L4t0ChkVjNL7lf5Zi+dagWpcB+KvWHKeFRN0fhFbUNv7I6atDbvmOWxDpvOhn
# ec3QIydxlfgTRCGmnpC/Hbv5+Wl/N4xBpwPtVyJZSIXdMuK7vBPZsEJIQ1SfeF8Y
# wbg8m9gW87mjgMDWI28eEbihLNy2h2gl9vhzwSNVqELD80uLMHetr41Z7aBkFJpk
# qtozEW3rvrKrHtFxCeNsXhHQ4sai+xm3be9Tr0DkF2g/F0D3O72sz6pMGw8NVQl7
# FjARVTQZjsEnmZRZaeLIA8dbRa/gDOTm3sjRdQiMDf7Y4aSvR1UFdUEPIR4YFWth
# cR2F9UvC6HocEYkV0isRjkqgaWmhP7gEFB7hcIfmy/XlSj4zvZUpaM8DkTHed8Uk
# Lg/kVbVJHqiUJJoiu2dnNz7OCalLKIP4ZwTa51BFAdsOLvh6deBrOTT6S2kdnVny
# hO9JpIhESi9dItsfcoLy4UiRe5yXtc8ftkYiuYX14XjO6ijkUhSey9XrSQuoUPM+
# T5RsuaBkNQI+UUUEF6Fpo2+LETKbH043Ypd6/4x8ro5kKGoZus4LbC+8AUfIqVNl
# tUd2o2K7S7lrZPUL11JNGfLX+HEvBzEv0FY/NAvCGyLJepTMzu4PSUP349gxrFRi
# ChVLGpvjG88KJWos1psj5a2MTNh9DQ/7q0FMWwIDAQABo4IBYjCCAV4wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBIGA1UdEwEB/wQIMAYBAf8C
# AQAwHQYDVR0OBBYEFHcCOwExDx50d8NIyMMHY1WIpTuiMB8GA1UdIwQYMBaAFEay
# HHfhexXwpTmhcN7RxC7qbbLeMIGOBggrBgEFBQcBAQSBgTB/MDcGCCsGAQUFBzAB
# hitodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1MEQG
# CCsGAQUFBzAChjhodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC90
# aW1lc3RhbXByb290cjQ1LmNydDA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
# Lmdsb2JhbHNpZ24uY29tL3RpbWVzdGFtcHJvb3RyNDUuY3JsMBEGA1UdIAQKMAgw
# BgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAgEAMqPuftFu5GYxllheqUw9EmhHpfWf
# /+q5cYtV86kWhH1hrTkv3jDTLAGN6XIYZ/6cAH4JkVDuBQ53ZrZul+lbxfDkCsz5
# iM8R/wC0LgTpivXTlTVg2OVNIRGhYkpzWGRI3mbh2mxi14XKTMVBXBfnSFgoffJn
# pVy7odrQQDmh/MumLaMraNtEMJdsU0uLmY7XEpF0HYDMAXR/kLTRvgfd3mwI4Hye
# NO8DBpMwYQx5OQtYzhn1j7dQ606mjVC7FdsOldWQtetobbmIvVW2+PEQDLjnfidQ
# g0H3CE5GJwklJMttrp84rZ//VAZYR17BYscDMT43mgfRCg1EAuknkmMh94ie876x
# B0GJ2c+4son3kdOPtfIy8mEVmO1sckaURbHhSApy40osMtdYAt/BAM3YN7LeRN93
# jLDidB2TU9y0ssrcXgvaecu/3gEySlj5F+Xneg4Q3jJO+3AJg/5UO5muS1zs1pyh
# NXFmcoaS/xrVqRyR07BBkL6LwDLVXLMwBf9Nvj6vdzrkHtykC2rc6hSKNdQmC9nF
# yLpNfvyyYvZNjLa1af7wbiSude/LYQtHZdicoQ5LgxWatIKyMzmfFKuCETXRUNdB
# sR9r3eWGKR8Wgi4g0rNYMuq+7xm5ybES5/GkeM2edFVdf9m/kpCrym78xCg7PoML
# vifn47ltLC9PmyAwggajMIIEi6ADAgECAhB4SqqBc2ackAlU5CHJR+vAMA0GCSqG
# SIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMw
# EQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTIwMTIw
# OTAwMDAwMFoXDTM0MTIxMDAwMDAwMFowUzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAunQz
# 7CfcEjghG8XTYSjWWrxP34vMkYRDJFe8ZCG8OxwfPU+MrQe388XXAukRFIKaqrSU
# cjtxDRrvaGuFeY6vZupYmA26wXx50v/Ns28xRdAFdAQAcmonfrg3PzqI7ZeD9as1
# TQ+fWTv1L99ZxXylMnZglsjt7vgEfhlRcqi/REF6vHseOwCbvLrglr+Q/o2bw3KL
# ABL4IDpgOPfBzIWK+4d5LqErIObLoIWRI7bEKAdUKN7sEDFPivLNFB8e3VUc6igx
# TPkhaqjN85Zn+gFBm80PC2h/u97xQ+oX5bDccCKzaTZZdGvG5YkqfOULgV2rP4+4
# 0XZy83yiqeKXQb/MjEX+Ycn2bAcLAAToFSNPgiot9u/D+hE2SKHR/Xo5OjRdoywO
# m3dQIDRA3bEDMa1f6WKHc5YDYfeUsNlcbE/nFMXh8XsNI5zNcIwdat5KLYsqu9tC
# FAUHqvsU3DHT9h9sy75oZkRwTW0X+XHrBXOOkZJ162hcHvZEYRgpYt0XZojsKLpJ
# b9s+d/65MR91HBiipke92O5IhTv9s+IPPyqYxpr6gm+xpaWGHVo6+qRsdA93UmFq
# f4cp3jmbi+6zRWAwJJcVEiqFMJMmrJamLehwbQupMq0smygKdkLyVWFRmJTe7fbF
# F288FRCwDq2w3sUW9GXRzC9aVgjPmcTwVZHCLHkCAwEAAaOCAXgwggF0MA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDAPBgNVHRMBAf8EBTADAQH/
# MB0GA1UdDgQWBBRGshx34XsV8KU5oXDe0cQu6m2y3jAfBgNVHSMEGDAWgBSubAWj
# kxPioufi1xzWx/B/yGdToDB7BggrBgEFBQcBAQRvMG0wLgYIKwYBBQUHMAGGImh0
# dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjYwOwYIKwYBBQUHMAKGL2h0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L3Jvb3QtcjYuY3J0MDYG
# A1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1y
# Ni5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8v
# d3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4IC
# AQCLSLo2Vzxyxdp1+e8y9Ya93BIo44guTzZfJpnsDwEhEJaSOMZwa23zrtQOvSXv
# hn/iiY2VpX4pRANNqpio8bfc6iljIdztzYgKyxBpYXkpQgwjvOnF71IeLzM31U9m
# emapR1Qzsd0W8thkcaMxlOVv9k1L4oRs0MklZ0/IS9DOSwXWPft9QfqKscAh4H4I
# sNlkK/nq8scK9M8uDDRg7my7kvA/8XtSEmh3WYH1HC6kOow5Aw3t5cyvZkh5Y9VJ
# uP9L0iVPSE6TO5N3sJpIbLagHbN0nl+9IgQ7fDcNhbXDmrvdnFoDjbQNn0x2NNWF
# rUV7tZ+7Lom7rMi/kmNIxj/KF6oNvAARX4vo40OEikM0zf07wKJ72x+4Z8iMFd4/
# pn/HKO+hb2+yQc8CIusB+EvI0nZvJd9e2mhoPXtEBMJBbkk7p5hWBO3RJisElNvk
# 7WaOPYCdpKRVeVBe4/gaH8AWb5AVPIqmSKEMe7oq4LGphwVGm+0lVT03aZjtRpmY
# hUcKHmLb/ZzlwUNCjr3Pb/aMkf2C5J/sreOVVQXzSS9tNPf/Z+6ZQLvTmoBCQNoj
# iWAfg3GStenmygr53cdsslhBnGaNmypvH29XBENcg107aZzeOfqETTXzextti/Fv
# A8EpUuKUv3tUi99AegtwAnc/L4gHAgB10q/G1iIyGaM76DCCBYMwggNroAMCAQIC
# DkXmuwODM8OFZUjm/0VRMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2Jh
# bFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQD
# EwpHbG9iYWxTaWduMB4XDTE0MTIxMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowTDEg
# MB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2Jh
# bFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQCVB+hzymb57BTKezz3DQjxtEULLIK0SMbrWzyug7hBkjMUpG9/
# 6SrMxrCIa8W2idHGsv8UzlEUIexK3RtaxtaH7k06FQbtZGYLkoDKRN5zlE7zp4l/
# T3hjCMgSUG1CZi9NuXkoTVIaihqAtxmBDn7EirxkTCEcQ2jXPTyKxbJm1ZCatzEG
# xb7ibTIGph75ueuqo7i/voJjUNDwGInf5A959eqiHyrScC5757yTu21T4kh8jBAH
# OP9msndhfuDqjDyqtKT285VKEgdt/Yyyic/QoGF3yFh0sNQjOvddOsqi250J3l1E
# LZDxgc1Xkvp+vFAEYzTfa5MYvms2sjnkrCQ2t/DvthwTV5O23rL44oW3c6K4NapF
# 8uCdNqFvVIrxclZuLojFUUJEFZTuo8U4lptOTloLR/MGNkl3MLxxN+Wm7CEIdfzm
# YRY/d9XZkZeECmzUAk10wBTt/Tn7g/JeFKEEsAvp/u6P4W4LsgizYWYJarEGOmWW
# WcDwNf3J2iiNGhGHcIEKqJp1HZ46hgUAntuA1iX53AWeJ1lMdjlb6vmlodiDD9H/
# 3zAR+YXPM0j1ym1kFCx6WE/TSwhJxZVkGmMOeT31s4zKWK2cQkV5bg6HGVxUsWW2
# v4yb3BPpDW+4LtxnbsmLEbWEFIoAGXCDeZGXkdQaJ783HjIH2BRjPChMrwIDAQAB
# o2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
# rmwFo5MT4qLn4tcc1sfwf8hnU6AwHwYDVR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfw
# f8hnU6AwDQYJKoZIhvcNAQEMBQADggIBAIMl7ejR/ZVSzZ7ABKCRaeZc0ITe3K2i
# T+hHeNZlmKlbqDyHfAKK0W63FnPmX8BUmNV0vsHN4hGRrSMYPd3hckSWtJVewHuO
# mXgWQxNWV7Oiszu1d9xAcqyj65s1PrEIIaHnxEM3eTK+teecLEy8QymZjjDTrCHg
# 4x362AczdlQAIiq5TSAucGja5VP8g1zTnfL/RAxEZvLS471GABptArolXY2hMVHd
# VEYcTduZlu8aHARcphXveOB5/l3bPqpMVf2aFalv4ab733Aw6cPuQkbtwpMFifp9
# Y3s/0HGBfADomK4OeDTDJfuvCp8ga907E48SjOJBGkh6c6B3ace2XH+CyB7+WBso
# K6hsrV5twAXSe7frgP4lN/4Cm2isQl3D7vXM3PBQddI2aZzmewTfbgZptt4KCUhZ
# h+t7FGB6ZKppQ++Rx0zsGN1s71MtjJnhXvJyPs9UyL1n7KQPTEX/07kwIwdMjxC/
# hpbZmVq0mVccpMy7FYlTuiwFD+TEnhmxGDTVTJ267fcfrySVBHioA7vugeXaX3yL
# SqGQdCWnsz5LyCxWvcfI7zjiXJLwefechLp0LWEBIH5+0fJPB1lfiy1DUutGDJTh
# 9WZHeXfVVFsfrSQ3y0VaTqBESMjYsJnFFYQJ9tZJScBluOYacW6gqPGC6EU+bNYC
# 1wpngwVayaQQMYIDYTCCA10CAQEwczBeMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5lIFI0
# NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwCwYJYIZI
# AWUDBAICoIIBQTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcN
# AQk0MR4wHDALBglghkgBZQMEAgKhDQYJKoZIhvcNAQEMBQAwPwYJKoZIhvcNAQkE
# MTIEMM/VLqIXQZ65ZnKzyPPlm5emlgAYSMpofPglAjkztuxQNofFKkOWfnm9NzSv
# rmRWnTCBtAYLKoZIhvcNAQkQAi8xgaQwgaEwgZ4wgZsEIIMq1y5SP96sg/pGlLzn
# xswmF2SIKGZWZYjIrco6g4VRMHcwYqRgMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUg
# UjQ1IFRpbWVzdGFtcGluZyBDQSAyMDI1AhEAhHI/wZXMFvHbK6L2YN8r5DANBgkq
# hkiG9w0BAQwFAASCAYC0Lzhx8uZgooZBcxHCe0m89kdFo0U+O9yYawVUix35iBOJ
# cEIA27+YvM77UwBL2smBZiyuh7kL5jnctUse14ZeX3S4DeMGnbQqsfSaduo2hOOC
# bIL6N9Kl4aB+1Z9RRdERd0uFUxKNDBb4sQxWhQRbfk+uCxmxskWdsbDeqx3pi8En
# mPiVqDGabtAu/V5hyMGq7DbljNxgCuNlhuDePTwEpg6D3tvx5EWDl/Ckq1FCpl41
# PiH9dm3ftW1nEWlip900YT98M5FF82bkbwqld4JszQW97nweeCss3jaAhcN1Xugh
# 60V1FFI0t9SDynuORxWtbdsEY3C6o4CP7aaGCMp13k9YKL0guYOLAkS8nawAQ3hd
# 3CIdrGbGyYc1DVjzk01DuhGK1UPZpIwvAkcVHodYHkpTuh8Vx6ua55p/ZjhMXBi0
# q9wpvAya1/i/jRFcMu7s4CmtY7PQCMBkUuuOSNx2EaMmTNF/OF+U+wTZAlgvkCby
# RXcVlZGsF0wCvtyDWBA=
# SIG # End signature block
