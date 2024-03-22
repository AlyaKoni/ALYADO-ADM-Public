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
    07.03.2024 Konrad Brunner       Initial Version

    push – Microsoft Authenticator push notifications with number matching.
    oath – 6 digit (OTP) password with authentication app.
    voiceMobile – Voice call answering with 6 digit code.
    voiceAlternateMobile – Voice call answering with 6 digit code on alternative mobile.
    voiceOffice – Voice call answering on office phone with 6 digit code.
    sms – Text message with 6 digit code.
    unknownFutureValue – Unsupported value.

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("windowsHelloForBusinessMethod","softwareOathMethod","platformCredentialMethod","passwordAuthenticationMethod","fido2AuthenticationMethod","temporaryAccessPassAuthenticationMethod","microsoftAuthenticatorAuthenticationMethod","voiceAuthenticationMethod","phoneAuthenticationMethodOffice","phoneAuthenticationMethodMobile","emailAuthenticationMethod","smsAuthenticationMethod")]
    [string]$methodToRemove
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Remove-UsersMfaMethod-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Directory.Read.All", "UserAuthenticationMethod.ReadWrite.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Remove-UsersMfaMethod | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Warnings
switch ($methodToRemove) {
    "smsAuthenticationMethod" {  
        Write-Warning "Removing smsAuthenticationMethod will also remove phoneAuthenticationMethodMobile!"
        pause
    }
    "phoneAuthenticationMethodMobile" {  
        Write-Warning "Removing phoneAuthenticationMethodMobile will also remove smsAuthenticationMethod!"
        pause
    }
}
<#
$odataTypes = @()
$phoneTypes = @()
foreach($user in $mgUsers)
{
    $methods = Get-MgBetaUserAuthenticationMethod -UserId $user.UserPrincipalName
    foreach($method in $methods)
    {
        if (-Not $odataTypes.Contains($method.AdditionalProperties."@odata.type"))
        {
            $odataTypes += $method.AdditionalProperties."@odata.type"
            if ($method.AdditionalProperties.phoneType -and -Not $phoneTypes.Contains($method.AdditionalProperties.phoneType))
            {
                $phoneTypes += $method.AdditionalProperties.phoneType
            }
        }
    }
}
#>

# Getting users
Write-Host "Getting users" -ForegroundColor $CommandInfo
$mgUsers = Get-MgBetaUser -Property "*" -All

# Removing auth method
Write-Host "Removing auth method '$methodToRemove' on user:" -ForegroundColor $CommandInfo
foreach($user in $mgUsers)
{
    $odataType = $methodToRemove
    $phoneType = $null
    switch ($methodToRemove) {
        "smsAuthenticationMethod" {  
            $odataType = "phoneAuthenticationMethod"
            $phoneType = "mobile"
        }
        "phoneAuthenticationMethodMobile" {  
            $odataType = "phoneAuthenticationMethod"
            $phoneType = "mobile"
        }
        "phoneAuthenticationMethodOffice" {  
            $odataType = "phoneAuthenticationMethod"
            $phoneType = "office"
        }
        "voiceAuthenticationMethod" {  
            $odataType = "phoneAuthenticationMethod"
            $phoneType = "alternateMobile"
        }
    }

    $methods = Get-MgBetaUserAuthenticationMethod -UserId $user.UserPrincipalName
    $method = $methods | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.$odataType" -and ($phoneType -eq $null -or $phoneType -eq $_.AdditionalProperties.phoneType) }
    if ($method)
    {
        Write-Host "$($user.userPrincipalName)"
        switch ($methodToRemove) {
            "emailAuthenticationMethod" {  
                try {
                    Remove-MgUserAuthenticationEmailMethod -EmailAuthenticationMethodId $method.Id -UserId $user.Id
                }
                catch {
                    Write-Host $_.Exception.Message -ForegroundColor $CommandError
                }
            }
            {$_ -in @("smsAuthenticationMethod","phoneAuthenticationMethodMobile","phoneAuthenticationMethodOffice","voiceAuthenticationMethod")} {  
                try {
                    Remove-MgUserAuthenticationPhoneMethod -PhoneAuthenticationMethodId $method.Id -UserId $user.Id
                }
                catch {
                    Write-Host $_.Exception.Message -ForegroundColor $CommandError
                }
            }
            "microsoftAuthenticatorAuthenticationMethod" {  
                try {
                    Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -MicrosoftAuthenticatorAuthenticationMethodId $method.Id -UserId $user.Id
                }
                catch {
                    Write-Host $_.Exception.Message -ForegroundColor $CommandError
                }
            }
            "temporaryAccessPassAuthenticationMethod" {  
                try {
                    Remove-MgUserAuthenticationTemporaryAccessPassMethod -TemporaryAccessPassAuthenticationMethodId $method.Id -UserId $user.Id
                }
                catch {
                    Write-Host $_.Exception.Message -ForegroundColor $CommandError
                }
            }
            "fido2AuthenticationMethod" {  
                try {
                    Remove-MgUserAuthenticationFido2Method -Fido2AuthenticationMethodId $method.Id -UserId $user.Id
                }
                catch {
                    Write-Host $_.Exception.Message -ForegroundColor $CommandError
                }
            }
            "softwareOathMethod" {  
                try {
                    Remove-MgUserAuthenticationSoftwareOathMethod -SoftwareOathAuthenticationMethodId $method.Id -UserId $user.Id
                }
                catch {
                    Write-Host $_.Exception.Message -ForegroundColor $CommandError
                }
            }
            "windowsHelloForBusinessMethod" {  
                try {
                    Remove-MgUserAuthenticationWindowsHelloForBusinessMethod -WindowsHelloForBusinessAuthenticationMethodId $method.Id -UserId $user.Id
                }
                catch {
                    Write-Host $_.Exception.Message -ForegroundColor $CommandError
                }
            }
            Default {
                Write-Error "Not yet implemented method $methodToRemove"
            }
        }
    }
}

#Stopping Transscript
Stop-Transcript
