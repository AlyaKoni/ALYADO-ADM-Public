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
    19.02.2024 Konrad Brunner       Initial Version

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
    [string[]]$users = $null,
    [ValidateSet("push","oath","voiceMobile","voiceAlternateMobile","voiceOffice","sms")]
    [string]$defaultMethod = "oath"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Set-UsersMfaDefaultMethod-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Directory.Read.All", "UserAuthenticationMethod.ReadWrite.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Set-UsersMfaDefaultMethod | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting users
Write-Host "Getting users" -ForegroundColor $CommandInfo
$mgUsers = Get-MgBetaUser -Property "*" -All

# Processing users
Write-Host "Processing users" -ForegroundColor $CommandInfo
foreach($userPrincipalName in $users)
{
    Write-Host "User $userPrincipalName"
    $mgUser = $mgUsers | Where-Object { $_.userPrincipalName -eq $userPrincipalName }
    if (-Not $mguser) {
        Write-Warning "  Not found!"
    }
    else {
        $body = "{`"userPreferredMethodForSecondaryAuthentication`": `"$defaultMethod`"}"
        $uri = "$AlyaGraphEndpoint/beta/users/$($mguser.id)/authentication/signInPreferences"
        Patch-MsGraph -Uri $uri -Body $body
    }
}

#Stopping Transscript
Stop-Transcript
