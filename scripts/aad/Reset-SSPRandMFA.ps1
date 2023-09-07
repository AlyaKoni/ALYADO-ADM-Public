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
    19.05.2021 Konrad Brunner       Initial Version
    28.08.2023 Konrad Brunner       Switch to MgGraph

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$userUpn
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Reset-SSPRandMFA-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Directory.ReadWrite.All", "UserAuthenticationMethod.ReadWrite.All")

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Reset-SSPRandMFA | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Actual OtherMails" -ForegroundColor $CommandInfo
Write-Host (Get-MgBetaUser -UserId $userUpn -Select OtherMails).OtherMails "`n"

Write-Host "Actual BusinessPhones" -ForegroundColor $CommandInfo
Write-Host (Get-MgBetaUser -UserId $userUpn -Select BusinessPhones).BusinessPhones "`n"

Write-Host "Actual MobilePhone" -ForegroundColor $CommandInfo
Write-Host (Get-MgBetaUser -UserId $userUpn -Select MobilePhone).MobilePhone "`n"

$methods = Get-MgBetaUserAuthenticationMethod -UserId $userUpn
foreach($method in $methods)
{
    switch ($method.AdditionalProperties.'@odata.type')
    {
        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
            Write-Host "microsoftAuthenticatorAuthenticationMethod" -ForegroundColor $CommandInfo
            Get-MgBetaUserAuthenticationMicrosoftAuthenticatorMethod -UserId $userUpn -MicrosoftAuthenticatorAuthenticationMethodId $method.Id
            $resp = $Host.UI.PromptForChoice("Question", "Remove this method?", @("&Yes", "&No"), 1)
            if ($resp -eq 0) {
                Remove-MgBetaUserAuthenticationMicrosoftAuthenticatorMethod -UserId $userUpn -MicrosoftAuthenticatorAuthenticationMethodId $method.Id
            }
        }
        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
            Write-Host "windowsHelloForBusinessAuthenticationMethod" -ForegroundColor $CommandInfo
            Get-MgBetaUserAuthenticationWindowsHelloForBusinessMethod -UserId $userUpn -WindowsHelloForBusinessAuthenticationMethodId $method.Id
        }
        "#microsoft.graph.emailAuthenticationMethod" {
            Write-Host "emailAuthenticationMethod" -ForegroundColor $CommandInfo
            Get-MgBetaUserAuthenticationEmailMethod -UserId $userUpn -EmailAuthenticationMethodId $method.Id
            $resp = $Host.UI.PromptForChoice("Question", "Remove this method?", @("&Yes", "&No"), 1)
            if ($resp -eq 0) {
                Remove-MgBetaUserAuthenticationEmailMethod -UserId $userUpn -EmailAuthenticationMethodId $method.Id
            }
        }
        "#microsoft.graph.passwordAuthenticationMethod" {
            Write-Host "passwordAuthenticationMethod" -ForegroundColor $CommandInfo
            Get-MgBetaUserAuthenticationPasswordMethod -UserId $userUpn -PasswordAuthenticationMethodId $method.Id
        }
        default {
            Write-Warning "Don't know method $($method.AdditionalProperties.'@odata.type')"
        }
    }
}

#Stopping Transscript
Stop-Transcript
