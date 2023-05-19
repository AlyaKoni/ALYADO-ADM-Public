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
    27.02.2020 Konrad Brunner       Initial Version
    10.07.2022 Konrad Brunner       Added AlyaSsprEnabledGroup

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-PasswordReset-$($AlyaTimeString).log" | Out-Null

# Constants

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "MSOnline"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MSOL

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-PasswordReset | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$MsolCompanySettings = Get-MsolCompanyInformation
if ($MsolCompanySettings.SelfServePasswordResetEnabled -ne $AlyaPasswordResetEnabled)
{
    Write-Warning "SelfServePasswordReset was set to $($MsolCompanySettings.SelfServePasswordResetEnabled). Setting it now to $($AlyaPasswordResetEnabled)."
    Set-MsolCompanySettings -SelfServePasswordResetEnabled $AlyaPasswordResetEnabled
}
else
{
    Write-Host "SelfServePasswordReset was already set to $($AlyaPasswordResetEnabled)." -ForegroundColor $CommandSuccess
}

if ($AlyaPasswordResetEnabled)
{
    Write-Host "Enabling password reset options" -ForegroundColor $CommandInfo
    Write-Host "You have now to configure password reset options. Pleas browse to"
    Write-Host "  https://portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/PasswordReset"
    if ([string]::IsNullOrEmpty($AlyaSsprEnabledGroupName))
    {
        Write-Host "and allow password reset for all users."
    }
    else
    {
        Write-Host "and allow password reset for group $AlyaSsprEnabledGroupName. Also configure reset options."
    }
    Write-Host "Also configure reset options."
    Start-Process "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/PasswordReset"
    pause
}

#Stopping Transscript
Stop-Transcript
