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
    04.08.2023 Konrad Brunner       Browser parameter
    28.08.2023 Konrad Brunner       Switch to MgGraph

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
	[object]$browser
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-PasswordReset-$($AlyaTimeString).log" | Out-Null

# Constants

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Policy.ReadWrite.Authorization")

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-PasswordReset | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

if (-Not $browser) {
    if ($Global:AlyaSeleniumBrowser) {
        $browser = $Global:AlyaSeleniumBrowser
    }
}

$authorizationPolicy = Get-MgBetaPolicyAuthorizationPolicy -AuthorizationPolicyId "authorizationPolicy"
if ($authorizationPolicy.AllowedToUseSspr -ne $AlyaPasswordResetEnabled)
{
    Write-Warning "AllowedToUseSspr was set to $($authorizationPolicy.AllowedToUseSspr). Setting it now to $($AlyaPasswordResetEnabled)."
    $param = @{
        AllowedToUseSspr = $AlyaPasswordResetEnabled
    }
    Update-MgPolicyAuthorizationPolicy -BodyParameter $param
}
else
{
    Write-Host "AllowedToUseSspr was already set to $($AlyaPasswordResetEnabled)." -ForegroundColor $CommandSuccess
}

if ($AlyaPasswordResetEnabled)
{
    Write-Host "Enabling password reset options" -ForegroundColor $CommandInfo
    Write-Host "You have now to configure password reset options. Pleas browse to"
    Write-Host "  https://portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/PasswordReset"
    if ([string]::IsNullOrEmpty($AlyaSsprEnabledGroupName) -or $AlyaSsprEnabledGroupName -eq "PleaseSpecify"-or $AlyaSsprEnabledGroupName.Count -eq 0 )
    {
        #TODO get groups enabling password reset by licenses
        Write-Host "and allow password reset for all users."
    }
    else
    {
        Write-Host "and allow password reset for group(s) $AlyaSsprEnabledGroupName. "
    }
    Write-Host "Also configure reset options."
    if (-Not $browser) {
        Start-Process "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/PasswordReset"
    } else {
        $browser.Url =  "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/PasswordReset"
    }
    pause
}

#Stopping Transscript
Stop-Transcript
