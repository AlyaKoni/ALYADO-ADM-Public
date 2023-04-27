#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2023

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
    Alya Basis Konfiguration ist Freie Software: Sie koennen es unter den
	Bedingungen der GNU General Public License, wie von der Free Software
	Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veroeffentlichten Version, weiter verteilen und/oder modifizieren.
    Alya Basis Konfiguration wird in der Hoffnung, dass es nuetzlich sein wird,
	aber OHNE JEDE GEWAEHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewaehrleistung der MARKTFAEHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
	https://www.gnu.org/licenses/gpl-3.0.txt

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    26.04.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-OneTimePasscodeEnabled-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Identity.SignIns"

# Logins
LoginTo-MgGraph -Scopes @("Policy.ReadWrite.AuthenticationMethod")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-OneTimePasscodeEnabled | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking Email OTP enabled
Write-Host "Checking Email OTP enabled" -ForegroundColor $CommandInfo
(Get-MgPolicyAuthenticationMethodPolicy).AuthenticationMethodConfigurations
$conf = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Email"
if ($conf.State -ne "enabled")
{
    Write-Warning "Email OTP was not enabled. Enabling it now"
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Email" -State "enabled"
}

# Checking guests enabled
Write-Host "Checking guests enabled" -ForegroundColor $CommandInfo
$conf = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Email"
if ($conf.AdditionalProperties.allowExternalIdToUseEmailOtp -ne "enabled")
{
    Write-Warning "Email OTP guests were not enabled. Enabling them now"
    $conf.AdditionalProperties.allowExternalIdToUseEmailOtp = "enabled"

}
if ($conf.AdditionalProperties.includeTargets.Count -eq 0)
{
    Write-Warning "Email OTP include target not set. Setting it now"
    $conf.AdditionalProperties.includeTargets += @{
        targetType = "group"
        id = "all_users"
        isRegistrationRequired = $false
    }
}
else {
    #TODO
}
Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Email" -AdditionalProperties $conf.AdditionalProperties

#Stopping Transscript
Stop-Transcript
