#Requires -Version 7.0

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
    24.10.2026 Konrad Brunner       Initial Version

#>

<#
.SYNOPSIS
Configures per-user multi-factor authentication (MFA) for all users in Microsoft Entra ID according to the tenant's security defaults state.

.DESCRIPTION
The Configure-AllEntraPerUserMfa.ps1 script reads the tenant's security defaults policy (identitySecurityDefaultsEnforcementPolicy) and routes the per-user MFA configuration accordingly. If security defaults are enabled, per-user MFA is disabled for all users by calling Disable-AllEntraPerUserMfa.ps1, because Microsoft Entra ID ignores per-user MFA states while security defaults are active (security defaults enforce MFA tenant-wide themselves). If security defaults are disabled, per-user MFA is enforced for all users except the breaking glass admin by calling Enforce-AllEntraPerUserMfa.ps1. The script itself does not change any user state; all changes are performed by the called script, which also writes its own transcript log.

.INPUTS
None

.OUTPUTS
None

.EXAMPLE
PS> .\Configure-AllEntraPerUserMfa.ps1

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
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Configure-AllEntraPerUserMfa-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Policy.Read.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "MFA | Configure-AllEntraPerUserMfa | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking security defaults
Write-Host "Checking security defaults" -ForegroundColor $CommandInfo
$sdPolicy = Invoke-MgGraphRequest -Method "Get" -Uri "/beta/policies/identitySecurityDefaultsEnforcementPolicy"
if ($sdPolicy.isEnabled)
{
    Write-Host "Security defaults are enabled. Disabling per-user MFA for all users" -ForegroundColor $CommandInfo
    $targetScript = "$PSScriptRoot\Disable-AllEntraPerUserMfa.ps1"
}
else
{
    Write-Host "Security defaults are disabled. Enforcing per-user MFA for all users except the breaking glass admin" -ForegroundColor $CommandInfo
    $targetScript = "$PSScriptRoot\Enforce-AllEntraPerUserMfa.ps1"
}

# Configuring per-user MFA via the target script
Write-Host "Calling $($targetScript)" -ForegroundColor $CommandInfo

# Stopping Transcript (the called script starts its own transcript)
Stop-Transcript | Out-Null

& "$targetScript"
