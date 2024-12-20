﻿#Requires -Version 2.0

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
    04.03.2020 Konrad Brunner       Initial Version
    28.08.2023 Konrad Brunner       Switch to MgGraph

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-EmailVerifiedUsers-$($AlyaTimeString).log" | Out-Null

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
Write-Host "Tenant | Set-EmailVerifiedUsers | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

if ($AlyaAllowEmailVerifiedUsers -is [string] -and $AlyaAllowEmailVerifiedUsers -eq "PleaseSpecify")
{
    Write-Warning "Please configure variable `$AlyaAllowEmailVerifiedUsers in ConfigureEnv.ps1"
    exit
}

$authorizationPolicy = Get-MgBetaPolicyAuthorizationPolicy -AuthorizationPolicyId "authorizationPolicy"
if ($authorizationPolicy.AllowEmailVerifiedUsersToJoinOrganization -ne $AlyaAllowEmailVerifiedUsers)
{
    Write-Warning "AllowEmailVerifiedUsersToJoinOrganization was $($authorizationPolicy.AllowEmailVerifiedUsersToJoinOrganization). Setting it to $($AlyaAllowEmailVerifiedUsers)."
    $param = @{
        allowEmailVerifiedUsersToJoinOrganization = $AlyaAllowEmailVerifiedUsers
    }
    Update-MgBetaPolicyAuthorizationPolicy -AuthorizationPolicyId $authorizationPolicy.Id -BodyParameter $param
}
else
{
    Write-Host "AllowEmailVerifiedUsersToJoinOrganization was already set to $($AlyaAllowEmailVerifiedUsers)." -ForegroundColor $CommandSuccess
}

#Stopping Transscript
Stop-Transcript
