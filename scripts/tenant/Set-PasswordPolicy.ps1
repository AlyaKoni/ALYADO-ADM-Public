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
    07.12.2020 Konrad Brunner       Initial Version
    28.08.2023 Konrad Brunner       Switch to MgGraph

#>

[CmdletBinding()]
Param(
    [int]$ValidityPeriod = 365,
    [int]$NotificationDays = 21
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-PasswordPolicy-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Directory.ReadWrite.All","Domain.ReadWrite.All")

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-PasswordPolicy | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Setting domain password policy" -ForegroundColor $CommandInfo
$domain = Get-MgBetaDomain -DomainId $AlyaTenantName
if ($domain.ValidityPeriod -ne $ValidityPeriod -or $domain.NotificationDays -ne $NotificationDays)
{
    Write-Warning "SelfServePasswordReset was set to"
    Write-Warning "  ValidityPeriod: $($domain.PasswordValidityPeriodInDays)"
    Write-Warning "  NotificationDays: $($domain.PasswordNotificationWindowInDays)"
    Write-Warning "Setting now to"
    Write-Warning "  ValidityPeriod: $($ValidityPeriod)"
    Write-Warning "  NotificationDays: $($NotificationDays)"
    Update-MgBetaDomain -DomainId $AlyaTenantName -PasswordNotificationWindowInDays $NotificationDays -PasswordValidityPeriodInDays $ValidityPeriod
}
else
{
    Write-Host "SelfServePasswordReset was already correctly configured." -ForegroundColor $CommandSuccess
}

Write-Host "Users with password expiration disabled" -ForegroundColor $CommandInfo
$users = Get-MgBetaUser -All -Property UserPrincipalName, PasswordPolicies
foreach($user in $users)
{
    if ($user.PasswordPolicies -contains "DisablePasswordExpiration")
    {
        Write-Host "$($user.UserPrincipalName)"
    }
}

#Stopping Transscript
Stop-Transcript
