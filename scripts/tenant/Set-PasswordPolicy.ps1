#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    07.12.2020 Konrad Brunner       Initial Version

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
Write-Host "Tenant | Set-PasswordPolicy | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Setting domain password policy" -ForegroundColor $CommandInfo
$MsolPasswordPolicy = Get-MsolPasswordPolicy -TenantId $AlyaTenantId -DomainName $AlyaDomainName
if ($MsolPasswordPolicy.ValidityPeriod -ne $ValidityPeriod -or $MsolPasswordPolicy.NotificationDays -ne $NotificationDays)
{
    Write-Warning "SelfServePasswordReset was set to"
    Write-Warning "  ValidityPeriod: $($MsolPasswordPolicy.ValidityPeriod)"
    Write-Warning "  NotificationDays: $($MsolPasswordPolicy.NotificationDays)"
    Write-Warning "Setting now to"
    Write-Warning "  ValidityPeriod: $($ValidityPeriod)"
    Write-Warning "  NotificationDays: $($NotificationDays)"
    Set-MsolPasswordPolicy -ValidityPeriod $ValidityPeriod -NotificationDays $NotificationDays -TenantId $AlyaTenantId -DomainName $AlyaDomainName
}
else
{
    Write-Host "SelfServePasswordReset was already correctly configured." -ForegroundColor $CommandSuccess
}

Write-Host "Setting PasswordNeverExpires=false for domain users to" -ForegroundColor $CommandInfo
$users = Get-MsolUser -DomainName $AlyaDomainName
foreach($user in $users)
{
    Set-MsolUser -ObjectId $user.ObjectId -PasswordNeverExpires $false
}

#Stopping Transscript
Stop-Transcript
