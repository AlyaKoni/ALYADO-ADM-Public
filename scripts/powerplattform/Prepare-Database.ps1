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
    17.01.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\powerplattform\Prepare-Database-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.PowerApps.Administration.PowerShell"
Install-ModuleIfNotInstalled "Microsoft.PowerApps.PowerShell"

# Logins
LoginTo-PowerApps

# =============================================================
# PowerPlatform stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Environment | Prepare-Database | PowerPlatform" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$defCurrency = Get-AdminPowerAppCdsDatabaseCurrencies -LocationName $env.location | Where-Object { $_.IsTenantDefaultCurrency -eq $true }
$defLanguage = Get-AdminPowerAppCdsDatabaseLanguages -LocationName $env.location | Where-Object { $_.IsTenantDefaultLanguage -eq $true }

$envs = Get-AdminPowerAppEnvironment
foreach($env in $envs)
{
    #$env = $envs[0]
    Write-Host "Environment: $($env.DisplayName)"
    Write-Host " DB state  : $($env.CommonDataServiceDatabaseProvisioningState)"
    if ($env.CommonDataServiceDatabaseProvisioningState -ne "Succeeded")
    {
        Write-Warning "Provisioning database"
        New-AdminPowerAppCdsDatabase -EnvironmentName $env.DisplayName -CurrencyName $defCurrency.CurrencyName -LanguageName $defLanguage.LanguageDisplayName -WaitUntilFinished
    }
}

#Stopping Transscript
Stop-Transcript
