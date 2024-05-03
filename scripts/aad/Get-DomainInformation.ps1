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
    01.05.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Get-DomainInformation-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "MSOnline"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MSOL

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Get-DomainInformation | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting all MSOL domains
Write-Host "Getting all MSOL domains" -ForegroundColor $CommandInfo
$domains = Get-MsolDomain
$domains | Format-Table

# Getting additional information
Write-Host "Getting additional information" -ForegroundColor $CommandInfo
$federatedDomains = Get-MsolDomain | Where-Object {$_.Authentication -eq "Federated"}
$rootDomains = $federatedDomains | Where-Object {$_.RootDomain -eq $null}
$rootDomainsSupportMFAFalse = @()
foreach ($rootDomain in $rootDomains)
{
    $fedProps = Get-MsolDomainFederationSettings -DomainName $rootDomain.Name 
    If ($fedProps.SupportsMfa -ne $True) {
        $rootDomainsSupportMFAFalse += $rootDomain.Name
    }
}

Write-Host "Federated domains"
$federatedDomains | Format-Table

Write-Host "Root domains"
$rootDomains | Format-Table

Write-Host "Domains not supporting MFA"
$rootDomainsSupportMFAFalse | Format-Table

# Getting all Azure domains
Write-Host "Getting all Azure domains" -ForegroundColor $CommandInfo
$azdomains = Get-AzAdDomain
$azdomains | Format-Table

foreach ($domain in $domains)
{
    Write-Host "Federation settings $($domain.Name)" -ForegroundColor $CommandInfo
    $fedProps = Get-MsolDomainFederationSettings -DomainName $domain.Name
    $fedProps | Format-List
}

#Stopping Transscript
Stop-Transcript
