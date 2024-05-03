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
    [Parameter(Mandatory=$true)]
    [string]$domainName
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Set-DomainToFederated-$($AlyaTimeString).log" | Out-Null

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
Write-Host "AAD | Set-DomainToFederated | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting all MSOL domains
Write-Host "Getting all MSOL domains" -ForegroundColor $CommandInfo
$domain = Get-MsolDomain -Name $domainName
if (-Not $domain)
{
    throw "Domain $domainName not found"
}

if ($domain.Authentication -eq "Federated")
{
    Write-Host "Domain $domainName is already federated"
}
else
{
    Write-Host "Federating now domain $domainName"
    try {
        Convert-MsolDomainToFederated -DomainName $domainName -SupportMultipleDomain
    }
    catch {
        Write-Warning "Not able to federate this domain."
        Write-Warning "- was SupportMultipleDomain on other domains not configured?"
        <#
            Convert-MsolDomainToStandard `
            -DomainName <Name der einen vorhanden Domäne> `
            -SkipUserConversion $True
            Convert-MsolDomainToFederated 
            -DomainName <Name der einen vorhanden Domäne> 
            -SupportMultipleDomain
        #>
    }
}

Write-Host "Federation settings $($domainName)" -ForegroundColor $CommandInfo
$fedProps = Get-MsolDomainFederationSettings -DomainName $domainName
$fedProps | Format-List

#Stopping Transscript
Stop-Transcript
