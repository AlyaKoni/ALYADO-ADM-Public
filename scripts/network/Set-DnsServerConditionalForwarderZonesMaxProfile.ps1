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
    25.09.2024 Konrad Brunner       Initial version


    https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-dns
    
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({$_ -match [IPAddress]$_ })]
    [string]$forwarderIp = $null,
    [int]$dnsTimeout = 10,
    [bool]$onlyShowValues = $true
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\network\Set-DnsServerConditionalForwarderZonesMaxProfile-$($AlyaTimeString).log" | Out-Null

# Constants
$allDomains = @(
    "azconfig.io",
    "azmk8s.io",
    "azure.com",
    "azure.net",
    "azure-api.net",
    "azure-automation.net",
    "azurecr.io",
    "azuredatabricks.net",
    "azure-devices.net",
    "azure-devices-provisioning.net",
    "azurehdinsight.net",
    "azurehealthcareapis.com",
    "azureiotcentral.com",
    "azureml.ms",
    "azurestaticapps.net",
    "azuresynapse.net",
    "azurewebsites.net",
    "botframework.com",
    "microsoft.com",
    "signalr.net",
    "windows.net",
    "windows.net1",
    "windowsazure.com"
)

# =============================================================
# DNS stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "DNS | Set-DnsServerConditionalForwarderZonesMaxProfile | ON-PREMISES" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

foreach($domain in $allDomains)
{
    Write-Host "  Forwarding $domain to $forwarderIp"
    if (-Not $onlyShowValues) { Add-DnsServerConditionalForwarderZone -Name $domain -ReplicationScope "Forest" -MasterServers $forwarderIp -ForwarderTimeout $dnsTimeout }
}

#Stopping Transscript
Stop-Transcript
