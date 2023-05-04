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
    25.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding(DefaultParameterSetName='all')] 
Param  
(
    [Parameter(ParameterSetName="ipsonly", Mandatory=$false)]
    [switch] $ipsonly = $false,
    [Parameter(ParameterSetName="urlsonly", Mandatory=$false)]
    [switch] $urlsonly = $false,
    [Parameter(ParameterSetName="all", Mandatory=$false)]
    [Parameter(ParameterSetName="ipsonly", Mandatory=$false)]
    [Parameter(ParameterSetName="urlsonly", Mandatory=$false)]
    [switch] $dataonly = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\network\Get-MSIPRangesAndUrls-$($AlyaTimeString).log" | Out-Null

# Azure IP ranges updated every Wednesday
$clientRequestId = [GUID]::NewGuid().Guid
$AzureIPRangesPage = Invoke-WebRequest -SkipHttpErrorCheck -Uri ("https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519&clientRequestId=" + $clientRequestId) -Method Get -UseBasicParsing 
$azureIps = Invoke-RestMethod -uri ($AzureIPRangesPage.Links |Where {$_.outerhtml -like "*Click here*"}).href[0]

$azureUrls = @( `
    "*.azure.com", `
    "*.azure.net", `
    "*.azure-dns.com", `
    "*.azure-dns.net", `
    "*.azurecomcdn.net", `
    "*.azureedge.net", `
    "*.msecnd.net", `
    "login.live.com", `
    "*.windows.net", `
    "*.sendgrid.com", `
    "*.aadrm.com", `
    "*.msft.net", `
    "*.microsoft.com", `
    "*.microsoftonline.com", `
    "*.microsoftazuread-sso.com", `
    "www.msftconnecttest.com", `
    "aka.ms", `
    "*.sfx.ms", `
    "*.azure-apihub.net", `
    "*.azure-apihub.net", `
    "*.digicert.com", `
    "169.254.169.254", `
    "168.63.129.16" `
)

if (-Not $urlsonly)
{
    if (-Not $dataonly) { Write-Host "`nAzure IP Ranges" -ForegroundColor $CommandInfo }
    foreach($azureIpRange in $azureIps.values)
    {
        "`nAzure: $($azureIpRange.name)"
        $azureIpRange.properties.addressPrefixes
    }
}

if (-Not $ipsonly)
{
    if (-Not $dataonly) { Write-Host "`nAzure URLs" -ForegroundColor $CommandInfo }
    $azureUrls | Sort-Object -Unique
}

# O365 IP ranges updated hourly
# https://docs.microsoft.com/en-us/office365/enterprise/office-365-ip-web-service
$clientRequestId = [GUID]::NewGuid().Guid
$endpointSets = Invoke-RestMethod -Uri ("https://endpoints.office.com/endpoints/Worldwide?clientRequestId=" + $clientRequestId)
$o365Urls = $endpointSets | ForEach-Object {
    $endpointSet = $_
    $urls = $(if ($endpointSet.urls.Count -gt 0) { $endpointSet.urls } else { @() })
    $urlCustomObjects = @()
    if ($endpointSet.category -in ("Allow", "Optimize")) {
        $urlCustomObjects = $urls | ForEach-Object {
            [PSCustomObject]@{
                category = $endpointSet.category;
                url      = $_;
                tcpPorts = $endpointSet.tcpPorts;
                udpPorts = $endpointSet.udpPorts;
            }
        }
    }
    $urlCustomObjects
}
$o365Ips = $endpointSets | ForEach-Object {
    $endpointSet = $_
    $ips = $(if ($endpointSet.ips.Count -gt 0) { $endpointSet.ips } else { @() })
    $ip4s = $ips | Where-Object { $_ -like '*.*' }
    $ipCustomObjects = @()
    if ($endpointSet.category -in ("Allow", "Optimize")) { #Default??
        $ipCustomObjects = $ip4s | ForEach-Object {
            [PSCustomObject]@{
                category = $endpointSet.category;
                ip = $_;
                tcpPorts = $endpointSet.tcpPorts;
                udpPorts = $endpointSet.udpPorts;
            }
        }
    }
    $ipCustomObjects
}

if (-Not $urlsonly)
{
    if (-Not $dataonly) { Write-Host "`nO365 IP Ranges" -ForegroundColor $CommandInfo }
    $o365Ips.ip | Sort-Object -Unique
}

if (-Not $ipsonly)
{
    if (-Not $dataonly) { Write-Host "`nO365 URLs" -ForegroundColor $CommandInfo }
    $o365Urls.url | Sort-Object -Unique
}

#Stopping Transscript
Stop-Transcript
