#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2022

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
    13.04.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-CustomDomain-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "AzureAdPreview"
    
# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-CustomDomain | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Configuring custom domain
Write-Host "Configuring custom domain" -ForegroundColor $CommandInfo
$dom = Get-AzureADDomain -Name $AlyaDomainName -ErrorAction SilentlyContinue
if (-Not $dom)
{
    Write-Warning "Please register first your custom domain and rerun this script"
    pause
    exit
}
if ($dom.SupportedServices.Count -eq 0)
{
    Write-Warning "Supported services on domain not yet configured. Configuring them now"
    $null = Set-AzureADDomain -Name $AlyaDomainName -SupportedServices @("Email","OfficeCommunicationsOnline","Intune") #OrgIdAuthentication, Yammer
}

# Your domain configuration
Write-Host "Your domain configuration" -ForegroundColor $CommandInfo
$domConfigs = Get-AzureADDomainServiceConfigurationRecord -Name $AlyaDomainName
$domConfigs | Select-Object -Property * -ExcludeProperty DnsRecordId,SupportedService,IsOptional | Format-List

# Checking domain configuration
Write-Host "Checking domain configuration" -ForegroundColor $CommandInfo
foreach($domConfig in $domConfigs)
{
    Write-Host "$($domConfig.RecordType) $($domConfig.Label)"
    if ($domConfig.RecordType -eq "CName")
    {
        $rec = Resolve-DnsName $domConfig.Label CName -DnsOnly
        if ($rec.NameHost -ne $domConfig.CanonicalName)
        {
            Write-Warning "Wrong value in DNS: $($rec.NameHost)"
        }
    }
    if ($domConfig.RecordType -eq "Mx")
    {
        $rec = Resolve-DnsName $domConfig.Label MX -DnsOnly
        if ($rec.Exchange -ne $domConfig.MailExchange)
        {
            Write-Warning "Wrong Exchange in DNS: $($rec.Exchange)"
        }
        if ($rec.Preference -ne $domConfig.Preference)
        {
            Write-Warning "Wrong Preference in DNS: $($rec.Preference)"
        }
    }
    if ($domConfig.RecordType -eq "Txt")
    {
        $rec = Resolve-DnsName $domConfig.Label TXT -DnsOnly
        if ($rec.Text -ne $domConfig.Text)
        {
            Write-Warning "Wrong Text in DNS: $($rec.Text)"
        }
    }
    if ($domConfig.RecordType -eq "Srv")
    {
        $rec = Resolve-DnsName $domConfig.Label SRV -DnsOnly
        if ($rec.NameTarget -ne $domConfig.NameTarget)
        {
            Write-Warning "Wrong NameTarget in DNS: $($rec.NameTarget)"
        }
        if ($rec.Priority -ne $domConfig.Priority)
        {
            Write-Warning "Wrong Priority in DNS: $($rec.Priority)"
        }
        if ($rec.Weight -ne $domConfig.Weight)
        {
            Write-Warning "Wrong Weight in DNS: $($rec.Weight)"
        }
        if ($rec.Port -ne $domConfig.Port)
        {
            Write-Warning "Wrong Port in DNS: $($rec.Port)"
        }
    }
}

#Stopping Transscript
Stop-Transcript
