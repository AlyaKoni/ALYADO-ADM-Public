#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2021

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
    01.11.2020 Konrad Brunner       Initial Creation

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Get-DomainRecordsFor_DMARC_DKIM_SPF-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "EXCHANGE | Get-DomainRecordsFor_DMARC_DKIM_SPF | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$domains = @()

$domains += $AlyaDomainName
foreach ($dom in $AlyaAdditionalDomainNames)
{
    $domains += $dom
}

foreach ($dom in $domains)
{
    Write-Host "DNS config for domain $dom" -ForegroundColor $CommandSuccess

    # SPF generator https://dmarcly.com/tools/spf-record-generator
    Write-Host "SPF" -ForegroundColor $CommandInfo
    Write-Host "Type:  TXT"
    Write-Host "Name:  @"
    Write-Host "Value: v=spf1 include:spf.protection.outlook.com -all"
    # if sendgrid: v=spf1 include:sendgrid.net include:spf.protection.outlook.com –all
    Write-Host "TTL:   1 hour"

    Write-Host "`nDMARC" -ForegroundColor $CommandInfo
    Write-Host "Type:  TXT"
    Write-Host "Name:  _dmarc"
    Write-Host "Value: v=DMARC1; p=quarantine; sp=quarantine; pct=100; ruf=mailto:$($AlyaSecurityEmail); rua=mailto:$($AlyaSecurityEmail)"
    Write-Host "TTL:   1 hour"

    Write-Host "`nDMARC Reports" -ForegroundColor $CommandInfo
    Write-Host "Type:  TXT"
    Write-Host "Name:  $($dom)._report._dmarc"
    Write-Host "Value: v=DMARC1"
    Write-Host "TTL:   1 hour"

    try
    {
        LoginTo-EXO
        $conf = Get-DkimSigningConfig -Identity $dom | Format-List Selector1CNAME, Selector2CNAME

        Write-Host "`nDKIM 1" -ForegroundColor $CommandInfo
        Write-Host "Type:  CNAME"
        Write-Host "Name:  selector1._domainkey"
        Write-Host "Value: $($conf.Selector1CNAME)"
        Write-Host "TTL:   1 hour"

        Write-Host "`nDKIM 2" -ForegroundColor $CommandInfo
        Write-Host "Type:  CNAME"
        Write-Host "Name:  selector2._domainkey"
        Write-Host "Value: $($conf.Selector2CNAME)"
        Write-Host "TTL:   1 hour"

    }
    catch
    {
        try { Write-Error ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
	    Write-Error ($_.Exception) -ErrorAction Continue
    }
    finally
    {
        DisconnectFrom-EXOandIPPS
    }
    Write-Host "`n"

}
#Stopping Transscript
Stop-Transcript