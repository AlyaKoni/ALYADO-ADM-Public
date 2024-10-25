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

try
{
    LoginTo-EXO

    foreach ($dom in $domains)
    {
        Write-Output "`nDNS config for domain $dom"

        # SPF generator https://dmarcly.com/tools/spf-record-generator
        Write-Output "`nSPF"
        Write-Output "Type:  TXT"
        Write-Output "Name:  @"
        Write-Output "Value: v=spf1 include:spf.protection.outlook.com -all"
        # if sendgrid: v=spf1 include:sendgrid.net include:spf.protection.outlook.com –all
        Write-Output "TTL:   1 hour"

        Write-Output "`nDMARC"
        Write-Output "Type:  TXT"
        Write-Output "Name:  _dmarc"
        Write-Output "Value: v=DMARC1; p=quarantine; sp=quarantine; pct=100; rf=afrf; fo=0:s; aspf=r; adkim=r; ruf=mailto:$($AlyaSecurityEmail); rua=mailto:$($AlyaSecurityEmail)"
        Write-Output "TTL:   1 hour"

        Write-Output "`nDMARC Reports"
        Write-Output "Type:  TXT"
        Write-Output "Name:  $($dom)._report._dmarc"
        Write-Output "Value: v=DMARC1"
        Write-Output "TTL:   1 hour"

        $cfg = Get-DkimSigningConfig -Identity $dom
        if (-Not $cfg -or -Not $cfg.Selector1CNAME)
        {
            Write-Error "No domain config found for $dom" -ErrorAction Continue
        }
        $Selector1CNAME = $cfg.Selector1CNAME
        $Selector2CNAME = $cfg.Selector2CNAME

        Write-Output "`nDKIM 1"
        Write-Output "Type:  CNAME"
        Write-Output "Name:  selector1._domainkey"
        Write-Output "Value: $Selector1CNAME"
        Write-Output "TTL:   1 hour"

        Write-Output "`nDKIM 2"
        Write-Output "Type:  CNAME"
        Write-Output "Name:  selector2._domainkey"
        Write-Output "Value: $Selector2CNAME"
        Write-Output "TTL:   1 hour"

        Write-Output "`n"

        Write-Host "If you like to get a service for DMARC reports, you can get one for free here:"
        Write-Host "https://dmarc.postmarkapp.com/?utm_source=dmarcdigests&utm_medium=web&utm_content=pricing"
        Write-Host "`n"

    }

}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
    Write-Error ($_.Exception) -ErrorAction Continue
}
finally
{
    DisconnectFrom-EXOandIPPS
}

#Stopping Transscript
Stop-Transcript
