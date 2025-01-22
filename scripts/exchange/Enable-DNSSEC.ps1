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
    17.01.2024 Konrad Brunner       Initial Creation

#>

[CmdletBinding()]
Param(
    [string[]]$ignoreDomains = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Enable-DNSSEC-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "EXCHANGE | Enable-DNSSEC | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$domains = @()

$domains += $AlyaDomainName
foreach ($dom in $AlyaAdditionalDomainNames)
{
    if ($ignoreDomains -and $dom -in $ignoreDomains) { continue }
    $domains += $dom
}

try
{
    LoginTo-EXO
    foreach ($dom in $domains)
    {
        Write-Host "Checking domain $dom"

        $conf = Get-DnssecStatusForVerifiedDomain -Domain $dom
        if ($conf.DnssecFeatureStatus.Value -eq "Disabled")
        {
            Write-Warning "DNSSEC not yet enabled on this domain. Enabling it now"

            Write-Host "Update the TTL of your existing MX record to the lowest TTL possible (but not lower than 30 seconds)"
            Write-Host "Then, wait for the previous TTL to expire before proceeding)"
            $Readhost = Read-Host "Already done? (y/n) "
            if($ReadHost -eq "n")
            {
                Write-Host "Please restart this script after TTL expiration" -ForegroundColor $CommandWarning
                exit
            }            
            $conf = Enable-DnssecForVerifiedDomain -DomainName $dom
            if ($conf.Result -eq "Success")
            {
                Write-Host "DNSSEC successfully enabled"
                Write-Host "Add now a new MX record to DNS with lowest TTL possible (but not lower than 30 seconds) and set lowest priority (ex. 20)"
                Write-Host "MX: $($conf.DnssecMxValue)"
                Write-Host "Verify that the new MX is working via the Inbound SMTP Email test:"
                Write-Host "  https://testconnectivity.microsoft.com/tests/O365InboundSmtp/input"
                $Readhost = Read-Host "Test successfull? (y/n) "
                if($ReadHost -eq "n")
                {
                    Write-Host "Please fix and restart this script" -ForegroundColor $CommandError
                    exit
                }
                Write-Host "Change the priority of the legacy MX pointing to mail.protection.outlook.com from current priority to lowest priority (ex. 30)"
                Write-Host "Change the priority of the new MX record created so that it's set to priority 0 (highest priority)"
                Write-Host "Wait for lowest configured TTL and hit then return"
                pause
                Write-Host "Delete the old mail.protection.outlook.com MX record"
                Write-Host "Update the TTL of the new MX record created to 3600"
                Write-Host "Hit return when done"
                pause
            }
            else
            {
                $conf | Format-List
                throw "There was an error, enabling DNSSEC"
            }
        }
        else
        {
            Write-Host "DNSSEC already enabled on this domain"
            Write-Host "MX: $($conf.ExpectedMxRecord.Record)"
        }
    }
}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}

#Stopping Transscript
Stop-Transcript
