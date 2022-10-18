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
    02.12.2019 Konrad Brunner       Initial Version
    25.02.2020 Konrad Brunner       Changes for a project
    25.10.2020 Konrad Brunner       Changed from service user to new ExchangeOnline module

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-O365AuditLogging-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-O365AuditLogging | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Setting auditing in exchange"
try
{
    Write-Host "  Connecting to Exchange Online" -ForegroundColor $CommandInfo
    LoginTo-EXO

    $cfg = Get-OrganizationConfig
    if ($cfg.IsDehydrated)
    {
        Enable-OrganizationCustomization -ErrorAction Stop
    }
    while ((Get-OrganizationConfig).IsDehydrated)
    {
        Write-Host "Waiting 1 minute..."
        Start-Sleep -Seconds 60
    }

    $error.Clear()
    if (-Not (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled)
    {
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        if ($error.Count -gt 0)
        {
            Write-Error "We were not able to set audit logging. Possibly it needs some time until customization gets enabled. Please rerun in an hour or so." -ErrorAction Continue
        }
    }
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

#Stopping Transscript
Stop-Transcript
