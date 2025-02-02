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
    07.07.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Enable-BasicAuthPopImapSmtpGlobally-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Enable-BasicAuthPopImapSmtpGlobally | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Setting authentication policy in exchange"
try
{
    Write-Host "Connecting to Exchange Online" -ForegroundColor $CommandInfo
    try {
        LoginTo-EXO
    }
    catch {
        Write-Error $_.Exception -ErrorAction Continue
        LogoutFrom-EXOandIPPS
        LoginTo-EXO
    }

    Write-Host "Checking policy EnableBasicAuthPopImapSmtp" -ForegroundColor $CommandInfo
    $pol = Get-AuthenticationPolicy -Identity "EnableBasicAuthPopImapSmtp" -ErrorAction SilentlyContinue
    if (-Not $pol)
    {
        Write-Warning "Authentication policy EnableBasicAuthPopImapSmtp not found. Creating it now"
        $pol = New-AuthenticationPolicy -Name "EnableBasicAuthPopImapSmtp" -AllowBasicAuthSmtp -AllowBasicAuthPop -AllowBasicAuthImap
    }
    else
    {
        Write-Host "Authentication policy EnableBasicAuthPopImapSmtp already exists"
    }

    if (-Not $pol.AllowBasicAuthImap -or -Not $pol.AllowBasicAuthSmtp -or -Not $pol.AllowBasicAuthPop)
    {
        Write-Warning "One of pop, imap or smtp was disabled. Enabling them now all"
        Set-AuthenticationPolicy -Name "EnableBasicAuthPopImapSmtp" -AllowBasicAuthSmtp -AllowBasicAuthPop -AllowBasicAuthImap
    }


    Write-Host "Checking default policy in OrganizationConfig" -ForegroundColor $CommandInfo
    $tconf = Get-OrganizationConfig -ErrorAction SilentlyContinue
    if ($tconf.DefaultAuthenticationPolicy -ne "EnableBasicAuthPopImapSmtp")
    {
        Write-Warning "EnableBasicAuthPopImapSmtp is not set as default. Setting it now"
        $null = Set-OrganizationConfig -DefaultAuthenticationPolicy "EnableBasicAuthPopImapSmtp"
    }
    else
    {
        Write-Host "Default policy EnableBasicAuthPopImapSmtp was already set"
    }

}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}

#Stopping Transscript
Stop-Transcript
