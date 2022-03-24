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
    07.12.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$userUpn = $null
)

if (-Not $userUpn)
{
    throw "Please specify the userUpn"
}

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Enable-BasicAuthPopImapSmtp-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Enable-BasicAuthPopImapSmtp | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Setting authentication policy in exchange"
try
{
    Write-Host "  Connecting to Exchange Online" -ForegroundColor $CommandInfo
    LoginTo-EXO

    Write-Host "  Checking policy EnableBasicAuthPopImapSmtp" -ForegroundColor $CommandInfo
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

    <#
    Write-Host "  Checking transport config" -ForegroundColor $CommandInfo
    $tc = Get-TransportConfig
    if ($tc.SmtpClientAuthenticationDisabled)
    {
        Write-Warning "Enabling SMTP client authentication"
        Set-TransportConfig -SmtpClientAuthenticationDisabled $false
    }
    #>

    # Setting authentication policy for user
    Write-Host "Setting authentication policy for user " -ForegroundColor $CommandInfo
    $user = Get-User | where { $_.RecipientType -eq "UserMailbox" -and $_.UserPrincipalName -eq "$userUpn" }
    if ($user.AuthenticationPolicy -ne "EnableBasicAuthPopImapSmtp")
    {
        Set-User -Identity $user.UserPrincipalName -AuthenticationPolicy "EnableBasicAuthPopImapSmtp"
        #Set-CasMailbox <mailbox account> -SmtpClientAuthenticationDisabled $False
    }

    # Setting authentication policy for all users
    <#
    Write-Host "Setting authentication policy for all users" -ForegroundColor $CommandInfo
    $users = Get-User | where { $_.RecipientType -eq "UserMailbox" -and $_.UserPrincipalName -like "*@$AlyaDomainName*" }
    foreach($user in $users)
    {
        if ($user.AuthenticationPolicy -ne "EnableBasicAuthPopImapSmtp")
        {
            Set-User -Identity $user.UserPrincipalName -AuthenticationPolicy "EnableBasicAuthPopImapSmtp"
            #Set-CasMailbox <mailbox account> -SmtpClientAuthenticationDisabled $False
        }
    }
    #>

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