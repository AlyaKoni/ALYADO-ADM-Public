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
    17.02.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string[]]$mailboxUpns = $null
)

if (-Not $mailboxUpns)
{
    throw "Please specify the mailboxUpns"
}

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Set-MailboxMessageCopyForDelegated-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Exchange | Set-MailboxMessageCopyForDelegated | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Setting mailbox to save sent emails in own sent items folder"
try
{
    Write-Host "  Connecting to Exchange Online" -ForegroundColor $CommandInfo
    LoginTo-EXO

    foreach($mailboxUpn in $mailboxUpns)
    {

        Write-Host "Mailbox: $mailboxUpn" -ForegroundColor $CommandInfo
        $mbx = Get-Mailbox $mailboxUpn

        if (-Not $mbx.MessageCopyForSendOnBehalfEnabled)
        {
            Write-Warning "MessageCopyForSendOnBehalfEnabled was not enabled. Enabling it now"
            Set-Mailbox $mailboxUpn -MessageCopyForSendOnBehalfEnabled $True
        }
        else
        {
            Write-Host "MessageCopyForSendOnBehalfEnabled was already enabled."
        }

        if (-Not $mbx.MessageCopyForSentAsEnabled)
        {
            Write-Warning "MessageCopyForSentAsEnabled was not enabled. Enabling it now"
            Set-Mailbox $mailboxUpn -MessageCopyForSentAsEnabled $True
        }
        else
        {
            Write-Host "MessageCopyForSentAsEnabled was already enabled."
        }

        if (-Not $mbx.MessageCopyForSMTPClientSubmissionEnabled)
        {
            Write-Warning "MessageCopyForSMTPClientSubmissionEnabled was not enabled. Enabling it now"
            Set-Mailbox $mailboxUpn -MessageCopyForSMTPClientSubmissionEnabled $True
        }
        else
        {
            Write-Host "MessageCopyForSMTPClientSubmissionEnabled was already enabled."
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