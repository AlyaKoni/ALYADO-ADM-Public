﻿#Requires -Version 2.0

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
    14.01.2021 Konrad Brunner       Initial Creation

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Setup-DoNotReplySharedMailbox-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "EXCHANGE | Setup-DoNotReplySharedMailbox | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Configuring DoNotReply Shared Mailbox in Exchange"
try
{
    Write-Host "  Connecting to Exchange Online" -ForegroundColor $CommandInfo
    LoginTo-EXO

    $mailbox = Get-Mailbox -Identity "DoNotReply" -ErrorAction SilentlyContinue
    if (-Not $mailbox)
    {
        Write-Warning "Creating the shared mailbox DoNotReply"
        New-Mailbox -Shared -Name "DoNotReply" -DisplayName "DoNotReply" -Alias "DoNotReply"
    }
    $retries = 10
    $mailbox = $null
    do {
        try {
            Start-Sleep -Seconds 5
            $retries--
            if ($retries -lt 0) { throw "Error creating mailbox" }
            $mailbox = Get-Mailbox -Identity "DoNotReply"
        }
        catch {
            <#Do this if a terminating exception happens#>
        }
    } while (-Not $mailbox)
    $doNotReplyUserId = $mailbox.ExternalDirectoryObjectId
    $doNotReplyEmail = $mailbox.EmailAddresses[0].Replace("SMTP:","")

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

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "EXCHANGE | Setup-DoNotReplySharedMailbox | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

if ($doNotReplyUserId)
{
    Write-Host "Blocking DoNotReply account from login"
    Update-AzADUser -ObjectId $doNotReplyUserId -EnableAccount $false
}

#Stopping Transscript
Stop-Transcript
