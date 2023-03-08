#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2023

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
    01.03.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Hashtable[]]$userEmailsToInvite = @(), #@({Name="";Mail=""},{Name="";Mail=""})
    [Bool]$sendInvitationMessage = $true,
    [String]$inviteRedirectUrl = "https://myapps.microsoft.com",
    [String]$invitedUserType = "Guest", #Guest, Member
    [String[]]$ccRecipients = @(),
    [String]$customizedMessageBody = "Bitte akzeptiere diese Einladung, damit wir Dich in unseren Systemen korrekt berechtigen können.",
    [String]$messageLanguage = "de"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Invite-Guests-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "AzureADPreview"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# Constants


# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Invite-Guests | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

if ($sendInvitationMessage)
{
    $invitedUserMessageInfo = New-Object Microsoft.Open.MSGraph.Model.InvitedUserMessageInfo
    if ($ccRecipients -and $ccRecipients.Length -gt 0)
    {
        $invitedUserMessageInfo.CcRecipients = New-Object System.Collections.Generic.List[Microsoft.Open.MSGraph.Model.Recipient]
    }
    foreach($ccRecipient in $ccRecipients)
    {
        $recpt = New-Object Microsoft.Open.MSGraph.Model.Recipient
        $addr = New-Object Microsoft.Open.MSGraph.Model.EmailAddress
        $addr.Address = $ccRecipient
        $recpt.EmailAddress = $addr
        $invitedUserMessageInfo.CcRecipients.Add($recpt)
    }
    $invitedUserMessageInfo.CustomizedMessageBody = $customizedMessageBody
    $invitedUserMessageInfo.MessageLanguage = $messageLanguage
}

foreach($userEmailToInvite in $userEmailsToInvite)
{
    Write-Host "Inviting guest $($userEmailToInvite.Mail)" -ForegroundColor $CommandInfo
    if ($sendInvitationMessage)
    {
        New-AzureADMSInvitation `
           -InvitedUserDisplayName $userEmailToInvite.Name `
           -InvitedUserEmailAddress $userEmailToInvite.Mail `
           -SendInvitationMessage $sendInvitationMessage `
           -InviteRedirectUrl $inviteRedirectUrl `
           -InvitedUserMessageInfo $invitedUserMessageInfo `
           -InvitedUserType $invitedUserType
    }
    else
    {
        New-AzureADMSInvitation `
           -InvitedUserDisplayName $userEmailToInvite.Name `
           -InvitedUserEmailAddress $userEmailToInvite.Mail `
           -SendInvitationMessage $sendInvitationMessage `
           -InviteRedirectUrl $inviteRedirectUrl `
           -InvitedUserType $invitedUserType
    }
}

#Stopping Transscript
Stop-Transcript
