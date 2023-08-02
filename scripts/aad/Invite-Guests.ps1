#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2023

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
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Invite-Guests | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

if ($sendInvitationMessage)
{
    Import-Module "Microsoft.Graph.Beta.Identity.SignIns"
    $invitedUserMessageInfo = New-Object Microsoft.Graph.Beta.PowerShell.Models.MicrosoftGraphInvitedUserMessageInfo
    $recptList = New-Object System.Collections.Generic.List[Microsoft.Graph.Beta.PowerShell.Models.MicrosoftGraphRecipient]
    foreach($ccRecipient in $ccRecipients)
    {
        $recpt = New-Object Microsoft.Graph.Beta.PowerShell.Models.MicrosoftGraphRecipient
        $addr = New-Object Microsoft.Graph.Beta.PowerShell.Models.MicrosoftGraphEmailAddress
        $addr.Address = $ccRecipient
        $recpt.EmailAddress = $addr
        $recptList.Add($recpt)
    }
    if ($recptList.Count -gt 0)
    {
        $invitedUserMessageInfo.CcRecipients = $recptList
    }
    $invitedUserMessageInfo.CustomizedMessageBody = $customizedMessageBody
    $invitedUserMessageInfo.MessageLanguage = $messageLanguage
}

foreach($userEmailToInvite in $userEmailsToInvite)
{
    Write-Host "Inviting guest $($userEmailToInvite.Mail)" -ForegroundColor $CommandInfo
    if ($sendInvitationMessage)
    {
        $params = @{
            InvitedUserEmailAddress = $userEmailToInvite.Mail
            InvitedUserDisplayName = $userEmailToInvite.Name
            InviteRedirectUrl = $inviteRedirectUrl
            InvitedUserMessageInfo = $invitedUserMessageInfo
            InvitedUserType = $invitedUserType
            SendInvitationMessage = $sendInvitationMessage
        }
        New-MgBetaInvitation -BodyParameter $params
    }
    else
    {
        $params = @{
            InvitedUserEmailAddress = $userEmailToInvite.Mail
            InvitedUserDisplayName = $userEmailToInvite.Name
            InviteRedirectUrl = $inviteRedirectUrl
            InvitedUserType = $invitedUserType
            SendInvitationMessage = $sendInvitationMessage
        }
        New-MgBetaInvitation -BodyParameter $params
    }
}

#Stopping Transscript
Stop-Transcript
