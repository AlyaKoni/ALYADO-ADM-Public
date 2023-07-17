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
    27.02.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$userEmailToReset,
    [Parameter(Mandatory = $false)]
    [string]$newUserEmail = $null,
    [Parameter(Mandatory = $false)]
    [string]$inviteRedirectUrl = "http://myapps.microsoft.com"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Reset-GuestInvitation-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users" -exactVersion 1.28.0

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MgGraph -Scopes "User.ReadWrite.All"

# =============================================================
# Graph stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Guests | Reset-GuestInvitation | AAD" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking user
Write-Host "Checking user" -ForegroundColor $CommandInfo
$user = Get-MgBetaUser -Filter "startsWith(mail, '$userEmailToReset')"
if (-Not $user)
{
    throw "User $userEmailToReset not found"
}

if (-Not $newUserEmail)
{

    # Resetting invitation
    Write-Host "Resetting invitation" -ForegroundColor $CommandInfo
    New-MgBetaInvitation `
        -InvitedUserEmailAddress $user.Mail `
        -InviteRedirectUrl $inviteRedirectUrl `
        -ResetRedemption `
        -SendInvitationMessage `
        -InvitedUser $user

}
else
{

    # Resetting invitation with new email
    Write-Host "Resetting invitation with new email" -ForegroundColor $CommandInfo
    $otherMails = $user.OtherMails
    if ($user.Mail -notin $otherMails)
    {
        $otherMails += $user.Mail
    }
    Update-MgBetaUser -UserId $user.Id -Mail $newUserEmail -OtherMails $otherMails
    $invitation = New-MgBetaInvitation `
        -InvitedUserEmailAddress $newUserEmail `
        -InviteRedirectUrl $inviteRedirectUrl `
        -ResetRedemption `
        -SendInvitationMessage `
        -InvitedUser $user
    Write-Host "InviteRedeemUrl: $($invitation.InviteRedeemUrl)"
}

#Stopping Transscript
Stop-Transcript
