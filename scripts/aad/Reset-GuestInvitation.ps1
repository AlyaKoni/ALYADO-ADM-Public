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
    27.02.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$userEmailToReset,
    [Parameter(Mandatory = $false)]
    [string]$newUserEmail = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Reset-GuestInvitation-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Users"

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
$user = Get-MgUser -Filter "startsWith(mail, '$userEmailToReset')"
if (-Not $user)
{
    throw "User $userEmailToReset not found"
}

if (-Not $newUserEmail)
{

    # Resetting invitation
    Write-Host "Resetting invitation" -ForegroundColor $CommandInfo
    New-MgInvitation `
        -InvitedUserEmailAddress $user.Mail `
        -InviteRedirectUrl "http://myapps.microsoft.com" `
        -ResetRedemption `
        -SendInvitationMessage `
        -InvitedUser $user

}
else
{

    # Resetting invitation with new email
    Write-Host "Resetting invitation with new email" -ForegroundColor $CommandInfo
    $otherMails = $user.OtherMails
    $otherMails += $user.Mail
    Update-MgUser -UserId $user.Id -Mail $newUserEmail -OtherMails $otherMails
    New-MgInvitation `
        -InvitedUserEmailAddress $newUserEmail `
        -InviteRedirectUrl "http://myapps.microsoft.com" `
        -ResetRedemption `
        -SendInvitationMessage `
        -InvitedUser $user

}

#Stopping Transscript
Stop-Transcript