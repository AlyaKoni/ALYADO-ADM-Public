#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    03.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    $samAccName = "konradbrunner"
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Reading configuration
Import-Module "ActiveDirectory" -ErrorAction Stop

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\upnchange\Change-UpnInAdSingleUser-$($AlyaTimeString).log" | Out-Null

# =============================================================
# AD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "UPNCHANGE | Change-UpnInAdSingleUser | AD" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main

#Changing UPN
$user = Get-ADUser $samAccName -Properties *
Write-Host "Changing UPN from $($samAccName)" -ForegroundColor $CommandInfo
if (-Not [string]::IsNullOrEmpty($user.mail))
{
	if ($user.UserPrincipalName -eq $user.mail)
	{
		Write-Host " - Users UPN was already in right format"
	}
	else
	{
		Set-ADUser -Identity $samAccName -UserPrincipalName $user.mail
	}
}
else
{
	if (-Not [string]::IsNullOrEmpty($user.WindowsEmailAddress))
	{
		if ($user.UserPrincipalName -eq $user.WindowsEmailAddress)
		{
			Write-Host " - Users UPN was already in right format"
		}
		else
		{
			Set-ADUser -Identity $samAccName -UserPrincipalName $user.WindowsEmailAddress
		}
	}
	else
	{
		if (-Not [string]::IsNullOrEmpty($user.givenName) -and -Not [string]::IsNullOrEmpty($user.sn))
		{
			if ($user.UserPrincipalName -eq "$($user.givenName).$($user.sn)@$($AlyaDomainName)")
			{
				Write-Host " - Users UPN was already in right format"
			}
			else
			{
				Set-ADUser -Identity $samAccName -UserPrincipalName "$($user.givenName).$($user.sn)@$($AlyaDomainName)"
			}
		}
		else
		{
			Write-Host "Can't set UPN for this user"
		}
	}
}
repadmin /syncall /AdeP

#Stopping Transscript
Stop-Transcript