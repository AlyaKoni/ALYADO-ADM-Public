#Requires -Version 2.0

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
    04.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [String]$userToImport = "konrad.brunner@alyaconsulting.ch",
    [SecureString]$newPassword = $null
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\onprem\Import-AndSyncAadUser-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Check-Module ActiveDirectory
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "MSOnline"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MSOL

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AD | Import-AndSyncAadUser | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$aadUser = Get-MsolUser -UserPrincipalName $userToImport -ErrorAction SilentlyContinue
if (-Not $aadUser)
{
    Write-Error "Can't find user with UPN '$($userToImport)' in online AAD" -ErrorAction Continue
    return
}
$adUser = Get-ADUser -Filter "UserPrincipalName -eq '$($userToImport)'" -ErrorAction SilentlyContinue
if ($adUser)
{
    Write-Error "User with UPN '$($userToImport)' already exists in local AD" -ErrorAction Continue
}
else
{
    Write-Host "Creating user with UPN '$($userToImport)' in local AD"
    $san = $userToImport.Substring(0, $userToImport.IndexOf("@"))
    New-ADUser -SamAccountName $san -GivenName $aadUser.LastName -Surname $aadUser.FirstName -Name $aadUser.DisplayName -DisplayName $aadUser.DisplayName -EmailAddress $aadUser.UserPrincipalName -UserPrincipalName $aadUser.UserPrincipalName -ChangePasswordAtLogon $false -AccountPassword $newPassword -Enabled $true
}

$adUser = Get-ADUser -Filter "UserPrincipalName -eq '$($userToImport)'" -ErrorAction SilentlyContinue
if ($aadUser.ImmutableId.ToString() -ne $adUser.objectGUID.ToString())
{
    $GUIDbyte = $adUser.objectGUID.ToByteArray()
    $immuID = [System.Convert]::ToBase64String($GUIDbyte)
    Set-MsolUser -UserPrincipalName $userToImport -ImmutableId $immuID
}

Start-ADSyncSyncCycle
Start-Sleep -Seconds 30

$aadUser = Get-MsolUser -UserPrincipalName $userToImport -ErrorAction SilentlyContinue
$aadUser.ImmutableId
$aadUser.Errors
$aadUser.DirSyncProvisioningErrors
$aadUser.LastDirSyncTime

#$password = ConvertTo-SecureString -String "#############" -AsPlainText -Force
#Set-ADAccountPassword -Identity $adUser -NewPassword $password

#Stopping Transscript
Stop-Transcript