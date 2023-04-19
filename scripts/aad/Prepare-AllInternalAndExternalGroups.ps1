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
    25.03.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Prepare-AllInternalAndExternalGroups-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "MSOnline"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Prepare-AllInternalAndExternalGroups | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$AllInternalsGroup = Get-AzADGroup -DisplayName $AlyaAllInternals
$AllExternalsGroup = Get-AzADGroup -DisplayName $AlyaAllExternals

$AllUsers = Get-AzAdUser -Select "ExternalUserState" -AppendSelected
$AllInternalsGroupMembers = Get-AzADGroupMember -GroupObjectId $AllInternalsGroup.Id
$AllExternalsGroupMembers = Get-AzADGroupMember -GroupObjectId $AllExternalsGroup.Id

$AllUsers = Get-AzAdUser -Select "ExternalUserState" -AppendSelected
foreach($user in $AllUsers)
{
    if ($user.ExternalUserState -eq "Accepted")
    {
        Write-Host "Guest $($user.Mail)"
        $extMemb = $AllExternalsGroupMembers | where { $_.Id -eq $user.Id }
        if (-Not $extMemb)
        {
            Write-Warning "Adding to $AlyaAllExternals"
            Add-AzADGroupMember -TargetGroupObject $AllExternalsGroup -MemberUserPrincipalName $user.UserPrincipalName
        }
    }
    if (-Not $user.ExternalUserState)
    {
        Write-Host "Member $($user.UserPrincipalName)"
        $intMemb = $AllInternalsGroupMembers | where { $_.Id -eq $user.Id }
        if (-Not $intMemb)
        {
            Write-Warning "Adding to $AlyaAllExternals"
            Add-AzADGroupMember -TargetGroupObject $AllInternalsGroup -MemberUserPrincipalName $user.UserPrincipalName
        }
    }
}

#Stopping Transscript
Stop-Transcript
