#Requires -Version 2.0

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
    22.12.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string[]] [Parameter(Mandatory=$false)]
    $adminUsers = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\teams\Add-AdminsToAllTeams-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MicrosoftTeams"

# Logins
LoginTo-Teams

# =============================================================
# Teams stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Teams | Add-AdminsToAllTeams | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting all teams
$Teams = Get-Team

# Defining functions
function CheckNotIn($searchFor, $searchIn)
{
    $notfnd = $true
    foreach($search in $searchIn)
    {
        if ($search -like "*$searchFor*") { $notfnd = $false ; break }
        if ($searchFor -like "*$search*") { $notfnd = $false ; break }
    }
    return $notfnd
}

# Defining admins
$owners = @()
if (-Not [string]::IsNullOrEmpty($AlyaTeamsNewTeamOwner) -and $AlyaTeamsNewTeamOwner -ne "PleaseSepcify") { if (CheckNotIn -searchFor $AlyaTeamsNewTeamOwner -searchIn $owners) { $owners += $AlyaTeamsNewTeamOwner } }
if (-Not [string]::IsNullOrEmpty($AlyaTeamsNewTeamAdditionalOwner) -and $AlyaTeamsNewTeamAdditionalOwner -ne "PleaseSepcify") { if (CheckNotIn -searchFor $AlyaTeamsNewTeamAdditionalOwner -searchIn $owners) { $owners += $AlyaTeamsNewTeamAdditionalOwner } }
if ($AlyaTeamsNewAdmins -and $AlyaTeamsNewAdmins.Count -gt 0)
{
    foreach($AlyaTeamsNewTeamAdmin in $AlyaTeamsNewAdmins)
    {
        if (-Not [string]::IsNullOrEmpty($AlyaTeamsNewTeamAdmin) -and $AlyaTeamsNewTeamAdmin -ne "PleaseSepcify") { if (CheckNotIn -searchFor $AlyaTeamsNewTeamAdmin -searchIn $owners) { $owners += $AlyaTeamsNewTeamAdmin } }
    }
}
foreach($owner in $adminUsers)
{
    if (CheckNotIn -searchFor $owner -searchIn $owners) { $owners += $owner ; if (-Not $primaryAdmin) { $primaryAdmin = $owner } }
}

# Processing teams
foreach($Team in $Teams)
{
    #$Team = $Teams[22]
    Write-Host "Team $($Team.DisplayName)"
    $members = Get-TeamUser -GroupId $Team.GroupId -Role Owner
    foreach($memb in $owners)
    {
        if (CheckNotIn -searchFor $memb -searchIn $members.User)
        {
            Write-Warning "Adding owner $memb to team."
            Add-TeamUser -GroupId $Team.GroupId -Role Owner -User $memb
        }
    }
    
}

# Stopping Transscript
Stop-Transcript
