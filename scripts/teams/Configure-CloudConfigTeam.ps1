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
    08.07.2022 Konrad Brunner       Initial Version
    23.04.2023 Konrad Brunner       Switched to MgGraph module

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\teams\Configure-CloudConfigTeam-$($AlyaTimeString).log" | Out-Null

# Constants
[string]$TitleAndGroupName = "$($AlyaCompanyNameShortM365.ToUpper())TM-ADM-CloudConfiguration"
[string]$Description = "Team fuer die Dokumentation der Cloud Konfiguration."
[string]$Visibility = "Private"
[string[]]$Owners = $AlyaTeamsNewAdmins
[string]$TeamPicturePath = $AlyaLogoUrlQuad

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MicrosoftTeams"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Teams"

# Logins
LoginTo-Teams
LoginTo-MgGraph -Scopes @(
    "Directory.ReadWrite.All",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "TeamsApp.ReadWrite.All",
    "TeamsAppInstallation.ReadWriteForTeam",
    "TeamsAppInstallation.ReadWriteSelfForTeam",
    "TeamSettings.ReadWrite.All",
    "TeamsTab.ReadWrite.All",
    "TeamMember.ReadWrite.All",
    "ChannelMessage.Send"
)

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Teams | Configure-CloudConfigTeam | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking team
Write-Host "Checking team" -ForegroundColor $CommandInfo
$Team = Get-Team -DisplayName $TitleAndGroupName -ErrorAction SilentlyContinue
if (-Not $Team)
{
    Write-Warning "Team $TitleAndGroupName does not exist. Creating it now."
    $Team = New-Team -DisplayName $TitleAndGroupName -Description $Description -Visibility $Visibility
    Start-Sleep -Seconds 10
}
else
{
    Write-Host "Team $TitleAndGroupName already exist. Updating."
    $null = Set-Team -GroupId $Team.GroupId -DisplayName $TitleAndGroupName -Description $Description -Visibility $Visibility
}
do
{
    $Team = Get-Team -DisplayName $TitleAndGroupName -ErrorAction SilentlyContinue
    if (-Not $Team -or -Not $Team.GroupId) { Start-Sleep -Seconds 2 }
}
while (-Not $Team -or -Not $Team.GroupId)
if ($TeamPicturePath)
{
    if ($TeamPicturePath.StartsWith("http"))
    {
        $fname = Split-Path -Path $TeamPicturePath -Leaf
        $tempFile = [System.IO.Path]::GetTempFileName()+$fname
        Invoke-RestMethod -Method GET -UseBasicParsing -Uri $TeamPicturePath -OutFile $tempFile
        $null = Set-TeamPicture -GroupId $Team.GroupId -ImagePath $tempFile
        Remove-Item -Path $tempFile
    }
    else
    {
        $null = Set-TeamPicture -GroupId $Team.GroupId -ImagePath $TeamPicturePath
    }
}

# Getting groups
Write-Host "Getting groups" -ForegroundColor $CommandInfo
$allGroups = Get-MgBetaGroup -All

# Checking team owners
Write-Host "Checking team owners" -ForegroundColor $CommandInfo
$NewOwners = @()
foreach($memb in $Owners)
{
    if ($memb.IndexOf("@") -gt -1)
    {
        # is email
        $user = Get-MgBetaUser -UserId $memb
        if (-Not $user)
        {
            $group = $allGroups | Where-Object { $_.MailNickname -eq $memb.Substring(0,$memb.IndexOf("@")) }
            if (-Not $group)
            {
                throw "Can't find a user or group with email $memb"
            }
            else
            {
                Get-MgBetaGroupMember -GroupId $group.Id | Foreach-Object {
                    if ($_.UserPrincipalName -notlike "*#EXT#*" -and $NewOwners -notcontains $_.UserPrincipalName)
                    {
                        $NewOwners += $_.UserPrincipalName
                    }
				}
            }
        }
        else
        {
            if ($NewOwners -notcontains $memb)
            {
                $NewOwners += $memb
            }
        }
    }
    else
    {
        # is guid
        $user = Get-AzADUser -ObjectId $memb -ErrorAction SilentlyContinue
        if (-Not $user)
        {
            $group = $allGroups | Where-Object { $_.Id -eq $memb }
            if (-Not $group)
            {
                throw "Can't find a user or group with id $memb"
            }
            else
            {
                $allMembers = Get-AzADGroupMember -GroupObjectId $group.Id | Foreach-Object {
                    if ($_.UserPrincipalName -notlike "*#EXT#*" -and $NewOwners -notcontains $_.UserPrincipalName)
                    {
                        $NewOwners += $_.UserPrincipalName
                    }
                }
            }
        }
        else
        {
            if ($NewOwners -notcontains $user.UserPrincipalName)
            {
                $NewOwners += $user.UserPrincipalName
            }
        }
    }
}
$TOwners = Get-TeamUser -GroupId $Team.GroupId -Role Owner
foreach($own in $NewOwners)
{
    $fnd = $false
    foreach($town in $TOwners)
    {
        if ($own -eq $town.User)
        {
            $fnd = $true
            break
        }
    }
    if (-Not $fnd)
    {
        Write-Warning "Adding owner $own to team."
        Add-TeamUser -GroupId $Team.GroupId -Role Owner -User $own
    }
}

# Checking team guest settings
Write-Host "Checking team guest settings" -ForegroundColor $CommandInfo
$SettingTemplate = Get-MgBetaDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Group.Unified.Guest" }
$Setting = Get-MgBetaGroupSetting -GroupId $Team.GroupId | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
if (-Not $Setting)
{
    Write-Warning "Setting not yet created. Creating one based on template."
    $Values = @()
    foreach($dval in $SettingTemplate.Values) {
	    $Values += @{Name = $dval.Name; Value = $dval.DefaultValue}
    }
    $Setting = New-MgBetaGroupSetting -GroupId $Team.GroupId -DisplayName "Group.Unified.Guest" -TemplateId $SettingTemplate.Id -Values $Values
    $Setting = Get-MgBetaGroupSetting -GroupId $Team.GroupId | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
}
$Value = $Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }
if ($Value.Value -eq $true) {
    Write-Host "Setting 'AllowToAddGuests' was already set to '$true'"
} 
else {
    Write-Warning "Setting 'AllowToAddGuests' was set to '$($Value.Value)' updating to '$true'"
    ($Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }).Value = $true
}
Update-MgBetaGroupSetting -GroupId $Team.GroupId -DirectorySettingId $Setting.Id -Values $Setting.Values

#Stopping Transscript
Stop-Transcript
