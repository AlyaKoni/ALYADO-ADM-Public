﻿#Requires -Version 7.0

<#
    Copyright (c) Alya Consulting, 2022-2023

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
    18.10.2022 Konrad Brunner       Initial Version
    25.03.2023 Konrad Brunner       Added assignedGroups parameter
    23.04.2023 Konrad Brunner       Switched to MgGraph module

#>

[CmdletBinding()]
Param(
    [bool]$assignedGroups = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\teams\Configure-ProjectsTeam-$($AlyaTimeString).log" | Out-Null

# Constants
[string]$TitleAndGroupName = "$($AlyaCompanyNameShortM365.ToUpper())TM-PRJ-ProjekteIntern"
[string]$Description = "Projekt Team fuer interne Benutzer."
[string]$Visibility = "Private"
[string[]]$Owners = $AlyaTeamsNewAdmins
[string]$TeamPicturePath = $AlyaLogoUrlQuad
[string]$DynamicMembershipRule = "(user.userType -eq `"Member`")"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MicrosoftTeams"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Teams"

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
Write-Host "Teams | Configure-ProjectsTeam | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking team
Write-Host "Checking team" -ForegroundColor $CommandInfo
$Team = Get-Team -DisplayName $TitleAndGroupName -ErrorAction SilentlyContinue
$TeamHasBeenCreated = $false
if (-Not $Team)
{
    Write-Warning "Team $TitleAndGroupName does not exist. Creating it now."
    $Team = New-Team -DisplayName $TitleAndGroupName -Description $Description -Visibility $Visibility
    Start-Sleep -Seconds 10
    $TeamHasBeenCreated = $true
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

# Setting team access
Write-Host "Setting team access" -ForegroundColor $CommandInfo
Set-Team -GroupId $Team.GroupId `
    -AllowAddRemoveApps $false `
    -AllowChannelMentions $false `
    -AllowCreatePrivateChannels $false `
    -AllowCreateUpdateChannels $false `
    -AllowCreateUpdateRemoveConnectors $false `
    -AllowCreateUpdateRemoveTabs $false `
    -AllowCustomMemes $false `
    -AllowDeleteChannels $false `
    -AllowGiphy $false `
    -AllowGuestCreateUpdateChannels $false `
    -AllowGuestDeleteChannels $false `
    -AllowOwnerDeleteMessages $true `
    -AllowStickersAndMemes $false `
    -AllowTeamMentions $false `
    -AllowUserDeleteMessages $false `
    -AllowUserEditMessages $false

# Getting groups
Write-Host "Getting groups" -ForegroundColor $CommandInfo
$allGroups = Get-MgGroup -All

# Checking team owners
Write-Host "Checking team owners" -ForegroundColor $CommandInfo
$NewOwners = @()
foreach($memb in $Owners)
{
    if ($memb.IndexOf("@") -gt -1)
    {
        # is email
        $user = Get-MgUser -UserId $memb
        if (-Not $user)
        {
            $group = $allGroups | where { $_.MailNickname -eq $memb.Substring(0,$memb.IndexOf("@")) }
            if (-Not $group)
            {
                throw "Can't find a user or group with email $memb"
            }
            else
            {
                Get-MgGroupMember -GroupId $group.Id | foreach {
                    if ($_.AdditionalProperties.userPrincipalName -notlike "*#EXT#*" -and $NewOwners -notcontains $_.AdditionalProperties.userPrincipalName)
                    {
                        $NewOwners += $_.AdditionalProperties.userPrincipalName
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
        $user = Get-MgUser -UserId $memb
        if (-Not $user)
        {
            $group = $allGroups | where { $_.Id -eq $memb }
            if (-Not $group)
            {
                throw "Can't find a user or group with id $memb"
            }
            else
            {
                Get-MgGroupMember -GroupId $group.Id | foreach {
                    if ($_.AdditionalProperties.userPrincipalName -notlike "*#EXT#*" -and $NewOwners -notcontains $_.AdditionalProperties.userPrincipalName)
                    {
                        $NewOwners += $_.AdditionalProperties.userPrincipalName
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
$SettingTemplate = Get-MgDirectorySettingTemplate | where { $_.DisplayName -eq "Group.Unified.Guest" }
$Setting = Get-MgGroupSetting -GroupId $Team.GroupId | where { $_.TemplateId -eq $SettingTemplate.Id }
if (-Not $Setting)
{
    Write-Warning "Setting not yet created. Creating one based on template."
    $Values = @()
    foreach($dval in $SettingTemplate.Values) {
	    $Values += @{Name = $dval.Name; Value = $dval.DefaultValue}
    }
    $Setting = New-MgGroupSetting -GroupId $Team.GroupId -DisplayName "Group.Unified.Guest" -TemplateId $SettingTemplate.Id -Values $Values
    $Setting = Get-MgGroupSetting -GroupId $Team.GroupId | where { $_.TemplateId -eq $SettingTemplate.Id }
}
$Value = $Setting.Values | where { $_.Name -eq "AllowToAddGuests" }
if ($Value.Value -eq $true) {
    Write-Host "Setting 'AllowToAddGuests' was already set to '$true'"
} 
else {
    Write-Warning "Setting 'AllowToAddGuests' was set to '$($Value.Value)' updating to '$true'"
    ($Setting.Values | where { $_.Name -eq "AllowToAddGuests" }).Value = $true
}
Update-MgGroupSetting -GroupId $Team.GroupId -DirectorySettingId $Setting.Id -Values $Setting.Values

# Checking members
Write-Host "Checking members" -ForegroundColor $CommandInfo
if (-Not $assignedGroups)
{
    # Setting DynamicMembershipRule
    Write-Host "Setting DynamicMembershipRule" -ForegroundColor $CommandInfo
    $group = Update-MgGroup -GroupId $Team.GroupId -GroupTypes "DynamicMembership", "Unified" `
        -MembershipRule $DynamicMembershipRule -MembershipRuleProcessingState "On"
}
else
{
    $group = $allGroups | where { $_.DisplayName -eq $AlyaAllInternals }
    if (-Not $group)
    {
        throw "Can't find a user or group $AlyaAllInternals"
    }
    else
    {
        $TMembers = Get-TeamUser -GroupId $Team.GroupId -Role Member
        $NewMembers = @()
        Get-MgGroupMember -GroupId $group.Id | foreach {
            if ($_.AdditionalProperties.userPrincipalName -notlike "*#EXT#*")
            {
                $NewMembers += $_.AdditionalProperties.userPrincipalName
            }
        }
        foreach($memb in $NewMembers)
        {
            $fnd = $false
            foreach($tmemb in $TMembers)
            {
                if ($memb -eq $tmemb.User)
                {
                    $fnd = $true
                    break
                }
            }
            if (-Not $fnd)
            {
                Write-Warning "Adding member $memb to team."
                Add-TeamUser -GroupId $Team.GroupId -Role Member -User $memb
            }
        }
    }
}

# Posting welcome messages
if ($TeamHasBeenCreated)
{
    Write-Host "Posting welcome messages" -ForegroundColor $CommandInfo
    $postMessageDE = "<h1>Willkommen</h1>"
    $postMessageDE += "<p>Willkommen im Projekt-Team von $($AlyaCompanyNameFull). In diesem Team verwalten wir unsere aktuellen internen Projekte. Dieses Team kann nicht mit externen geteilt werden!</p>"
    $postMessageEN = "<h1>Welcome</h1>"
    $postMessageEN += "<p>Welcome to the Project-Team from $($AlyaCompanyNameFull). In this team we manage our actual internal projects. This team can't be shared with externals!</p>"
    $bodyDE = @{
        body = @{
            contentType = "html"
            content = "$postMessageDE"
        }
    }
    $bodyEN = @{
        body = @{
            contentType = "html"
            content = "$postMessageEN"
        }
    }
    $Channel = Get-TeamChannel -GroupId $Team.GroupId
    $message = New-MgTeamChannelMessage -TeamId $Team.GroupId -ChannelId $Channel.Id -BodyParameter $bodyDE
    $message = New-MgTeamChannelMessage -TeamId $Team.GroupId -ChannelId $Channel.Id -BodyParameter $bodyEN

    Write-Host "Please pin now the created messages and" -ForegroundColor $CommandWarning
    Write-Host "set channel to allow only owners posting messages" -ForegroundColor $CommandWarning
    $teamLink = "https://teams.microsoft.com/_?tenantId=$($AlyaTenantId)#/conversations/Allgemein?groupId=$($Team.GroupId)&threadId=$($Channel.Id)2&ctx=channel"
    Write-Host "  $teamLink"
    start $teamLink
    pause
}


#Stopping Transscript
Stop-Transcript