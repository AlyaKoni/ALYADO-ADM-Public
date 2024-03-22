#Requires -Version 7.0

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
    18.10.2022 Konrad Brunner       Initial Version
    25.03.2023 Konrad Brunner       Added assignedGroups parameter
    23.04.2023 Konrad Brunner       Switched to MgGraph module
    05.08.2023 Konrad Brunner       Added browser param

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [bool]$assignedGroups = $false,
    [Parameter(Mandatory=$false)]
    [object]$seleniumBrowser = $null
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
[string]$TeamPicturePath = $AlyaLogoUrlQuadDark
if ([string]::IsNullOrEmpty($TeamPicturePath)) { $TeamPicturePath = $AlyaLogoUrlQuad }
[string]$DynamicMembershipRule = "(user.userType -eq `"Member`")"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MicrosoftTeams"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Teams"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"

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

# Configuring browser
if ($seleniumBrowser) {
    $browser = $seleniumBrowser
} else {
	if (-Not $browser)
	{
		if ($Global:AlyaSeleniumBrowser) {
			$browser = $Global:AlyaSeleniumBrowser
		} else {
			$browser = Get-SeleniumBrowser
		}
	}
}

# Checking team
Write-Host "Checking team" -ForegroundColor $CommandInfo
$Team = Get-Team -DisplayName $TitleAndGroupName -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $TitleAndGroupName }
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
    $Team = Get-Team -DisplayName $TitleAndGroupName -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $TitleAndGroupName }
    if (-Not $Team -or -Not $Team.GroupId) { 
        Write-Host "Waiting for Teams..."
        Start-Sleep -Seconds 10
    }
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
        $user = Get-MgBetaUser -UserId $memb
        if (-Not $user)
        {
            $group = $allGroups | Where-Object { $_.Id -eq $memb }
            if (-Not $group)
            {
                throw "Can't find a user or group with id $memb"
            }
            else
            {
                Get-MgBetaGroupMember -GroupId $group.Id | Foreach-Object {
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
if ($Value.Value -eq $false) {
    Write-Host "Setting 'AllowToAddGuests' was already set to '$false'"
} 
else {
    Write-Warning "Setting 'AllowToAddGuests' was set to '$($Value.Value)' updating to '$false'"
    ($Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }).Value = $false
}
Update-MgBetaGroupSetting -GroupId $Team.GroupId -DirectorySettingId $Setting.Id -Values $Setting.Values

# Checking members
Write-Host "Checking members" -ForegroundColor $CommandInfo
if (-Not $assignedGroups)
{
    # Setting DynamicMembershipRule
    Write-Host "Setting DynamicMembershipRule" -ForegroundColor $CommandInfo
    $group = Update-MgBetaGroup -GroupId $Team.GroupId -GroupTypes "DynamicMembership", "Unified" `
        -MembershipRule $DynamicMembershipRule -MembershipRuleProcessingState "On"
}
else
{
    $group = $allGroups | Where-Object { $_.DisplayName -eq $AlyaAllInternals }
    if (-Not $group)
    {
        throw "Can't find a user or group $AlyaAllInternals"
    }
    else
    {
        $TMembers = Get-TeamUser -GroupId $Team.GroupId -Role Member
        $NewMembers = @()
        Get-MgBetaGroupMember -GroupId $group.Id | Foreach-Object {
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
$Channel = Get-TeamChannel -GroupId $Team.GroupId
$msgs = Get-MgBetaTeamChannelMessage -TeamId $Team.GroupId -ChannelId $Channel.Id | Where-Object { $_.MessageType -eq "message" }
if (-Not $msgs -or $msgs.Count -eq 0)
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
    $message = New-MgBetaTeamChannelMessage -TeamId $Team.GroupId -ChannelId $Channel.Id -BodyParameter $bodyDE
    $message = New-MgBetaTeamChannelMessage -TeamId $Team.GroupId -ChannelId $Channel.Id -BodyParameter $bodyEN

    Write-Host "Please pin now the created messages and" -ForegroundColor $CommandWarning
    Write-Host "set channel to allow only owners posting messages" -ForegroundColor $CommandWarning
    $teamLink = "https://teams.microsoft.com/v2/_?tenantId=$($AlyaTenantId)#/conversations/Allgemein?groupId=$($Team.GroupId)&threadId=$($Channel.Id)&ctx=channel"
    Write-Host "  $teamLink"
    if (-Not $browser) {
        Start-Process "$teamLink"
    } else {
        $browser.Url =  "$teamLink"
    }
    pause
}


#Stopping Transscript
Stop-Transcript
