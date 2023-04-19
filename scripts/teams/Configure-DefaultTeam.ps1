#Requires -Version 7.0

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
    08.07.2022 Konrad Brunner       Initial Version
    25.03.2023 Konrad Brunner       Added assignedGroups parameter

#>

[CmdletBinding()]
Param(
    [bool]$assignedGroups = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\teams\Configure-DefaultTeam-$($AlyaTimeString).log" | Out-Null

# Constants
[string]$TitleAndGroupName = "$($AlyaCompanyNameShortM365.ToUpper())TM"
[string]$Description = "Haupt Team fuer alle Benutzer. Intern und Extern."
[string]$Visibility = "Private"
[string[]]$Owners = @($AlyaTeamsNewTeamOwner,$AlyaTeamsNewTeamAdditionalOwner)
[string]$TeamPicturePath = $AlyaLogoUrlQuad
[string]$DynamicMembershipRule = "(user.accountEnabled -eq true)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Teams"
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "MicrosoftTeams"
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad
LoginTo-Teams

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Teams | Configure-DefaultTeam | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking team
Write-Host "Checking team" -ForegroundColor $CommandInfo
$Team = Get-Team -DisplayName $TitleAndGroupName -ErrorAction SilentlyContinue
$TeamHasBeenCreated = $false
if (-Not $Team)
{
    Write-Warning "Team $TitleAndGroupName does not exist. Creating it now."
    $Team = New-Team -DisplayName $TitleAndGroupName -Description $Description -Visibility $Visibility
    Start-Sleep -Seconds 60
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
$allGroups = Get-AzADGroup

# Checking team owners
Write-Host "Checking team owners" -ForegroundColor $CommandInfo
$NewOwners = @()
foreach($memb in $Owners)
{
    if ($memb.IndexOf("@") -gt -1)
    {
        # is email
        $user = Get-AzADUser -UserPrincipalName $memb -ErrorAction SilentlyContinue
        if (-Not $user)
        {
            $group = $allGroups | where { $_.MailNickname -eq $memb.Substring(0,$memb.IndexOf("@")) }
            if (-Not $group)
            {
                throw "Can't find a user or group with email $memb"
            }
            else
            {
                $allMembers = Get-AzADGroupMember -GroupObjectId $group.Id | foreach {
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
            $group = $allGroups | where { $_.Id -eq $memb }
            if (-Not $group)
            {
                throw "Can't find a user or group with id $memb"
            }
            else
            {
                $allMembers = Get-AzADGroupMember -GroupObjectId $group.Id | foreach {
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

Write-Host "Checking team guest settings" -ForegroundColor $CommandInfo
$settings = Get-AzureADObjectSetting -TargetType "Groups" -TargetObjectId $Team.GroupId -All $true | where { $_.DisplayName -eq "Group.Unified.Guest" }
if (-Not $settings)
{
    Write-Warning "Created new team guest settings to disable Guests"
    $template = Get-AzureADDirectorySettingTemplate | ? {$_.displayname -eq "Group.Unified.Guest"}
    $settingsCopy = $template.CreateDirectorySetting()
    $settingsCopy["AllowToAddGuests"] = $true
    $settings = New-AzureADObjectSetting -TargetType "Groups" -TargetObjectId $Team.GroupId -DirectorySetting $settingsCopy
}
if ($settings["AllowToAddGuests"] -eq $false)
{
    Write-Warning "Existing team guest settings changed to disable Guests"
    $settings["AllowToAddGuests"] = $true
    $settings = Set-AzureADObjectSetting -TargetType "Groups" -TargetObjectId $Team.GroupId -Id $settings.Id -DirectorySetting $settings
}

if (-Not $assignedGroups)
{
    # Setting DynamicMembershipRule
    Write-Host "Setting DynamicMembershipRule" -ForegroundColor $CommandInfo
    $grp = Get-AzureADGroup -ObjectId $Team.GroupId
    $tmp = Set-AzureADMSGroup -Id $Team.GroupId -GroupTypes "DynamicMembership", "Unified" -MembershipRule $DynamicMembershipRule -MembershipRuleProcessingState "On" `
            -Description $grp.Description -DisplayName $grp.DisplayName -MailEnabled $grp.MailEnabled -MailNickname $grp.MailNickName `
            -SecurityEnabled $grp.SecurityEnabled
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
        $allMembers = Get-AzADGroupMember -GroupObjectId $group.Id | foreach {
            $user = Get-AzADUser -ObjectId $_.Id
            if ($user.UserPrincipalName -notlike "*#EXT#*")
            {
                $NewMembers += $user.UserPrincipalName
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
    $group = $allGroups | where { $_.DisplayName -eq $AlyaAllExternals }
    if (-Not $group)
    {
        throw "Can't find a user or group $AlyaAllExternals"
    }
    else
    {
        $TMembers = Get-TeamUser -GroupId $Team.GroupId -Role Guest
        $NewGuests = @()
        $allGuests = Get-AzADGroupMember -GroupObjectId $group.Id | foreach {
            $user = Get-AzADUser -ObjectId $_.Id
            if ($user.UserPrincipalName -like "*#EXT#*")
            {
                $NewGuests += $user.Mail
            }
        }
        $TGuests = Get-TeamUser -GroupId $Team.GroupId -Role Guest
        foreach($guest in $NewGuests)
        {
            $fnd = $false
            foreach($tguest in $TGuests)
            {
                if ($tguest.User -like "$($guest.Replace("@","_"))#*" )
                {
                    $fnd = $true
                    break
                }
            }
            if (-Not $fnd)
            {
                Write-Warning "Adding guest $guest to team."
                Add-TeamUser -GroupId $Team.GroupId -User $guest
            }
        }
    }
}

# Posting welcome message
if ($TeamHasBeenCreated)
{
    Write-Host "Posting welcome message" -ForegroundColor $CommandInfo
    $postMessageDE = "<h1>Willkommen</h1>"
    $postMessageDE += "<p>Willkommen im Teams von $($AlyaCompanyNameFull). Teams ist unsere Kommunikationsplatform. Unsere Dokumentenablage befindet sich grundsätzlich in SharePoint ($($AlyaSharePointUrl)). Teams verwenden wir für befristete Ablagen sowie für die Kommunikation nach Aussen.</p>"
    $postMessageDE += "<p>Falls Du gerne ein Teams für Dein Projekt oder Deine Kommunikation mit Externen hättest, kannst Du mit einer E-Mail an $($AlyaSupportEmail) Dein eigenes Team bestellen.</p>"
    $postMessageEN = "<h1>Welcome</h1>"
    $postMessageEN += "<p>Welcome to Teams from $($AlyaCompanyNameFull). Teams is our communication platform. In general we use SharePoint ($($AlyaSharePointUrl)) as our document repository. We use Teams for short term repositories or our external communicaion.</p>"
    $postMessageEN += "<p>Please write an email to $($AlyaSupportEmail), if you like to get your own team to use it in your project or to communicate with externals.</p>"
    $scopes = @(
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
    Connect-MgGraph -Scopes $scopes
    Select-MgProfile -Name "beta"
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
    $teamLink = "https://teams.microsoft.com/_?tenantId=$((Get-AzContext).Tenant.Id)#/conversations/Allgemein?groupId=$($Team.GroupId)&threadId=$($Channel.Id)2&ctx=channel"
    Write-Host "  $teamLink"
    start $teamLink
    pause
}

# Setting SharePoint access
Write-Host "Setting SharePoint access" -ForegroundColor $CommandInfo
$Channel = Get-TeamChannel -GroupId $Team.GroupId
$mgChannelFolder = Get-MgTeamChannelFileFolder -TeamId $Team.GroupId -ChannelId $Channel.Id
$mgChannelFolder = (Split-Path -Path (Split-Path -Path $mgChannelFolder.WebUrl -Parent) -Parent) -replace "\\", "/"
$siteCon = LoginTo-PnP -Url $mgChannelFolder
$mg = Get-PnPGroup -Connection $siteCon -AssociatedMemberGroup
Set-PnPGroupPermissions -Connection $siteCon -Identity $mg -RemoveRole @("Contributor","Editor") -ErrorAction SilentlyContinue

#Stopping Transscript
Stop-Transcript
