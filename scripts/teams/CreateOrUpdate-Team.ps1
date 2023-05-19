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
    16.08.2021 Konrad Brunner       Initial Version
    23.04.2023 Konrad Brunner       Switched to MgGraph module

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$TitleAndGroupName,
    [Parameter(Mandatory=$false)]
    [string]$Description = "",
    [Parameter(Mandatory=$false)]
    [ValidateSet('Private','Public','HiddenMembership')]
    [string]$Visibility = "Private",
    [Parameter(Mandatory=$false)]
    [string[]]$Owners = @(),
    [Parameter(Mandatory=$false)]
    [string[]]$Members = @(),
    [Parameter(Mandatory=$false)]
    [string[]]$Guests = @(),
    [Parameter(Mandatory=$false)]
    [object[]]$AddChannels = @(),
    [Parameter(Mandatory=$false)]
    [switch]$OwerwriteMembersOwnersGuests = $false,
    [Parameter(Mandatory=$false)]
    [string]$TeamPicturePath = $null,
    [Parameter(Mandatory=$false)]
    [bool]$AllowToAddGuests = $true
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\teams\CreateOrUpdate-Team-$($AlyaTimeString).log" | Out-Null

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
Write-Host "Teams | CreateOrUpdate-Team | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking team
Write-Host "Checking team" -ForegroundColor $CommandInfo
$Team = Get-Team -DisplayName $TitleAndGroupName -ErrorAction SilentlyContinue
$TeamCreated = $false
if (-Not $Team)
{
    Write-Warning "Team $TitleAndGroupName does not exist. Creating it now."
    $TeamCreated = $true
    if ([string]::IsNullOrEmpty($Description))
    {
        $Team = New-Team -DisplayName $TitleAndGroupName -Visibility $Visibility
    }
    else
    {
        $Team = New-Team -DisplayName $TitleAndGroupName -Description $Description -Visibility $Visibility
    }
    $retry = 30
    do
    {
        Start-Sleep -Seconds 10
        $Team = Get-Team -DisplayName $TitleAndGroupName -ErrorAction SilentlyContinue
        $retry--
        if ($retry -lt 0)
        {
            throw "Not able to create team $TitleAndGroupName"
        }
    } while (-Not $Team)
}
else
{
    Write-Host "Team $TitleAndGroupName already exist. Updating."
    if ([string]::IsNullOrEmpty($Description))
    {
        $null = Set-Team -GroupId $Team.GroupId -DisplayName $TitleAndGroupName -Visibility $Visibility
    }
    else
    {
        $null = Set-Team -GroupId $Team.GroupId -DisplayName $TitleAndGroupName -Description $Description -Visibility $Visibility
    }
}

# Checking channels
Write-Host "Checking channels" -ForegroundColor $CommandInfo
$TeamChannels = Get-TeamChannel -GroupId $Team.GroupId
foreach($AddChannel in $AddChannels)
{
    Write-Host "Channel $($AddChannel.DisplayName)"
    $TeamChannel = $TeamChannels | Where-Object { $_.DisplayName -eq $AddChannel.DisplayName }
    if (-Not $TeamChannel)
    {
        Write-Warning "Channel does not exist. Creating it now."
        if ([string]::IsNullOrEmpty($AddChannel.Description))
        {
            $TeamChannel = New-TeamChannel -GroupId $Team.GroupId -DisplayName $AddChannel.DisplayName
        }
        else
        {
            $TeamChannel = New-TeamChannel -GroupId $Team.GroupId -DisplayName $AddChannel.DisplayName -Description $AddChannel.Description
        }
    }
    else
    {
        Write-Host "Channel already exist. Updating."
        if ([string]::IsNullOrEmpty($AddChannel.Description))
        {
            #$TeamChannel = Set-TeamChannel -GroupId $Team.GroupId -CurrentDisplayName $AddChannel.DisplayName
        }
        else
        {
            $TeamChannel = Set-TeamChannel -GroupId $Team.GroupId -CurrentDisplayName $AddChannel.DisplayName -Description $AddChannel.Description
        }
    }
}

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
            $group = $allGroups | Where-Object { $_.MailNickname -eq $memb.Substring(0,$memb.IndexOf("@")) }
            if (-Not $group)
            {
                throw "Can't find a user or group with email $memb"
            }
            else
            {
                Get-MgGroupMember -GroupId $group.Id | Foreach-Object {
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
            $group = $allGroups | Where-Object { $_.Id -eq $memb }
            if (-Not $group)
            {
                throw "Can't find a user or group with id $memb"
            }
            else
            {
                Get-MgGroupMember -GroupId $group.Id | Foreach-Object {
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
$TMembers = Get-TeamUser -GroupId $Team.GroupId -Role Owner
foreach($memb in $NewOwners)
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
        Write-Warning "Adding owner $memb to team."
        Add-TeamUser -GroupId $Team.GroupId -Role Owner -User $memb
    }
}
if ($OwerwriteMembersOwnersGuests)
{
    $TMembers = Get-TeamUser -GroupId $Team.GroupId -Role Owner
    foreach($tmemb in $TMembers)
    {
        if ($NewOwners -notcontains $tmemb.User)
        {
            Remove-TeamUser -GroupId $Team.GroupId -Role Owner -User $tmemb.User
        }
    }
}

# Checking team members
Write-Host "Checking team members" -ForegroundColor $CommandInfo
$NewMembers = @()
foreach($memb in $Members)
{
    if ($memb.IndexOf("@") -gt -1)
    {
        # is email
        $user = Get-MgUser -UserId $memb
        if (-Not $user)
        {
            $group = $allGroups | Where-Object { $_.MailNickname -eq $memb.Substring(0,$memb.IndexOf("@")) }
            if (-Not $group)
            {
                throw "Can't find a user or group with email $memb"
            }
            else
            {
                Get-MgGroupMember -GroupId $group.Id | Foreach-Object {
                    if ($_.AdditionalProperties.userPrincipalName -notlike "*#EXT#*" -and $NewMembers -notcontains $_.AdditionalProperties.userPrincipalName)
                    {
                        $NewMembers += $_.AdditionalProperties.userPrincipalName
                    }
                }
            }
        }
        else
        {
            if ($NewMembers -notcontains $memb)
            {
                $NewMembers += $memb
            }
        }
    }
    else
    {
        # is guid
        $user = Get-MgUser -UserId $memb
        if (-Not $user)
        {
            $group = $allGroups | Where-Object { $_.Id -eq $memb }
            if (-Not $group)
            {
                throw "Can't find a user or group with id $memb"
            }
            else
            {
                Get-MgGroupMember -GroupId $group.Id | Foreach-Object {
                    if ($_.AdditionalProperties.userPrincipalName -notlike "*#EXT#*" -and $NewMembers -notcontains $_.AdditionalProperties.userPrincipalName)
                    {
                        $NewMembers += $_.AdditionalProperties.userPrincipalName
                    }
                }
            }
        }
        else
        {
            if ($NewMembers -notcontains $user.UserPrincipalName)
            {
                $NewMembers += $user.UserPrincipalName
            }
        }
    }
}
$TMembers = Get-TeamUser -GroupId $Team.GroupId -Role Member
foreach($memb in $NewMembers)
{
    if ($NewMembers -notcontains $memb)
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
if ($OwerwriteMembersOwnersGuests)
{
    $TMembers = Get-TeamUser -GroupId $Team.GroupId -Role Member
    foreach($tmemb in $TMembers)
    {
        if ($NewMembers -notcontains $tmemb.User)
        {
            Remove-TeamUser -GroupId $Team.GroupId -Role Member -User $tmemb.User
        }
    }
}

# Checking team guests
if ($AllowToAddGuests)
{
    Write-Host "Checking team guest settings" -ForegroundColor $CommandInfo
    $SettingTemplate = Get-MgDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Group.Unified.Guest" }
    $Setting = Get-MgGroupSetting -GroupId $Team.GroupId | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
    if (-Not $Setting)
    {
        Write-Warning "Setting not yet created. Creating one based on template."
        $Values = @()
        foreach($dval in $SettingTemplate.Values) {
            $Values += @{Name = $dval.Name; Value = $dval.DefaultValue}
        }
        $Setting = New-MgGroupSetting -GroupId $Team.GroupId -DisplayName "Group.Unified.Guest" -TemplateId $SettingTemplate.Id -Values $Values
        $Setting = Get-MgGroupSetting -GroupId $Team.GroupId | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
    }
    $Value = $Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }
    if ($Value.Value -eq $true) {
        Write-Host "Setting 'AllowToAddGuests' was already set to '$true'"
    } 
    else {
        Write-Warning "Setting 'AllowToAddGuests' was set to '$($Value.Value)' updating to '$true'"
        ($Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }).Value = $true
    }
    Update-MgGroupSetting -GroupId $Team.GroupId -DirectorySettingId $Setting.Id -Values $Setting.Values

    Write-Host "Checking team guests" -ForegroundColor $CommandInfo
    $NewGuests = @()
    foreach($memb in $Guests)
    {
        if ($memb.IndexOf("@") -gt -1)
        {
            # is email
            $user = Get-MgUser -UserId $memb
            if (-Not $user)
            {
                $group = $allGroups | Where-Object { $_.MailNickname -eq $memb.Substring(0,$memb.IndexOf("@")) }
                if (-Not $group)
                {
                    throw "Can't find a user or group with email $memb"
                }
                else
                {
                    Get-MgGroupMember -GroupId $group.Id | Foreach-Object {
                        if ($_.AdditionalProperties.userPrincipalName -notlike "*#EXT#*" -and $NewGuests -notcontains $_.AdditionalProperties.userPrincipalName)
                        {
                            throw "TODO"
                            $NewGuests += $_.Mail
                        }
                    }
                }
            }
            else
            {
                if ($NewGuests -notcontains $user.Mail)
                {
                    throw "TODO"
                    $NewGuests += $user.Mail
                }
            }
        }
        else
        {
            # is guid
            $user = Get-MgUser -UserId $memb
            if (-Not $user)
            {
                $group = $allGroups | Where-Object { $_.Id -eq $memb }
                if (-Not $group)
                {
                    throw "Can't find a user or group with id $memb"
                }
                else
                {
                    Get-MgGroupMember -GroupId $group.Id | Foreach-Object {
                        if ($_.AdditionalProperties.userPrincipalName -notlike "*#EXT#*" -and $NewGuests -notcontains $_.AdditionalProperties.userPrincipalName)
                        {
                            throw "TODO"
                            $NewGuests += $_.Mail
                        }
                    }
                }
            }
            else
            {
                if ($NewGuests -notcontains $user.Mail)
                {
                    throw "TODO"
                    $NewGuests += $user.Mail
                }
            }
        }
    }
    $TMembers = Get-TeamUser -GroupId $Team.GroupId -Role Guest
    foreach($memb in $NewGuests)
    {
        $fnd = $false
        foreach($tmemb in $TMembers)
        {
            if ($tmemb.User -like "$($memb.Replace("@","_"))#*" )
            {
                $fnd = $true
                break
            }
        }
        if (-Not $fnd)
        {
            Write-Warning "Adding guest $memb to team."
            Add-TeamUser -GroupId $Team.GroupId -User $memb
        }
    }
    if ($OwerwriteMembersOwnersGuests)
    {
        $TMembers = Get-TeamUser -GroupId $Team.GroupId -Role Guest
        foreach($tmemb in $TMembers)
        {
            $fnd = $false
            foreach($guest in $NewGuests)
            {
                if ($tmemb.User -like "$($guest.Replace("@","_"))#*" )
                {
                    $fnd = $true
                    break
                }
            }
            if (-Not $fnd)
            {
                Write-Warning "Removing guest $memb from team."
                Remove-TeamUser -GroupId $Team.GroupId -User $tmemb.User
            }
        }
    }
}
else
{
    Write-Host "Checking team guest settings" -ForegroundColor $CommandInfo
    $SettingTemplate = Get-MgDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Group.Unified.Guest" }
    $Setting = Get-MgGroupSetting -GroupId $Team.GroupId | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
    if (-Not $Setting)
    {
        Write-Warning "Setting not yet created. Creating one based on template."
        $Values = @()
        foreach($dval in $SettingTemplate.Values) {
            $Values += @{Name = $dval.Name; Value = $dval.DefaultValue}
        }
        $Setting = New-MgGroupSetting -GroupId $Team.GroupId -DisplayName "Group.Unified.Guest" -TemplateId $SettingTemplate.Id -Values $Values
        $Setting = Get-MgGroupSetting -GroupId $Team.GroupId | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
    }
    $Value = $Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }
    if ($Value.Value -eq $false) {
        Write-Host "Setting 'AllowToAddGuests' was already set to '$false'"
    } 
    else {
        Write-Warning "Setting 'AllowToAddGuests' was set to '$($Value.Value)' updating to '$false'"
        ($Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }).Value = $false
    }
    Update-MgGroupSetting -GroupId $Team.GroupId -DirectorySettingId $Setting.Id -Values $Setting.Values

}

# Setting logo
Write-Host "Setting logo" -ForegroundColor $CommandInfo
if ($TeamPicturePath)
{
    if ($TeamCreated) { Start-Sleep -Seconds 60}
    $null = Set-TeamPicture -GroupId $Team.GroupId -ImagePath $TeamPicturePath
}

# Stopping Transscript
Stop-Transcript
