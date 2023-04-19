#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2021

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
    16.08.2021 Konrad Brunner       Initial Version

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
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "MicrosoftTeams"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad
LoginTo-Teams

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
    $TeamChannel = $TeamChannels | where { $_.DisplayName -eq $AddChannel.DisplayName }
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
                    if ($_.UserPrincipalName -notlike "*#EXT#*" -and $NewMembers -notcontains $_.UserPrincipalName)
                    {
                        $NewMembers += $_.UserPrincipalName
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
                    if ($_.UserPrincipalName -notlike "*#EXT#*" -and $NewMembers -notcontains $_.UserPrincipalName)
                    {
                        $NewMembers += $_.UserPrincipalName
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
    Write-Host "Checking team guests" -ForegroundColor $CommandInfo
    $NewGuests = @()
    foreach($memb in $Guests)
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
                        if ($_.UserPrincipalName -notlike "*#EXT#*" -and $NewGuests -notcontains $_.UserPrincipalName)
                        {
                            $NewGuests += $_.Mail
                        }
                    }
                }
            }
            else
            {
                if ($NewGuests -notcontains $user.Mail)
                {
                    $NewGuests += $user.Mail
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
                        if ($_.UserPrincipalName -notlike "*#EXT#*" -and $NewGuests -notcontains $_.UserPrincipalName)
                        {
                            $NewGuests += $_.Mail
                        }
                    }
                }
            }
            else
            {
                if ($NewGuests -notcontains $user.Mail)
                {
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

    Write-Host "Checking team guest settings" -ForegroundColor $CommandInfo
    $settings = Get-AzureADObjectSetting -TargetType "Groups" -TargetObjectId $Team.GroupId -All $true | where { $_.DisplayName -eq "Group.Unified.Guest" }
    if ($settings)
    {
        if ($settings["AllowToAddGuests"] -eq $false)
        {
            Write-Warning "Existing team guest settings changed to allow Guests"
            $settings["AllowToAddGuests"] = $true
            $settings = Set-AzureADObjectSetting -TargetType "Groups" -TargetObjectId $Team.GroupId -Id $settings.Id -DirectorySetting $settings
        }
    }
}
else
{
    Write-Host "Checking team guest settings" -ForegroundColor $CommandInfo
    $settings = Get-AzureADObjectSetting -TargetType "Groups" -TargetObjectId $Team.GroupId -All $true | where { $_.DisplayName -eq "Group.Unified.Guest" }
    if (-Not $settings)
    {
        Write-Warning "Created new team guest settings to disable Guests"
        $template = Get-AzureADDirectorySettingTemplate | ? {$_.displayname -eq "Group.Unified.Guest"}
        $settingsCopy = $template.CreateDirectorySetting()
        $settingsCopy["AllowToAddGuests"] = $false
        $settings = New-AzureADObjectSetting -TargetType "Groups" -TargetObjectId $Team.GroupId -DirectorySetting $settingsCopy
    }
    if ($settings["AllowToAddGuests"] -eq $true)
    {
        Write-Warning "Existing team guest settings changed to disable Guests"
        $settings["AllowToAddGuests"] = $false
        $settings = Set-AzureADObjectSetting -TargetType "Groups" -TargetObjectId $Team.GroupId -Id $settings.Id -DirectorySetting $settings
    }
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
