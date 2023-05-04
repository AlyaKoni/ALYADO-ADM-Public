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
    11.06.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\groups\Find-InactiveGroups-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"
Install-ModuleIfNotInstalled "Microsoft.Online.SharePoint.PowerShell"
Install-ModuleIfNotInstalled "AzureAdPreview"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad
LoginTo-Msol
LoginTo-EXO

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Groups | Find-InactiveGroups | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$WarningDate = (Get-Date).AddDays(-365)
$Today = (Get-Date)

# Getting Groups
Write-Host "Getting Groups" -ForegroundColor $CommandInfo
$Groups = Get-Recipient -RecipientTypeDetails GroupMailbox -ResultSize Unlimited | Sort-Object DisplayName
$UsedUnifiedGroups = $false
if ($Groups.Count -eq 0)
{
    $Groups = Get-UnifiedGroup -ResultSize Unlimited | Sort-Object DisplayName 
    $UsedUnifiedGroups = $true
    if ($Groups.Count -eq 0) {
        throw "No Microsoft 365 Groups found"
    } 
}

# Getting Teams
Write-Host "Getting Teams" -ForegroundColor $CommandInfo
$TeamsList = @{}
if ($UsedUnifiedGroups -eq $false)
{
   Get-UnifiedGroup -Filter { ResourceProvisioningOptions -eq "Team" } -ResultSize Unlimited | Foreach-Object { $TeamsList.Add($_.ExternalDirectoryObjectId, $_.DisplayName) }
}
else
{
    $Groups | Where-Object {$_.ResourceProvisioningOptions -eq "Team"} | Foreach-Object { $TeamsList.Add($_.ExternalDirectoryObjectId, $_.DisplayName) }
}

# Loop groups
$GroupNumber = 0
foreach ($Group in $Groups)
{
    $Grp = Get-UnifiedGroup -Identity $Group.DistinguishedName
    $Obsolete = $false
    Write-Host "Checking $($Grp.DisplayName)"

    # Check group manager
    $ManagedBy = $Grp.ManagedBy
    if ([string]::IsNullOrWhiteSpace($ManagedBy) -and [string]::IsNullOrEmpty($ManagedBy))
    {
        Write-Host $Grp.DisplayName "  No group owners found" -ForegroundColor $CommandError
    }

    # Check last conversation
    Write-Host "  Checking Exchange"
    $ExchangeData = (Get-ExoMailboxFolderStatistics -Identity $Grp.ExternalDirectoryObjectId -IncludeOldestAndNewestItems -FolderScope Inbox)
    if ([string]::IsNullOrEmpty($ExchangeData.NewestItemReceivedDate))
    {
        Write-Host "    No conversation found" -ForegroundColor $CommandWarning
        $Obsolete = $true
    }
    else
    {
        if ($ExchangeData.NewestItemReceivedDate -le $WarningDate)
        {
            Write-Host "    Last conversation: $($ExchangeData.NewestItemReceivedDate) -> Obsolete:Yes"
            $Obsolete = $true
        }
    }

    # Check audit records for activity in the group's SharePoint document library
    if ($Obsolete)
    {
        Write-Host "  Checking SharePoint"
        if ($Grp.SharePointSiteURL -ne $null)
        {
            $AuditCheck = $Grp.SharePointSiteURL + "/*"
            $AuditRecs = Search-UnifiedAuditLog -StartDate $WarningDate -EndDate $Today -ObjectId $AuditCheck | Where-Object { $_.UserIds -ne "app@sharepoint" -and $_.UserIds -ne "SHAREPOINT\system" } | Sort-Object -Property CreationDate -Descending | Select-Object -First 1
            if ($AuditRecs -ne $null)
            {
                if ($AuditRecs[0].CreationDate -gt $WarningDate)
                {
                    Write-Host "    Last SharePoint activity: $($AuditRecs[0].CreationDate) -> Obsolete:No"
                    $Obsolete = $false
                }
            }          
        }
    }

    # Check Teams conversation compliance record
    if ($Obsolete)
    {
        if ($TeamsList.ContainsKey($Grp.ExternalDirectoryObjectId))
        {
            Write-Host "  Checking Teams"
            $TeamsData = (Get-ExoMailboxFolderStatistics -Identity $Grp.ExternalDirectoryObjectId -IncludeOldestAndNewestItems -FolderScope NonIPMRoot | ? {$_.FolderType -eq "TeamsMessagesData" })
            if ($TeamsData.NewestItemReceivedDate -gt $WarningDate)
            {
                Write-Host "    Last Teams chat: $($TeamsData.NewestItemReceivedDate) -> Obsolete:No"
                $Obsolete = $false
            }
        }
    }

    # Check last planner modifications
    if ($Obsolete)
    {
        Write-Host "  Checking Planner"
        $token = Get-AdalAccessToken
        $uri = "https://graph.microsoft.com/Beta/groups/$($Grp.ExternalDirectoryObjectId)/planner/plans"
        $apps = $null
        try
        {
            $plns = (Get-MsGraphObject -AccessToken $token -Uri $uri -DontThrowIfStatusEquals 403).value
        } catch {}
        $lastActivity = $null
        foreach($pln in $plns)
        {
            if ($lastActivity -eq $null)
            {
                #$pln = $plns[0]
                $uri = "https://graph.microsoft.com/Beta/planner/plans/$($pln.id)/tasks"
                $tasks = (Get-MsGraphObject -AccessToken $token -Uri $uri).value
                foreach($task in $tasks)
                {
                    #$task = $tasks[0]
                    if ($task.startDateTime -gt $WarningDate)
                    {
                        $lastActivity = $task.startDateTime
                        break
                    }
                    else
                    {
                        if ($task.dueDateTime -gt $WarningDate)
                        {
                            $lastActivity = $task.dueDateTime
                            break
                        }
                        else
                        {
                            if ($task.createdDateTime -gt $WarningDate)
                            {
                                $lastActivity = $task.createdDateTime
                                break
                            }
                        }
                    }
                }
            }
        }
        if ($lastActivity -ne $null)
        {
            Write-Host "    Last Planner activity: $($lastActivity) -> Obsolete:No"
            $Obsolete = $false
        }
    }

    # Decision
    if ($Obsolete)
    {
        Write-Host "  !!OBSOLETE!!" -ForegroundColor $CommandWarning
    }

}

DisconnectFrom-EXOandIPPS

#Stopping Transscript
Stop-Transcript
