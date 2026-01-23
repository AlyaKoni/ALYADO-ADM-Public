#Requires -Version 7.0

<#
    Copyright (c) Alya Consulting, 2019-2026

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
    11.02.2025 Konrad Brunner       Initial Version
    15.10.2025 Konrad Brunner       Added ByBackupPolicy
    21.01.2026 Konrad Brunner       Bug fixes and ExcelExport

#>

[CmdletBinding(DefaultParameterSetName = "ByBackupPolicy")]
Param(
    [Parameter(Mandatory = $false, ParameterSetName = "KeepNumberOfVersions")]
    [Parameter(Mandatory = $false, ParameterSetName = "ByBackupPolicy")]
    [ValidateScript({$_ -is [int] -and $_ -gt 0 -and $_ -lt 50000})]   
    [int]$maxMajorVersionLimit = 500,
    [Parameter(Mandatory = $false, ParameterSetName = "KeepNumberOfVersions")]
    [Parameter(Mandatory = $false, ParameterSetName = "ByBackupPolicy")]
    [ValidateScript({$_ -is [int] -and $_ -gt 0 -and $_ -lt 510})]
    [int]$maxMinorVersionLimit = 50,

    [Parameter(Mandatory = $false, ParameterSetName = "KeepNumberOfVersions")]
    [ValidateScript({$_ -is [int] -and $_ -gt 0})]
    [int]$keepMajorVersions = 50,
    [Parameter(Mandatory = $false, ParameterSetName = "KeepNumberOfVersions")]
    [ValidateScript({$_ -is [int] -and $_ -gt 0})]
    [int]$keepMinorVersions = 5,

    [Parameter(Mandatory = $false, ParameterSetName = "ByBackupPolicy")]
    [int]$keepDays = 14,
    [Parameter(Mandatory = $false, ParameterSetName = "ByBackupPolicy")]
    [int]$keepWeeks = 9,
    [Parameter(Mandatory = $false, ParameterSetName = "ByBackupPolicy")]
    [int]$keepMonths = 13,
    [Parameter(Mandatory = $false, ParameterSetName = "ByBackupPolicy")]
    [int]$keepYears = 10,

    [Parameter(Mandatory = $false, ParameterSetName = "KeepNumberOfVersions")]
    [Parameter(Mandatory = $false, ParameterSetName = "ByBackupPolicy")]
    [bool]$dryRun = $true,

    [Parameter(Mandatory = $false, ParameterSetName = "KeepNumberOfVersions")]
    [Parameter(Mandatory = $false, ParameterSetName = "ByBackupPolicy")]
    [string]$ClientId = $null,

    [Parameter(Mandatory = $false, ParameterSetName = "KeepNumberOfVersions")]
    [Parameter(Mandatory = $false, ParameterSetName = "ByBackupPolicy")]
    [string]$Thumbprint = $null,

    [Parameter(Mandatory = $false, ParameterSetName = "KeepNumberOfVersions")]
    [Parameter(Mandatory = $false, ParameterSetName = "ByBackupPolicy")]
    [string]$CertFile = $null,

    [Parameter(Mandatory = $false, ParameterSetName = "KeepNumberOfVersions")]
    [Parameter(Mandatory = $false, ParameterSetName = "ByBackupPolicy")]
    [Parameter(Mandatory = $false)]
    [string]$CertPassword = $null
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Purge-VersionsOnAllSites-$($AlyaTimeString).log" | Out-Null

# Members
$alreadyDone = @()
$startDate = Get-Date

# Checking modules
Install-ModuleIfNotInstalled "PnP.PowerShell"
Install-ModuleIfNotInstalled "ImportExcel"

# Login
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl -ClientId $ClientId -Thumbprint $Thumbprint -CertFile $CertFile -CertPassword $CertPassword

# Getting site collections
Write-Host "Getting site collections" -ForegroundColor $CommandInfo
$retries = 10
do
{
    try
    {
        $sitesToProcess = Get-PnPTenantSite -Connection $adminCon -Detailed
        break
    }
    catch
    {
        Write-Error $_.Exception -ErrorAction Continue
        Write-Warning "Retrying $retries times"
        Start-Sleep -Seconds 15
        $retries--
        if ($retries -lt 0) { throw }
    }
} while ($true)

# Getting actual users mail
$rootCon = LoginTo-PnP -Url $AlyaSharePointUrl -ClientId $ClientId -Thumbprint $Thumbprint -CertFile $CertFile -CertPassword $CertPassword
$rweb = Get-PnPWeb -Connection $rootCon
$rweb.Context.Load($rweb.CurrentUser)
Invoke-PnPQuery -Connection $rootCon
$owners = @($rweb.CurrentUser.Email)

if (-Not $ClientId)
{
    # Setting site admins
    Write-Host "Setting site admins" -ForegroundColor $CommandInfo
    $ctx = Get-PnPContext -Connection $adminCon
    $ctx.Load($ctx.Web.CurrentUser)
    Invoke-PnPQuery -Connection $adminCon
    foreach ($site in $sitesToProcess)
    {
        if ($site.Template -like "Redirect*") { continue }
        if (-Not $site.Url.Contains("/sites/") -And $site.Url.TrimEnd("/") -ne $AlyaSharePointUrl.TrimEnd("/")) { continue }

        # Setting site owner
        Write-Host "  Site: $($site.Url)"
        if (-Not $dryRun) { $null = Set-PnPTenantSite -Connection $adminCon -Identity $site.Url -Owners $owners }
    }
}

$Cult = Get-Culture
$WeekRule = $Cult.DateTimeFormat.CalendarWeekRule.value__
$FirstDayOfWeek = $Cult.DateTimeFormat.FirstDayOfWeek.value__

# Purging versions
Write-Host "Purging versions" -ForegroundColor $CommandInfo
$purgedVersions = [System.Collections.ArrayList]@()
$purgeErrors = [System.Collections.ArrayList]@()
$purgeWarnings = [System.Collections.ArrayList]@()
foreach ($site in $sitesToProcess)
{
    try
    {

        if ($site.Template -like "Redirect*") { continue }
        if (-Not $site.Url.Contains("/sites/") -And $site.Url.TrimEnd("/") -ne $AlyaSharePointUrl.TrimEnd("/")) { continue }
        if ($site.Url -in $alreadyDone) { continue }
        $alreadyDone += $site.Url

        # Login to site
        Write-Host ""
        Write-Host "  Site: $($site.Url)"
        $siteCon = LoginTo-PnP -Url $site.Url -ClientId $ClientId -Thumbprint $Thumbprint -CertFile $CertFile -CertPassword $CertPassword

        # Getting all doc libs
        $retries = 10
        do
        {
            try
            {
                $lists = Get-PnPList -Connection $siteCon -Includes @("ID", "Title", "Fields", "RootFolder", "EnableVersioning", "EnableMinorVersions", "MajorVersionLimit", "MajorWithMinorVersionsLimit") -ErrorAction SilentlyContinue
                $docLibs = $lists | Where-Object { $_.BaseType -eq "DocumentLibrary" `
                    -and -not $_.RootFolder.ServerRelativeUrl.Contains("/_catalogs") `
                    -and -not $_.RootFolder.ServerRelativeUrl.Contains("/Style Library") `
                    -and -not $_.RootFolder.ServerRelativeUrl.Contains("/FormServerTemplates") `
                    -and -not $_.RootFolder.ServerRelativeUrl.Contains("/IWConvertedForms") `
                    -and -not $_.RootFolder.ServerRelativeUrl.Contains("/SiteAssets") `
                    -and -not $_.RootFolder.ServerRelativeUrl.Contains("/SitePages") }
                break
            }
            catch
            {
                Write-Error $_.Exception -ErrorAction Continue
                Write-Warning "Retrying $retries times"
                Start-Sleep -Seconds 15
                $retries--
                if ($retries -lt 0) { throw }
            }
        } while ($true)

        foreach ($docLib in $docLibs)
        {
            try
            {

                Write-Host "    DocLib: $($docLib.RootFolder.ServerRelativeUrl)"
                if ($docLib.EnableVersioning)
                {
                    $minorVersionsEnabled = $docLib.EnableMinorVersions

                    # Checking version history limits
                    Write-Host "      Checking version history limits"
                    $limit = $docLib.MajorVersionLimit
                    if ($limit -gt $maxMajorVersionLimit)
                    {
                        Write-Host "        Setting MajorVersions from $limit to $maxMajorVersionLimit"
                        if (-Not $dryRun) { $null = Set-PnPList -Connection $siteCon -Identity $docLib -MajorVersions $maxMajorVersionLimit }
                        $null = $purgeWarnings.Add([PSCustomObject]@{
                            SiteUrl = $site.Url
                            DocLib  = $docLib.RootFolder.ServerRelativeUrl
                            ItemId  = $null
                            Warning = "MajorVersions changed from $limit to $maxMajorVersionLimit"
                        })
                    }
                    $limit = $docLib.MajorWithMinorVersionsLimit
                    if ($minorVersionsEnabled -and $limit -gt $maxMinorVersionLimit)
                    {
                        Write-Host "        Setting MinorVersions from $limit to $maxMinorVersionLimit"
                        if (-Not $dryRun) { $null = Set-PnPList -Connection $siteCon -Identity $docLib -MinorVersions $maxMinorVersionLimit }
                        $null = $purgeWarnings.Add([PSCustomObject]@{
                            SiteUrl = $site.Url
                            DocLib  = $docLib.RootFolder.ServerRelativeUrl
                            ItemId  = $null
                            Warning = "MinorVersions changed from $limit to $maxMinorVersionLimit"
                        })
                    }

                    # Getting files
                    Write-Host "      Getting files"
                    $items = Get-PnPListItem -Connection $siteCon -List $docLib -PageSize 5000
                    Write-Host "        $($items.Count) files"

                    foreach ($item in $items)
                    {
                        try
                        {

                            if ($item.FileSystemObjectType -eq "Folder") { continue }
                            #$file = $item.File
                            Write-Host "        $($item.FieldValues.FileRef)"
                            if (-Not $minorVersionsEnabled)
                            {
                                if ($item.FieldValues["_UIVersionString"] -eq "1.0") { continue }
                                switch ($PSCmdlet.ParameterSetName)
                                {
                                    "KeepNumberOfVersions"
                                    {
                                        $versions = Get-PnPFileVersion -Connection $siteCon -Url $item.FieldValues.FileRef | Sort-Object -Property "Created" -Descending
                                        Write-Host "          $($versions.Count) major versions"
                                        if ($versions.Count -gt $keepMajorVersions)
                                        {
                                            $cnt = $versions.Count - $keepMajorVersions
                                            Write-Host "          purging $($cnt) versions"
                                            for ($i = $keepMajorVersions; $i -lt $versions.Count; $i++)
                                            {
                                                Write-Host "          deleting version $($versions[$i].VersionLabel) from $($versions[$i].Created)"
                                                $null = $purgedVersions.Add([PSCustomObject]@{
                                                    VersionLabel = $versions[$i].VersionLabel
                                                    Created      = $versions[$i].Created
                                                    ContentType  = $item.FieldValues.ContentTypeId
                                                    ServerRelativeUrl = $item.FieldValues.FileRef
                                                    FileSize = [math]::Round(($versions[$i].Length / 1MB), 2)
                                                })
                                                if (-Not $dryRun)
                                                {
                                                    $retries = 5
                                                    do
                                                    {
                                                        try
                                                        {
                                                            Remove-PnPFileVersion -Connection $siteCon -Url $item.FieldValues.FileRef -Identity $versions[$i].ID -Force
                                                            break
                                                        }
                                                        catch
                                                        {
                                                            Write-Error $_.Exception -ErrorAction Continue
                                                            Write-Warning "Retrying $retries times"
                                                            Start-Sleep -Seconds 10
                                                            $retries--
                                                            if ($retries -lt 0) { throw }
                                                        }
                                                    } while ($true)
                                                }
                                            }
                                        }
                                        else
                                        {
                                            Write-Host "          nothing to purge"
                                        }
                                        break
                                    }
                                    "ByBackupPolicy"
                                    {
                                        $versions = Get-PnPFileVersion -Connection $siteCon -Url $item.FieldValues.FileRef | Sort-Object -Property "Created"
                                        Write-Host "          $($versions.Count) major versions"
                                        for ($i = 0; $i -lt $versions.Count; $i++)
                                        {
                                            Write-Host "          Version $($versions[$i].VersionLabel) from $($versions[$i].Created)"
                                            $keepThisVersion = $true
                                            if ($versions[$i].Created.ToLocalTime().AddDays($keepDays) -lt (Get-Date))
                                            {
                                                $DT = $versions[$i].Created.ToLocalTime()
                                                $WeekRuleDay = [int]($DT.DayOfWeek.Value__ -ge $FirstDayOfWeek ) * ( (6 - $WeekRule) - $DT.DayOfWeek.Value__ )
                                                $weekNumber = $Cult.Calendar.GetWeekOfYear(($DT).AddDays($WeekRuleDay), $WeekRule, $FirstDayOfWeek)
                                                if (($i+1) -lt $versions.Count)
                                                {
                                                    $DT = $versions[$i+1].Created.ToLocalTime()
                                                    $WeekRuleDay = [int]($DT.DayOfWeek.Value__ -ge $FirstDayOfWeek ) * ( (6 - $WeekRule) - $DT.DayOfWeek.Value__ )
                                                    $nextWeekNumber = $Cult.Calendar.GetWeekOfYear(($versions[$i+1].Created.ToLocalTime()).AddDays($WeekRuleDay), $WeekRule, $FirstDayOfWeek)
                                                    if ($weekNumber -eq $nextWeekNumber)
                                                    {
                                                        Write-Debug "            same week number as next version, not keeping this version"
                                                        $keepThisVersion = $false
                                                    }
                                                }
                                                if ($keepThisVersion)
                                                {
                                                    if ($versions[$i].Created.ToLocalTime().AddDays($keepWeeks*7) -lt (Get-Date))
                                                    {
                                                        if (($i+1) -lt $versions.Count)
                                                        {
                                                            $DT = $versions[$i+1].Created.ToLocalTime()
                                                            if ($DT.Month -eq $versions[$i].Created.ToLocalTime().Month -and $DT.Year -eq $versions[$i].Created.ToLocalTime().Year)
                                                            {
                                                                Write-Debug "            same month and year as next version, not keeping this version"
                                                                $keepThisVersion = $false
                                                            }
                                                        }
                                                        if ($keepThisVersion)
                                                        {
                                                            if ($versions[$i].Created.ToLocalTime().AddMonths($keepMonths) -lt (Get-Date))
                                                            {
                                                                if (($i+1) -lt $versions.Count)
                                                                {
                                                                    $DT = $versions[$i+1].Created.ToLocalTime()
                                                                    if ($DT.Year -eq $versions[$i].Created.ToLocalTime().Year)
                                                                    {
                                                                        Write-Debug "            same year as next version, not keeping this version"
                                                                        $keepThisVersion = $false
                                                                    }
                                                                }
                                                                if ($keepThisVersion)
                                                                {
                                                                    if ($versions[$i].Created.ToLocalTime().AddYears($keepYears) -lt (Get-Date))
                                                                    {
                                                                        Write-Debug "            older than year range, not keeping this version"
                                                                        $keepThisVersion = $false
                                                                    }
                                                                    else
                                                                    {
                                                                        Write-Debug "            keeping yearly version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within year range)"
                                                                    }
                                                                }
                                                            }
                                                            else
                                                            {
                                                                Write-Debug "            keeping monthly version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within month range)"
                                                            }
                                                        }
                                                    }
                                                    else
                                                    {
                                                        Write-Debug "            keeping weekly version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within week range)"
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                Write-Debug "            keeping daily version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within day range)"
                                            }
                                            if (-Not $keepThisVersion)
                                            {
                                                Write-Host "            deleting version $($versions[$i].VersionLabel) from $($versions[$i].Created)"
                                                $null = $purgedVersions.Add([PSCustomObject]@{
                                                    VersionLabel = $versions[$i].VersionLabel
                                                    Created      = $versions[$i].Created
                                                    ContentType  = $item.FieldValues.ContentTypeId
                                                    ServerRelativeUrl = $item.FieldValues.FileRef
                                                    FileSize = [math]::Round(($versions[$i].Length / 1MB), 2)
                                                })
                                                if (-Not $dryRun)
                                                {
                                                    $retries = 5
                                                    do
                                                    {
                                                        try
                                                        {
                                                            Remove-PnPFileVersion -Connection $siteCon -Url $item.FieldValues.FileRef -Identity $versions[$i].ID -Force
                                                            break
                                                        }
                                                        catch
                                                        {
                                                            Write-Error $_.Exception -ErrorAction Continue
                                                            Write-Warning "Retrying $retries times"
                                                            Start-Sleep -Seconds 10
                                                            $retries--
                                                            if ($retries -lt 0) { throw }
                                                        }
                                                    } while ($true)
                                                }
                                            }
                                        }
                                        break
                                    }
                                }
                            }
                            else
                            {
                                if ($item.FieldValues["_UIVersionString"] -eq "0.1") { continue }
                                switch ($PSCmdlet.ParameterSetName)
                                {
                                    "KeepNumberOfVersions"
                                    {
                                        $versions = Get-PnPFileVersion -Connection $siteCon -Url $item.FieldValues.FileRef | Sort-Object -Property "Created" -Descending
                                        Write-Host "          $($versions.Count) major/minor versions"
                                        $revs = $versions.VersionLabel | Where-Object { $_ -like "*.0" }
                                        Write-Host "          $($revs.Count) revisions"
                                        $revCnt = 0
                                        foreach ($rev in $revs)
                                        {
                                            Write-Host "            revision $($rev.VersionLabel)"
                                            $revCnt++
                                            if ($revCnt -eq $keepMajorVersions)
                                            {
                                                Write-Host "          keepMajorVersions reaged. Deleting now all minor versions"
                                                $null = $purgeWarnings.Add([PSCustomObject]@{
                                                    SiteUrl = $site.Url
                                                    DocLib  = $docLib.RootFolder.ServerRelativeUrl
                                                    ItemId  = $item.Id
                                                    Warning = "keepMajorVersions reaged. Deleting now all minor versions"
                                                })
                                            }
                                            $revStr = $rev.VersionLabel.Split(".")[0]+"."
                                            $minors = $versions | Where-Object { $_.VersionLabel -like "$revStr*" } | Sort-Object -Property "Created" -Descending
                                            Write-Host "              $($minors.Count) minor versions"
                                            $check = $keepMinorVersions
                                            if ($revCnt -ge $keepMajorVersions)
                                            {
                                                $check = 1
                                            }
                                            if ($minors.Count -gt $check)
                                            {
                                                $cnt = $minors.Count - $check
                                                Write-Host "              purging $($cnt) minor versions"
                                                for ($i = $check; $i -lt $minors.Count; $i++)
                                                {
                                                    Write-Host "              deleting minor version $($minors[$i].VersionLabel) from $($minors[$i].Created)"
                                                    $null = $purgedVersions.Add([PSCustomObject]@{
                                                        VersionLabel = $versions[$i].VersionLabel
                                                        Created      = $versions[$i].Created
                                                        ContentType  = $item.FieldValues.ContentTypeId
                                                        ServerRelativeUrl = $item.FieldValues.FileRef
                                                        FileSize = [math]::Round(($versions[$i].Length / 1MB), 2)
                                                    })
                                                    if (-Not $dryRun)
                                                    {
                                                        $retries = 5
                                                        do
                                                        {
                                                            try
                                                            {
                                                                Remove-PnPFileVersion -Connection $siteCon -Url $item.FieldValues.FileRef -Identity $versions[$i].ID -Force
                                                                break
                                                            }
                                                            catch
                                                            {
                                                                Write-Error $_.Exception -ErrorAction Continue
                                                                Write-Warning "Retrying $retries times"
                                                                Start-Sleep -Seconds 10
                                                                $retries--
                                                                if ($retries -lt 0) { throw }
                                                            }
                                                        } while ($true)
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                Write-Host "              nothing to purge"
                                            }
                                        }
                                        break
                                    }
                                    "ByBackupPolicy"
                                    {
                                        $versions = Get-PnPFileVersion -Connection $siteCon -Url $item.FieldValues.FileRef | Sort-Object -Property "Created"
                                        Write-Host "          $($versions.Count) major/minor versions"
                                        $revs = $versions.VersionLabel | Where-Object { $_ -like "*.0" }
                                        Write-Host "          $($revs.Count) revisions"
                                        for ($i = 0; $i -lt $versions.Count; $i++)
                                        {
                                            Write-Host "          Version $($versions[$i].VersionLabel) from $($versions[$i].Created)"
                                            $keepThisVersion = $true
                                            if ($versions[$i].Created.ToLocalTime().AddDays($keepDays) -lt (Get-Date))
                                            {
                                                $DT = $versions[$i].Created.ToLocalTime()
                                                $WeekRuleDay = [int]($DT.DayOfWeek.Value__ -ge $FirstDayOfWeek ) * ( (6 - $WeekRule) - $DT.DayOfWeek.Value__ )
                                                $weekNumber = $Cult.Calendar.GetWeekOfYear(($DT).AddDays($WeekRuleDay), $WeekRule, $FirstDayOfWeek)
                                                if (($i+1) -lt $versions.Count)
                                                {
                                                    $DT = $versions[$i+1].Created.ToLocalTime()
                                                    $WeekRuleDay = [int]($DT.DayOfWeek.Value__ -ge $FirstDayOfWeek ) * ( (6 - $WeekRule) - $DT.DayOfWeek.Value__ )
                                                    $nextWeekNumber = $Cult.Calendar.GetWeekOfYear(($versions[$i+1].Created.ToLocalTime()).AddDays($WeekRuleDay), $WeekRule, $FirstDayOfWeek)
                                                    if ($weekNumber -eq $nextWeekNumber)
                                                    {
                                                        Write-Debug "            same week number as next version, not keeping this version"
                                                        $keepThisVersion = $false
                                                    }
                                                }
                                                if ($keepThisVersion)
                                                {
                                                    if ($versions[$i].Created.ToLocalTime().AddDays($keepWeeks*7) -lt (Get-Date))
                                                    {
                                                        if (($i+1) -lt $versions.Count)
                                                        {
                                                            $DT = $versions[$i+1].Created.ToLocalTime()
                                                            if ($DT.Month -eq $versions[$i].Created.ToLocalTime().Month -and $DT.Year -eq $versions[$i].Created.ToLocalTime().Year)
                                                            {
                                                                Write-Debug "            same month and year as next version, not keeping this version"
                                                                $keepThisVersion = $false
                                                            }
                                                        }
                                                        if ($keepThisVersion)
                                                        {
                                                            if ($versions[$i].Created.ToLocalTime().AddMonths($keepMonths) -lt (Get-Date))
                                                            {
                                                                if (($i+1) -lt $versions.Count)
                                                                {
                                                                    $DT = $versions[$i+1].Created.ToLocalTime()
                                                                    if ($DT.Year -eq $versions[$i].Created.ToLocalTime().Year)
                                                                    {
                                                                        Write-Debug "            same year as next version, not keeping this version"
                                                                        $keepThisVersion = $false
                                                                    }
                                                                }
                                                                if ($keepThisVersion)
                                                                {
                                                                    if ($versions[$i].Created.ToLocalTime().AddYears($keepYears) -lt (Get-Date))
                                                                    {
                                                                        Write-Debug "            older than year range, not keeping this version"
                                                                        $keepThisVersion = $false
                                                                    }
                                                                    else
                                                                    {
                                                                        Write-Debug "            keeping yearly version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within year range)"
                                                                    }
                                                                }
                                                            }
                                                            else
                                                            {
                                                                Write-Debug "            keeping monthly version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within month range)"
                                                            }
                                                        }
                                                    }
                                                    else
                                                    {
                                                        Write-Debug "            keeping weekly version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within week range)"
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                Write-Debug "            keeping daily version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within day range)"
                                            }
                                            if (-Not $keepThisVersion)
                                            {
                                                if ($versions[$i].VersionLabel -like "*.0" )
                                                {
                                                    Write-Debug "            keeping revision version $($versions[$i].VersionLabel) from $($versions[$i].Created)"
                                                }
                                                else
                                                {
                                                    Write-Host "          deleting version $($versions[$i].VersionLabel) from $($versions[$i].Created)"
                                                    $null = $purgedVersions.Add([PSCustomObject]@{
                                                        VersionLabel = $versions[$i].VersionLabel
                                                        Created      = $versions[$i].Created
                                                        ContentType  = $item.FieldValues.ContentTypeId
                                                        ServerRelativeUrl = $item.FieldValues.FileRef
                                                        FileSize = [math]::Round(($versions[$i].Length / 1MB), 2)
                                                    })
                                                    if (-Not $dryRun)
                                                    {
                                                        $retries = 5
                                                        do
                                                        {
                                                            try
                                                            {
                                                                Remove-PnPFileVersion -Connection $siteCon -Url $item.FieldValues.FileRef -Identity $versions[$i].ID -Force
                                                                break
                                                            }
                                                            catch
                                                            {
                                                                Write-Error $_.Exception -ErrorAction Continue
                                                                Write-Warning "Retrying $retries times"
                                                                Start-Sleep -Seconds 10
                                                                $retries--
                                                                if ($retries -lt 0) { throw }
                                                            }
                                                        } while ($true)
                                                    }
                                                }
                                            }
                                        }
                                        break
                                    }
                                }
                            }

                        }
                        catch
                        {
                            Write-Error $_.Exception -ErrorAction Continue
                            Write-Warning "*** Error on file with item ID $($item.Id)"
                            $null = $purgeErrors.Add([PSCustomObject]@{
                                SiteUrl = $site.Url
                                DocLib  = $docLib.RootFolder.ServerRelativeUrl
                                ItemId  = $item.Id
                                Error   = $_.Exception.Message
                            })
                        }

                    }
                }
                else
                {
                    Write-Host "      Versioning not enabled"
                    $null = $purgeWarnings.Add([PSCustomObject]@{
                        SiteUrl = $site.Url
                        DocLib  = $docLib.RootFolder.ServerRelativeUrl
                        ItemId  = $null
                        Warning = "Versioning not enabled"
                    })
                }

            }
            catch
            {
                Write-Error $_.Exception -ErrorAction Continue
                Write-Warning "*** Error in document library $($docLib.Title)"
                $null = $purgeErrors.Add([PSCustomObject]@{
                    SiteUrl = $site.Url
                    DocLib  = $docLib.RootFolder.ServerRelativeUrl
                    ItemId  = $null
                    Error   = $_.Exception.Message
                })
            }

        }

    }
    catch
    {
        Write-Error $_.Exception -ErrorAction Continue
        Write-Warning "*** Error on site $($site.Url)"
        $null = $purgeErrors.Add([PSCustomObject]@{
            SiteUrl = $site.Url
            DocLib  = $null
            ItemId  = $null
            Error   = $_.Exception.Message
        })
    }

}

$purgedVersionCount = $purgedVersions.Count
$TotalFileSize = 0
foreach ($pv in $purgedVersions)
{
    $TotalFileSize += $pv.FileSize
}
$endDate = Get-Date

$totMin = [math]::Round(($endDate - $startDate).TotalMinutes, 2)
$totSiz = [math]::Round($TotalFileSize, 2)
Write-Host ""
Write-Host "Purged versions summary:" -ForegroundColor $CommandInfo
Write-Host ""
Write-Host "  Purge started at: $startDate"
Write-Host "  Purge ended at: $endDate"
Write-Host "  Elapsed time: $totMin minutes"
Write-Host ""
Write-Host "  Total purged versions: $purgedVersionCount"
Write-Host "  Total purged file size (MB): $totSiz"
Write-Host ""
Write-Host ""

if ($purgeWarnings.Count -gt 0)
{
    Write-Host "Purge warnings:" -ForegroundColor $CommandInfo
    Write-Host ""
    foreach ($warn in $purgeWarnings)
    {
        Write-Host "  Site: $($warn.SiteUrl) DocLib: $($warn.DocLib) ItemId: $($warn.ItemId) Warning: $($warn.Warning)" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host ""
}
if ($purgeErrors.Count -gt 0)
{
    Write-Host "Purge errors:" -ForegroundColor $CommandInfo
    Write-Host ""
    foreach ($err in $purgeErrors)
    {
        Write-Host "  Site: $($err.SiteUrl) DocLib: $($err.DocLib) ItemId: $($err.ItemId) Error: $($err.Error)" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host ""
}

if (-Not (Test-Path "$AlyaData\sharepoint\purgeReports"))
{
    New-Item -Path "$AlyaData\sharepoint\purgeReports" -ItemType Directory -Force | Out-Null
}
$outputFile = "$AlyaData\sharepoint\purgeReports\Purge-VersionsOnAllSites-$($AlyaTimeString).xlsx"
do
{
    try
    {
        $excel = $purgedVersions | Export-Excel -Path $outputFile -WorksheetName "purgedVersions" -TableName "purgedVersions" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru -NoNumberConversion *
        Close-ExcelPackage $excel
        $excel = $purgeErrors | Export-Excel -Path $outputFile -WorksheetName "purgeErrors" -TableName "purgeErrors" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru -NoNumberConversion *
        Close-ExcelPackage $excel
        $excel = $purgeWarnings | Export-Excel -Path $outputFile -WorksheetName "purgeWarnings" -TableName "purgeWarnings" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru -NoNumberConversion *
        Close-ExcelPackage $excel -Show
        break
    }
    catch
    {
        if ($_.Exception.Message.Contains("Could not open Excel Package"))
        {
            Write-Host "Please close excel sheet $outputFile"
            pause
        }
        else
        {
            throw
        }
    }
} while ($true)

# Stopping Transcript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAe6ILccDSxPALY
# XLKmByXXzPqlT2KM5LieKQHvGimFLaCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g604YfM/tV
# 5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD4ED6gVYD
# U/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S/gJXhZrh
# 0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp8nKmrVa4
# 6Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqtf2phU7+y
# R2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJQWTEE/bP
# 0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKXvYkPbEdx
# +QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4yMYgcMKb
# 9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmYF8T4xO2k
# 6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2mMIVpqWC
# Z1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7spNY6rQb
# 3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd2jANBgkq
# hkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy/fAHsVv1
# RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW2H3Bh6zN
# XULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0MP6pBPKO
# L6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/pFL9zlcc
# tWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcexU0bcV0hL
# Q4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf6AMOGaM5
# 6A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzECp9LnR+34
# c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9mUF5qE6Yw
# QqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+KuaJRsz+cn
# ZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/JlN6m6GM1j
# EhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutofdgNBzMUx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEbW7VR7GGjhvOOd
# WOD/rY1zbohqYn5XeXqEu9wrm4lwMA0GCSqGSIb3DQEBAQUABIICADNi+NHihEqc
# Iartu4NUgZRal1cTGwzzSarwuHjRctaZq9tL5DwSfvUMknP08N73htH3+IRtQPrH
# fMCA8F7A4VSNgPhkctY8lj0bbqONSAdIppEzhn/j80py6TAMCZ9JdE9CicFWo44n
# eqU6uakKaSC+Ac3xNB2Dem60Vwrub8EcnOv5YfQI6SgBkkTltrg7Cb6fMCcEI4oN
# A5NbKofWABU/j0Vv+DLETdEM7uXuHbUX0hh2lU//zN6i/XUKvNo5yAuD7DYcf1PQ
# pkaui4U7+ZxgRR9KtHBD2/FrCWEDhroczKUNhzrT0PtML8SZibPS21qZRN8WWTLg
# wy9Xed/G2uT0oXmCTRqBYEmgUujpSithJOyRJ8f16zDo4VUtOr3vHMuwmJki8OPb
# vTHNGi2N/OoGfAeAQVSW2QNVwrZ8W58azfuVaarGnLPvqSxQfSnh300sb/XdzufD
# y/bM6/B02Nm6HsftmGHvyPL5Cw5QPP3gT/ixBe++Bpc2RkH4JrPoF2FlF7gD1iXi
# Uedgyh+umxVCA3rcp4KXOKc0qVEHabZ9JHz7MLDj7nkamOBXoam9PG4cECd0WMeI
# P1TTYPVS8tE+3EDR1uNTqRf2Husk9tYNl3/8yhDqSbnxU0fpib3mw31G3Bek8IKK
# EAxjqiLWHWZxUc1ipiMNkykjcz8gHqNsoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCAlGa0yqgrGUQx5ujowK6CXsPznBZsQm4987TR6SmLi0AIUG+Bvo8FIEwJT
# BMUrRHu49p/2HSoYDzIwMjYwMTIzMDc1NDQxWjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# IHVj+kdQ/WPBD0MIXUCPvTBiojvXPbApjTMBz16zyQVYMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAAyCAEhQMv19z
# E6x1t24eRCZhmSzaWzZ/vsMVq/8P23XhNNESUkNC5WMBB377alRis47lAAqkVP75
# p9TYxHyiG0fp1iZ7SDQQDw6vhWEB+3bArcm1XiUnBP5VjesljVxmhUA4pXq7P3TM
# 6laczrBC8GjMgYveRGd3TLaRa9AKi9JEFrpDxo/Yhy+sRubvMPJdD8g3n5UBfew9
# 1ozGDslFPNOmKQXpEsikGc6IBKvByFB1czsHDZtu7mNLmz+akjCDa/ybAWClcMpJ
# uZMuPrVLTp8JaGsqld+b6S9zFixNjoEL/7/j82Xvh1bmCNFcpIfM6Si6kLT4kh0I
# 46MfFHJQVKaENsQy4x8dLmb7e1eRJDYutTaTXKs4TjAKKVaIHQvEHvZqPsW9WvLu
# V6TqHvNe/x4MUGOkqBtqtBCgTwKpHl5sXOolNAIHGDVuIftxEss3HjKYxY3ZY4/b
# xykOZmAGWrUwuUBAHOsRQunpLqzRqKZkfJHm2uVfrmmxsH5AGIVv
# SIG # End signature block
