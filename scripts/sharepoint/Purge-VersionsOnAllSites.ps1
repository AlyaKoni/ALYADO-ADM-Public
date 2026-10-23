#Requires -Version 7.0

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    06.02.2026 Konrad Brunner       Added powershell documentation
    19.10.2026 Konrad Brunner       Platform-dependent Close-ExcelPackage (-Show on Windows only)

#>

<#
.SYNOPSIS
Purges old SharePoint document versions across all site collections based on configured retention parameters.

.DESCRIPTION
Purge-VersionsOnAllSites.ps1 connects to a SharePoint tenant and iterates through all site collections to enforce version retention policies for document libraries. It supports two primary modes: maintaining a set number of major/minor versions or purging based on a backup retention policy using day, week, month, and year thresholds. The script optionally performs a dry run, outputs logs, and generates an Excel report summarizing purged versions, warnings, and errors.

.PARAMETER maxMajorVersionLimit
Specifies the maximum allowed number of major versions for a document library. Default is 500.

.PARAMETER maxMinorVersionLimit
Specifies the maximum allowed number of minor versions for a document library. Default is 500.

.PARAMETER keepMajorVersions
Specifies how many major versions of each file to keep when using the KeepNumberOfVersions parameter set. Default is 50.

.PARAMETER keepMinorVersions
Specifies how many minor versions of each file to keep when using the KeepNumberOfVersions parameter set. Default is 5.

.PARAMETER keepDays
Defines how many days of versions to retain when purging by backup policy. Default is 14.

.PARAMETER keepWeeks
Defines how many weeks of versions to retain when purging by backup policy. Default is 9.

.PARAMETER keepMonths
Defines how many months of versions to retain when purging by backup policy. Default is 13.

.PARAMETER keepYears
Defines how many years of versions to retain when purging by backup policy. Default is 10.

.PARAMETER dryRun
If set to true, the script simulates the purge without deleting any versions. Default is true.

.PARAMETER ClientId
Specifies the client ID for certificate-based authentication to SharePoint Online.

.PARAMETER Thumbprint
Specifies the certificate thumbprint for authentication to SharePoint Online.

.PARAMETER CertFile
Path to the client certificate file for authentication.

.PARAMETER CertPassword
Password for the client certificate if applicable.

.INPUTS
None. The script does not accept pipeline input.

.OUTPUTS
Generates an Excel report with details about purged versions, warnings, and errors. Logs the execution to a transcript file and the console.

.EXAMPLE
PS> .\Purge-VersionsOnAllSites.ps1 -ParameterSetName "ByBackupPolicy" -dryRun $false -ClientId "xxxx-xxxx" -Thumbprint "ABC123456789DEF" -keepDays 14 -keepWeeks 9 -keepMonths 13 -keepYears 10

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
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
    [int]$maxMinorVersionLimit = 500,

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
    [string]$CertPassword = $null
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Purge-VersionsOnAllSites-$($AlyaTimeString).log" | Out-Null

# Configurations
[System.Net.ServicePointManager]::MaxServicePointIdleTime = 600000
[Net.ServicePointManager]::SecurityProtocol = @([Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13)
$proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

# Members
$alreadyDone = @()
$startDate = Get-Date
$AlyaPnpEnvironment = "Production"

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

if (-Not $ClientId)
{
    # Getting actual users mail
    $rootCon = LoginTo-PnP -Url $AlyaSharePointUrl -ClientId $ClientId -Thumbprint $Thumbprint -CertFile $CertFile -CertPassword $CertPassword
    $rweb = Get-PnPWeb -Connection $rootCon
    $rweb.Context.Load($rweb.CurrentUser)
    Invoke-PnPQuery -Connection $rootCon
    $owners = @($rweb.CurrentUser.Email)

    # Setting site admins
    Write-Host "Setting site admins" -ForegroundColor $CommandInfo
    $ctx = Get-PnPContext -Connection $adminCon
    $ctx.Load($ctx.Web.CurrentUser)
    Invoke-PnPQuery -Connection $adminCon
    foreach ($site in $sitesToProcess)
    {
        if ($site.Template -like "Redirect*") { continue }
        if (-Not $site.Url.Contains("/sites/") -or $site.Url.TrimEnd("/") -eq $AlyaSharePointUrl.TrimEnd("/")) { continue }

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
        if (-Not $site.Url.Contains("/sites/") -or $site.Url.TrimEnd("/") -eq $AlyaSharePointUrl.TrimEnd("/")) { continue }
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
                    -and -not $_.RootFolder.ServerRelativeUrl.Contains("/AppCatalog") `
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
                    $items = [System.Collections.ArrayList]@()
                    $pages = 0
                    $null = Get-PnPListItem -Connection $siteCon -List $docLib -PageSize 500 -ScriptBlock {
                        Param($objs)
                        $retries = 10
                        do {
                            try {
                                $pages++
                                $objs.Context.ExecuteQuery()
                                foreach($obj in $objs)
                                {
                                    $null = $items.Add($obj)
                                }
                                break
                            }
                            catch {
                                Write-Host "Page $pages retry $($retries): $($_.Exception.Message)"
                                Start-Sleep -Seconds 5
                                $retries--
                                if ($retries -lt 0)
                                {
                                    throw
                                }
                            }
                        } while ($true)
                    }
                    Write-Host "        $($items.Count) files"

                    # Processing files
                    Write-Host "      Processing files"
                    foreach ($item in $items)
                    {
                        try
                        {

                            if ($item.FileSystemObjectType -eq "Folder") { continue }
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
        # -Show uses Start-Process on the xlsx file: works on Windows only,
        # on Linux/macOS it fails with Permission denied (file is already saved before)
        if (($PSVersionTable.PSVersion.Major -lt 6) -Or $IsWindows)
        {
            Close-ExcelPackage $excel -Show
        }
        else
        {
            Close-ExcelPackage $excel
        }
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
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA/UprzgwIPCzHh
# uhaN/FsLLAUX6wLcLC/FzZYJYQ32N6CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGju
# xOV7dX3H9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQT
# AxEACqVq4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f
# 46P2IukytvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdY
# TA3E3kMHBiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhD
# o6nZ2Iwj1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL
# 1yf/30OVyct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AH
# hviDcudo30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfd
# sbCXAJvYNCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx
# /j+7m9WSaK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cid
# mgdUVveoBPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgf
# tnoAWlVn8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vC
# oTANBgkqhkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQ
# ZpE364hOTSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTso
# VYpQr3IozYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yo
# DsPU9IHP/w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQ
# X6ibUXqjXk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNp
# HbGY6Eg0RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirM
# Jk0b9UF2hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnA
# mrVkGZj2a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj
# 3+nmvWbZfNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL
# /yMvbDOHhREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtH
# dwO39ACaudnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4Qh
# trofETAxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILhF99il
# +6epzos0s80NZ+qfqL8aKWJUYJ7A0A+gpQtzMA0GCSqGSIb3DQEBAQUABIICAHhf
# WeD2Bo4GbYGLLA5/3FDBd50HeeSKqPtdE5PdIg+2/3KizXmlo7lYa2f7BwOSHR2T
# 68nq93q2MBh/A7p2Z2VHwQOzfnNzj4SFacHNHJcH7Ig/y/Tq9AR5wfCyyf4lLVAf
# dtn90feVhdiCDvUAYAn4VyQsuDn3qDmXch3gHL8L4BKZjF/8JRfD/pxN0jt4mot4
# uEKuLtDAh1j3OJ73iy9gaps1u9IV8xoHHCt6y44wxDr7/ky6u8DHczrkaS+lHCkJ
# Ov+YyUhfmvWgr3ZrfpsGWyqLY+QStD/sUZhiiLs/SYm3kpfyaioRlMjM8GWdDweb
# AO9MQO2iY5aYVWsKJkxiLFe+vdOTWqiZpaspVhPKHnEbOzuM2eJ8uYCXnlb02LjB
# usGubutKt1GAQpVS/zNYZyv6moBDPAT1Kr2vaSO+toM7AVoysiQUDZ4X13DxykxB
# XAl4jTg0IgxPcoMEaCXaw+hS+94b/oZTX6dE66lQT8jQAF6Z3WhaKyqcGtjKPB2f
# DWqykrfU6yooYtnICWa+7BQ3cTEHqtSGYtT9Yr68q0bfuD6yyE46RmUZzcb0KVtD
# eP+Rw/CHu8WWKLe4jkM4ulHBXl9YmJD2JmuhwU3SJinb6Ox7dH/FkdrsZsZGwHHu
# dsTcatou3Iim+7hReCGVvMghzeHdzaLwiFdVMoa0oYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCCWxLiuC9ZXPyTD0jGHEKpG6I9jE9xoj9FVdI5YcO1cRgIUAkIm
# 1cnwCAX3MS8DyVEGFXiPJRUYDzIwMjYxMDIwMTMzODMyWjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
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
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDCyG/FwC8FFk9BR+BBjAwcrWLUJPLCfzoje+7BBrOekorNdFfliuLF9hZSv
# DkczQOYwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAo0vc0PrUu4ROakgwwemnHclNB4+2tiPljwvnfjdqiHIV
# +7T/PDcSCfkEJz1ZdR1yRH9GDMMSJnwiOGKC7InDKPXkzccpK70ZaO95qshcaLk0
# z7IBFl23HDDPZ1PVrz81fDbV+oc4ko+WHjTkaqwYcRzN1Hw5mi5uQcnoXU+RKEKL
# xfycCuYcLLWTK3qzouR5gAFW5Ru0DeCr+u5bnpshAddFcrjkovP/lfHBhf/EFGlA
# GinU7FjICTmP2/d+af7JWKdarKu6A84X8uw5duoNde/y5w1Yxc7+t8CwrM1pBXt6
# HxX0wDFI7hc/UG90OumvxI90Pl/p9kgKsOputsAlexUDntApI7+3u7qWKLMLx1J1
# Q1ziYn4uYHMYSitJQ8AHnSYF4OIYICY4FAO7q1FfYXNinDoItLxaUInRfQ2QCp1r
# 2Dp6L92+ryj9kJpU3Es7JstIJmZuXbrUt6+c5b01ewACYbJGSX2SlXjDlIZFyPGT
# ecA6R6fzNgUKl6nPsAiM
# SIG # End signature block
