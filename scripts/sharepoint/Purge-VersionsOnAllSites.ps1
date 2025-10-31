#Requires -Version 7.0

<#
    Copyright (c) Alya Consulting, 2019-2025

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

#>

[CmdletBinding(DefaultParameterSetName = "KeepNumberOfVersions")]
Param(
    [Parameter(Mandatory = $false, ParameterSetName = "KeepNumberOfVersions")]
    [Parameter(Mandatory = $false, ParameterSetName = "ByBackupPolicy")]
    [ValidateScript({$_ -is [int] -and $_ -gt 0 -and $_ -lt 50000})]   
    [int]$maxMajorVersionLimit = 250,
    [Parameter(Mandatory = $false, ParameterSetName = "KeepNumberOfVersions")]
    [Parameter(Mandatory = $false, ParameterSetName = "ByBackupPolicy")]
    [Parameter(Mandatory = $false)]
    [ValidateScript({$_ -is [int] -and $_ -gt 0 -and $_ -lt 510})]
    [int]$maxMinorVersionLimit = 50,

    [Parameter(Mandatory = $false, ParameterSetName = "KeepNumberOfVersions")]
    [int]$keepMajorVersions = 50,
    [Parameter(Mandatory = $false, ParameterSetName = "KeepNumberOfVersions")]
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
    [Parameter(Mandatory = $false)]
    [bool]$dryRun = $true
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Purge-VersionsOnAllSites-$($AlyaTimeString).log" | Out-Null

# Members
$alreadyDone = @(
)

# Checking modules
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Login
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

# Checking input
if ($maxMajorVersionLimit -lt 1)
{
    Write-Error "maxMajorVersionLimit needs to be at least 1" -ErrorAction Continue
    Exit
}
if ($maxMinorVersionLimit -lt 1)
{
    Write-Error "maxMinorVersionLimit needs to be at least 1" -ErrorAction Continue
    Exit
}
if ($keepMajorVersions -lt 1)
{
    Write-Error "keepMajorVersions needs to be at least 1" -ErrorAction Continue
    Exit
}
if ($keepMinorVersions -lt 1)
{
    Write-Error "keepMinorVersions needs to be at least 1" -ErrorAction Continue
    Exit
}

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
$rootCon = LoginTo-PnP -Url $AlyaSharePointUrl
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
    if (-Not $site.Url.Contains("/sites/") -And $site.Url.TrimEnd("/") -ne $AlyaSharePointUrl.TrimEnd("/")) { continue }

    # Setting site owner
    Write-Host "  Site: $($site.Url)"
    if (-Not $dryRun) { $null = Set-PnPTenantSite -Connection $adminCon -Identity $site.Url -Owners $owners }
}

$Cult = Get-Culture
$WeekRule = $Cult.DateTimeFormat.CalendarWeekRule.value__
$FirstDayOfWeek = $Cult.DateTimeFormat.FirstDayOfWeek.value__

# Purging versions
Write-Host "Purging versions" -ForegroundColor $CommandInfo
foreach ($site in $sitesToProcess)
{
    if ($site.Template -like "Redirect*") { continue }
    if (-Not $site.Url.Contains("/sites/") -And $site.Url.TrimEnd("/") -ne $AlyaSharePointUrl.TrimEnd("/")) { continue }
    if ($site.Url -in $alreadyDone) { continue }
    $alreadyDone += $site.Url

    # Login to site
    Write-Host ""
    Write-Host "  Site: $($site.Url)"
    $siteCon = LoginTo-PnP -Url $site.Url

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
        Write-Host "    DocLib: $($docLib.RootFolder.ServerRelativeUrl)"
        if ($docLib.EnableVersioning)
        {
            $minorVersionsEnabled = $docLib.EnableMinorVersions

            # Checking version history limit
            Write-Host "      Checking version history limit"
            if ($docLib.MajorVersionLimit -gt $maxMajorVersionLimit)
            {
                Write-Host "        Setting MajorVersions to $maxMajorVersionLimit"
                if (-Not $dryRun) { $null = Set-PnPList -Connection $siteCon -Identity $docLib -MajorVersions $maxMajorVersionLimit }
            }
            if ($minorVersionsEnabled -and $docLib.MajorWithMinorVersionsLimit -gt $maxMinorVersionLimit)
            {
                Write-Host "        Setting MinorVersions to $maxMinorVersionLimit"
                if (-Not $dryRun) { $null = Set-PnPList -Connection $siteCon -Identity $docLib -MinorVersions $maxMinorVersionLimit }
            }

            # Getting files
            Write-Host "      Getting files"
            $items = Get-PnPListItem -Connection $siteCon -List $docLib -PageSize 5000 -Fields "ID","Title","ContentType","File","File.ServerRelativeUrl"
            Write-Host "        $($items.Count) files"

            foreach ($item in $items)
            {
                $ct = $item.ContentType
                if ($ct.name -eq "Ordner" -or $ct.name -eq "Folder") { continue }
                #$file = $item.File
                Write-Host "        $($item.File.ServerRelativeUrl)"
                if (-Not $minorVersionsEnabled)
                {
                    switch ($PSCmdlet.ParameterSetName)
                    {
                        "KeepNumberOfVersions"
                        {
                            $versions = Get-PnPFileVersion -Connection $siteCon -Url $item.File.ServerRelativeUrl | Sort-Object -Property "Created" -Descending
                            Write-Host "          $($versions.Count) major versions"
                            if ($versions.Count -gt $keepMajorVersions)
                            {
                                $cnt = $versions.Count - $keepMajorVersions
                                Write-Host "          purging $($cnt) versions"
                                for ($i = $keepMajorVersions; $i -lt $versions.Count; $i++)
                                {
                                    Write-Host "          deleting version $($versions[$i].VersionLabel) from $($versions[$i].Created)"
                                    if (-Not $dryRun)
                                    {
                                        Remove-PnPFileVersion -Connection $siteCon -Url $item.File.ServerRelativeUrl -Identity $versions[$i].ID -Force
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
                            $versions = Get-PnPFileVersion -Connection $siteCon -Url $item.File.ServerRelativeUrl | Sort-Object -Property "Created" -Ascending
                            Write-Host "          $($versions.Count) major versions"
                            for ($i = 0; $i -lt $versions.Count; $i++)
                            {
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
                                            $keepThisVersion = $false
                                        }
                                    }
                                    if ($keepThisVersion)
                                    {
                                        if ($versions[$i].Created.ToLocalTime().AddWeeks($keepWeeks) -lt (Get-Date))
                                        {
                                            if (($i+1) -lt $versions.Count)
                                            {
                                                $DT = $versions[$i+1].Created.ToLocalTime()
                                                if ($DT.Month -eq $versions[$i].Created.ToLocalTime().Month -and $DT.Year -eq $versions[$i].Created.ToLocalTime().Year)
                                                {
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
                                                            $keepThisVersion = $false
                                                        }
                                                    }
                                                    if ($keepThisVersion)
                                                    {
                                                        if ($versions[$i].Created.ToLocalTime().AddYears($keepYears) -lt (Get-Date))
                                                        {
                                                            $keepThisVersion = $false
                                                        }
                                                        else
                                                        {
                                                            Write-Host "          keeping yearly version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within year range)"
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    Write-Host "          keeping monthly version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within month range)"
                                                }
                                            }
                                        }
                                        else
                                        {
                                            Write-Host "          keeping weekly version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within week range)"
                                        }
                                    }
                                }
                                else
                                {
                                    Write-Host "          keeping daily version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within day range)"
                                }
                                if (-Not $keepThisVersion)
                                {
                                    Write-Host "          deleting version $($versions[$i].VersionLabel) from $($versions[$i].Created)"
                                    if (-Not $dryRun)
                                    {
                                        Remove-PnPFileVersion -Connection $siteCon -Url $item.File.ServerRelativeUrl -Identity $versions[$i].ID -Force
                                    }
                                }
                            }
                            break
                        }
                    }
                }
                else
                {
                    switch ($PSCmdlet.ParameterSetName)
                    {
                        "KeepNumberOfVersions"
                        {
                            $versions = Get-PnPFileVersion -Connection $siteCon -Url $item.File.ServerRelativeUrl | Sort-Object -Property "Created" -Descending
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
                                        if (-Not $dryRun)
                                        {
                                            Remove-PnPFileVersion -Connection $siteCon -Url $item.File.ServerRelativeUrl -Identity $minors[$i].ID -Force
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
                            $versions = Get-PnPFileVersion -Connection $siteCon -Url $item.File.ServerRelativeUrl | Sort-Object -Property "Created" -Ascending
                            Write-Host "          $($versions.Count) major/minor versions"
                            $revs = $versions.VersionLabel | Where-Object { $_ -like "*.0" }
                            Write-Host "          $($revs.Count) revisions"
                            for ($i = 0; $i -lt $versions.Count; $i++)
                            {
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
                                            $keepThisVersion = $false
                                        }
                                    }
                                    if ($keepThisVersion)
                                    {
                                        if ($versions[$i].Created.ToLocalTime().AddWeeks($keepWeeks) -lt (Get-Date))
                                        {
                                            if (($i+1) -lt $versions.Count)
                                            {
                                                $DT = $versions[$i+1].Created.ToLocalTime()
                                                if ($DT.Month -eq $versions[$i].Created.ToLocalTime().Month -and $DT.Year -eq $versions[$i].Created.ToLocalTime().Year)
                                                {
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
                                                            $keepThisVersion = $false
                                                        }
                                                    }
                                                    if ($keepThisVersion)
                                                    {
                                                        if ($versions[$i].Created.ToLocalTime().AddYears($keepYears) -lt (Get-Date))
                                                        {
                                                            $keepThisVersion = $false
                                                        }
                                                        else
                                                        {
                                                            Write-Host "          keeping yearly version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within year range)"
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    Write-Host "          keeping monthly version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within month range)"
                                                }
                                            }
                                        }
                                        else
                                        {
                                            Write-Host "          keeping weekly version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within week range)"
                                        }
                                    }
                                }
                                else
                                {
                                    Write-Host "          keeping daily version $($versions[$i].VersionLabel) from $($versions[$i].Created) (within day range)"
                                }
                                if (-Not $keepThisVersion)
                                {
                                    if ($versions[$i].VersionLabel -like "*.0" )
                                    {
                                        Write-Host "          keeping revision version $($versions[$i].VersionLabel) from $($versions[$i].Created)"
                                    }
                                    else
                                    {
                                        Write-Host "          deleting version $($versions[$i].VersionLabel) from $($versions[$i].Created)"
                                        if (-Not $dryRun)
                                        {
                                            Remove-PnPFileVersion -Connection $siteCon -Url $item.File.ServerRelativeUrl -Identity $versions[$i].ID -Force
                                        }
                                    }
                                }
                            }
                            break
                        }
                    }
                }
            }
        }
        else
        {
            Write-Host "      Versioning not enabled"
        }

    }

}

# Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIvCQYJKoZIhvcNAQcCoIIu+jCCLvYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAumSJhUxlwrAga
# C4rDd79qPp0icVROT49dwtcgNRjGF6CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFpGJ1kB
# dLt8OCSOpxpdE2al6/5eA2LqCqGskbxp1wrlMA0GCSqGSIb3DQEBAQUABIICADz4
# ADU8gLtfUAnLS/QvN9U1pJR2DSpOe6A/KrC0Xr0eiA3JzNz/Bu1ru1AkxOczWCD9
# Zh32yPc0sFKw0TQljOd9fa4xp3eo0+MTk2YuDZhwItGmRDKveHbqLWZDSSy8JoKx
# hhrbBV+WDNHFIEu8JVDaoaer6wW79S+hByZYRzm/8/DGBQcMcT7J5L04A6gNV1NB
# Bn5Wo9RL4H52WJ5r2GJlnDtj6ILgfeWmY8CxEEUtuvAYMs4hvUQC8wHBXoSl5U++
# D8QECVXM1S+6HL+kpCo55axsUd1ZL38OVO7g7YzAi0T2EMJtthGL7haK0TjgAfdF
# J/AdzjhO5NLWhd6gunkR05EjMlCpcTkKsOAbVyZNWk/bdb1wgE30pyRh5xOYUJkI
# v/kx0xQs8qmUKxXOfoOZ55oJapWLI9eHCUUl8OpeLC3NVr+pmxXI/yGlGFqmfdBL
# YNyXaAmg5p1WadUMKZsfM3Ojqai5+gO+JEepM4gB5OulDpJ+TZ/Mdnw0kS2+jBKo
# dEE/Ykk1emlAKD3AwhTsT+1NizQNyDyC5uBwlUXfaMZEZTGUPGfwjRMLcH0V/Ssw
# ArN0cmWgt7Y0JVxDNwGMl1N8qg30OoGs5GiYYVRTG2m5wuc3MWjZRGxJwcVpJ2Q5
# zTnIP3NCpztQNte+3b+7oCPpBvST1GFQJHL9vfavoYIWuzCCFrcGCisGAQQBgjcD
# AwExghanMIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEw
# gd8GCyqGSIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCCXeQwBV3N2J5AziutBEglncOMrAJnZcpk+8iR7ZblIfwIUdd0x
# LbVekHrm9AfIjqmUmyPHM98YDzIwMjUxMDE3MDUwNDQxWjADAgEBoFikVjBUMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwh
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMC
# AQICEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNp
# Z24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5
# WhcNMzQxMjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFs
# U2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWdu
# MSAtIFI2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4
# PuCF6+aqCj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb
# 5gk0Xydy3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJSc
# RV1W6/6efi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy
# 5RJY+o1NWhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY
# 0Lie04DuKbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2Z
# wbI6yiFHaS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYh
# KUlrMH9+2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5s
# WtX1qvCzk6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGo
# MIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYD
# VR0OBBYEFIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQC
# MEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSB
# gzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2Ev
# Z3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2Jh
# bHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaA
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9j
# cmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG
# 9w0BAQwFAAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26
# IFq7fQMIrN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76Tkv
# L+v2f4mHolGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftP
# ttS+G/MhNUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIl
# S3Ki74CU15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt
# 8DT4RQj9LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5
# lgJkgXEc1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD
# 9hQchjiGkyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71
# yzGKWnbAWQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGL
# ZtJFJzGJD7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVA
# GXCqHsh62QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZ
# MIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAw
# MDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOv
# dYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt
# 0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHP
# vIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFU
# UweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16
# ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS
# 2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm1
# 9m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIG
# bxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMD
# Ad6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/Miy
# Tdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9
# GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGG
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDD
# vWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEB
# BDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jv
# b3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29t
# L3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0B
# AQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYW
# axlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCy
# z+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQ
# cXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0
# Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59e
# odaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8
# oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1
# If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbcl
# IA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2M
# tnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB
# +SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIID
# a6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQL
# ExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjET
# MBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAw
# MDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQK
# EwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4
# QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTe
# c5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWy
# ZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7tt
# U+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrK
# otudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKF
# t3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTfl
# puwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2Fm
# CWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5
# paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4O
# hxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwo
# TK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki
# 5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnm
# XNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJE
# lrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMp
# mY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6
# JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG
# 7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/
# gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324G
# abbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5
# MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO7
# 7oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4st
# Q1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjx
# guhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJ
# YIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZI
# hvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcN
# AQkEMSIEIMpx1AZlAFYqMclvEp9fmaF019MjhNz+5ZbWZ+jtMsGnMIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1or
# d69gXP0wczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAmXFU
# g7D8pOWpH7OrfdDbytUqFvyf/JRVMdjGOxmntjPi9/ckGiYBr8gEKKwHEoi+CNN/
# CvWW+cu1K7nKR36bbF3hzAUVAG5TJVMDRL5i4nwjm1IPX7RyoBhypFElWl/WTzgt
# f0fqoaVofw7uycL61TRYV2FfLE1R36DI7xrMYlySEy/Cg5NvwQF2VnDkHX4gMz6Z
# Tej6UfGFhQzlJyhdfsE8VmCnaRTPsZpEy32s871+KtoKfxzA3G11Lve3EQJLmkt7
# /TNGQBRsA7leAlHw3OoAx9RacnKPmmm6c5e2tYo7k7/NPVRBjnM1pTWYwSdeVlZR
# OFiDuadxnywzdtQbY2VI6hjv++rnpzIns5JBHjQUwEz3rH+BlZG8f9zOUPPW1JY9
# 02c1fkHJSrFS3hgRXSb9ctTPgUFB5waG9eF4agOqWMKPq1O2/ZhotWc6yKvTPxmx
# jjdiqGYzP2BK99B8eZz0GN1uOLlEHXNIGNpNMs0tBoQq/0g75TkTXD6kg1tV
# SIG # End signature block
