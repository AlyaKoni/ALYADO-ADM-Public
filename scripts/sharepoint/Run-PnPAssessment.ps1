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
    03.09.2026 Konrad Brunner       Initial Version
    04.09.2026 Konrad Brunner       Run the assessment tool without output capturing by
                                    default (fixes the Spectre.Console invalid console
                                    handle crash). Output is only captured when it must
                                    be parsed (assessment id detection after a start,
                                    list polling while waiting for completion).

#>

<#
.SYNOPSIS
Automates installation, update and execution of the Microsoft 365 Assessment tool.

.DESCRIPTION
The Run-PnPAssessment.ps1 script installs the Microsoft 365 Assessment tool into
$AlyaTools\pnpassessment when missing, checks GitHub releases for a newer
platform-specific version and then runs the selected assessment CLI action. For
assessment starts it uses the app-only certificate environment specified by the 
AlyaManagementApp, AlyaManagementCrt, and AlyaManagementPwd variables.

The tool is executed directly against the console by default (no output
capturing), because capturing its output redirects stdout into a pipe, which
breaks the Spectre.Console live rendering used inside the tool (crash:
"System.IO.IOException: The handle is invalid" at Console.set_CursorVisible).
The tool output is only captured when the script has to parse it: to detect the
assessment id after a start (when AssessmentId is not specified), and for the
list polling while waiting for completion. Note that under Start-Transcript the
direct native tool output is not logged into the transcript; this is accepted.

.PARAMETER Action
Assessment tool action to run. Start starts a new assessment, Report generates
report output, List/Status show assessment state, Pause/Restart/Stop/Cache run
the matching operational commands.

.PARAMETER Mode
Assessment mode passed to the start action.

.PARAMETER Tenant
SharePoint tenant host passed to --tenant. Defaults to the host part of
$AlyaSharePointUrl.

.PARAMETER SitesList
Optional site collection URLs passed to --siteslist for scoped assessments.

.PARAMETER SitesFile
Optional file containing site collection URLs passed to --sitesfile.

.PARAMETER AssessmentId
Assessment id for report, pause or restart actions.

.PARAMETER Threads
Number of parallel operations used for start or restart actions.

.PARAMETER ReportMode
Report mode used by the report action or by CreateReport after a start.

.PARAMETER ReportPath
Optional custom report output path.

.PARAMETER CreateReport
After Start, create a report for the detected assessment id. Use WaitForCompletion
when the assessment does not finish before the start command returns.

.PARAMETER WaitForCompletion
After Start, poll the assessment list until the new assessment is finished before
creating a report.

.PARAMETER ForceUpdate
Download the latest matching Microsoft 365 Assessment tool release even when the
local manifest already matches it.

.INPUTS
None. The script does not accept pipeline input.

.OUTPUTS
Console output from the Microsoft 365 Assessment tool and an optional summary
object when PassThru is true.

.EXAMPLE
PS> .\Run-PnPAssessment.ps1 -Mode AddInsACS -Threads 6

.EXAMPLE
PS> .\Run-PnPAssessment.ps1 -Mode Alerts -SitesFile "C:\Temp\sites.txt" -CreateReport $true -WaitForCompletion $true

.EXAMPLE
PS> .\Run-PnPAssessment.ps1 -Action Report -AssessmentId "22989c75-f08f-4af9-8857-6f19e333d6d3" -ReportMode CsvOnly -ReportPath "C:\Temp\assessment-report"

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Start", "List", "Status", "Report", "Stop", "Pause", "Restart", "Cache")]
    [string]$Action = "Start",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Classic", "InfoPath", "AddInsACS", "Alerts")]
    [string]$Mode = "AddInsACS",

    [Parameter(Mandatory = $false)]
    [string]$Tenant = "",

    [Parameter(Mandatory = $false)]
    [string[]]$SitesList = @(),

    [Parameter(Mandatory = $false)]
    [string]$SitesFile = "",

    [Parameter(Mandatory = $false)]
    [string]$AssessmentId = "",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 64)]
    [int]$Threads = 6,

    [Parameter(Mandatory = $false)]
    [ValidateSet("PowerBI", "CsvOnly")]
    [string]$ReportMode = "CsvOnly",

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = "",

    [Parameter(Mandatory = $false)]
    [bool]$CreateReport = $false,

    [Parameter(Mandatory = $false)]
    [bool]$WaitForCompletion = $false,

    [Parameter(Mandatory = $false)]
    [ValidateRange(10, 86400)]
    [int]$WaitTimeoutSeconds = 21600,

    [Parameter(Mandatory = $false)]
    [ValidateRange(10, 3600)]
    [int]$PollSeconds = 60,

    [Parameter(Mandatory = $false)]
    [bool]$ForceUpdate = $false,

    [Parameter(Mandatory = $false)]
    [bool]$PassThru = $false
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1
if ([string]::IsNullOrWhiteSpace($env:TEMP))
{
    $env:TEMP = [System.IO.Path]::GetTempPath()
}

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Run-PnPAssessment-$($AlyaTimeString).log" | Out-Null

function Get-PnPAssessmentPlatform()
{
    if ($IsWindows)
    {
        return @{
            ReleaseSuffix = "windows"
            BinaryName = "microsoft365-assessment.exe"
        }
    }
    if ($IsMacOS)
    {
        return @{
            ReleaseSuffix = "macOS"
            BinaryName = "microsoft365-assessment"
        }
    }
    if ($IsLinux)
    {
        return @{
            ReleaseSuffix = "linux"
            BinaryName = "microsoft365-assessment"
        }
    }

    throw "Unsupported operating system for the Microsoft 365 Assessment tool."
}

function ConvertTo-PnPAssessmentVersion([string]$TagName)
{
    if ($TagName -notmatch "^v(?<Version>[0-9]+(\.[0-9]+){1,3})-")
    {
        return [version]"0.0.0"
    }

    return [version]$Matches["Version"]
}

function Get-LatestPnPAssessmentRelease([string]$ReleaseSuffix)
{
    $releaseUri = "https://api.github.com/repos/pnp/pnpassessment/releases?per_page=100"
    $guid = [Guid]::NewGuid().ToString()
    $headers = @{
        "Accept" = "application/vnd.github+json"
        "User-Agent" = "Alya-Run-PnPAssessment-$guid"
    }
    $releases = @((Invoke-RestMethod -Uri $releaseUri -Headers $headers -Method Get))
    $matchingReleases = @(
        $releases |
            Where-Object { $_.prerelease -eq $false -and $_.draft -eq $false -and $_.tag_name -like "*-$ReleaseSuffix" } |
            Sort-Object -Property @{ Expression = { ConvertTo-PnPAssessmentVersion -TagName $_.tag_name }; Descending = $true }
    )

    if ($matchingReleases.Count -lt 1)
    {
        throw "Could not find a Microsoft 365 Assessment tool release for platform suffix '$ReleaseSuffix'."
    }

    return $matchingReleases[0]
}

function Read-PnPAssessmentManifest([string]$ManifestPath)
{
    if (-not (Test-Path -Path $ManifestPath))
    {
        return $null
    }

    return Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json
}

function Install-PnPAssessmentTool(
    [string]$InstallPath,
    [bool]$Force
)
{
    $platform = Get-PnPAssessmentPlatform
    $binaryPath = Join-Path -Path $InstallPath -ChildPath $platform.BinaryName
    $manifestPath = Join-Path -Path $InstallPath -ChildPath "version.json"
    try {
        $latestRelease = Get-LatestPnPAssessmentRelease -ReleaseSuffix $platform.ReleaseSuffix
    }
    catch {
        Write-Host "Not able to get latest release from GitHub. Expecting installation is not required." -ForegroundColor $CommandError
        return $binaryPath
    }
    $asset = @($latestRelease.assets | Where-Object { $_.name -eq $platform.BinaryName })[0]

    if ($null -eq $asset)
    {
        throw "Release '$($latestRelease.tag_name)' does not contain asset '$($platform.BinaryName)'."
    }

    $manifest = Read-PnPAssessmentManifest -ManifestPath $manifestPath
    $installedTag = $null
    if ($null -ne $manifest -and $null -ne $manifest.PSObject.Properties["TagName"])
    {
        $installedTag = $manifest.TagName
    }

    $needsDownload = $Force -eq $true -or -not (Test-Path -Path $binaryPath) -or $installedTag -ne $latestRelease.tag_name
    if ($needsDownload -eq $false)
    {
        Write-Host "Microsoft 365 Assessment tool is current: $installedTag" -ForegroundColor $CommandSuccess
        return $binaryPath
    }

    if (-not (Test-Path -Path $InstallPath))
    {
        $null = New-Item -Path $InstallPath -ItemType Directory -Force
    }

    Write-Host "Downloading Microsoft 365 Assessment tool $($latestRelease.tag_name)" -ForegroundColor $CommandInfo
    $downloadPath = Join-Path -Path $InstallPath -ChildPath "$($platform.BinaryName).download"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $downloadPath -UseBasicParsing

    if (Test-Path -Path $binaryPath)
    {
        Remove-Item -Path $binaryPath -Force
    }
    Move-Item -Path $downloadPath -Destination $binaryPath -Force

    if (-not $IsWindows)
    {
        $binary = Get-Item -Path $binaryPath
        if ($null -ne $binary.PSObject.Properties["UnixFileMode"])
        {
            $binary.UnixFileMode = [System.IO.UnixFileMode]"UserRead, UserWrite, UserExecute, GroupRead, GroupExecute, OtherRead, OtherExecute"
        }
        else
        {
            $null = chmod +x $binaryPath
        }
    }

    @{
        TagName = $latestRelease.tag_name
        Version = (ConvertTo-PnPAssessmentVersion -TagName $latestRelease.tag_name).ToString()
        Platform = $platform.ReleaseSuffix
        AssetName = $asset.name
        DownloadUrl = $asset.browser_download_url
        InstalledAt = (Get-Date).ToString("o")
    } | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath -Encoding UTF8 -Force

    return $binaryPath
}

function Import-AlyaManagementEnvironment()
{
    $tempPath = $env:TEMP
    if ([string]::IsNullOrWhiteSpace($tempPath))
    {
        $tempPath = [System.IO.Path]::GetTempPath()
    }
    $environmentFile = Join-Path -Path $tempPath -ChildPath "$AlyaTenantId-Actual.env"
    if (Test-Path -Path $environmentFile)
    {
        $envVars = Get-Content -Path $environmentFile -Raw | ConvertFrom-Json -AsHashtable
        foreach ($key in $envVars.Keys)
        {
            [Environment]::SetEnvironmentVariable($key, $envVars[$key], "Process")
        }
    }
}

function Assert-AlyaManagementAuthentication()
{
    Import-AlyaManagementEnvironment

    if ([string]::IsNullOrWhiteSpace($env:AlyaManagementApp))
    {
        throw "Env var AlyaManagementApp is not set."
    }
    if ([string]::IsNullOrWhiteSpace($env:AlyaManagementCrt))
    {
        throw "Env var AlyaManagementCrt is not set."
    }
    if ([string]::IsNullOrWhiteSpace($env:AlyaManagementPwd))
    {
        throw "Env var AlyaManagementPwd is not set."
    }
    if (-not (Test-Path -Path $env:AlyaManagementCrt))
    {
        throw "Env var AlyaManagementCrt points to '$($env:AlyaManagementCrt)', but the certificate file does not exist."
    }
}

function Get-DefaultAssessmentTenant()
{
    if (-not [string]::IsNullOrWhiteSpace($Tenant))
    {
        return $Tenant
    }

    if ([string]::IsNullOrWhiteSpace($AlyaSharePointUrl))
    {
        throw "Tenant was not specified and AlyaSharePointUrl is empty."
    }

    return ([System.Uri]$AlyaSharePointUrl).Host
}

function Find-AssessmentIdFromOutput([string]$OutputText)
{
    $match = [regex]::Match($OutputText, "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
    if ($match.Success)
    {
        return $match.Value
    }

    return ""
}

function Get-AssessmentStatusFromListOutput(
    [string]$OutputText,
    [string]$Id
)
{
    foreach ($line in ($OutputText -split "\r?\n"))
    {
        if ($line -notmatch [regex]::Escape($Id))
        {
            continue
        }
        if ($line -match "\bfinished\b")
        {
            return "finished"
        }
        if ($line -match "\bterminated\b")
        {
            return "terminated"
        }
        if ($line -match "\brunning\b")
        {
            return "running"
        }
        if ($line -match "\bpaused\b")
        {
            return "paused"
        }
    }

    return ""
}

function Invoke-AssessmentTool(
    [string]$ToolPath,
    [string[]]$Arguments,
    [string]$WorkingDirectory,
    [bool]$CaptureOutput = $false
)
{
    Push-Location -Path $WorkingDirectory
    try
    {
        Write-Host "Running Microsoft 365 Assessment tool action '$($Arguments[0])'" -ForegroundColor $CommandInfo
        if ($CaptureOutput -eq $true)
        {
            # Capturing must only be used when the output has to be parsed
            # (assessment id detection after a start, list polling while waiting
            # for completion). Capturing redirects stdout into a pipe, which
            # breaks the Spectre.Console live rendering inside the tool
            # (System.IO.IOException "The handle is invalid" at
            # Console.set_CursorVisible).
            $outputLines = @(& $ToolPath @Arguments 2>&1)
            $exitCode = $LASTEXITCODE
            foreach ($line in $outputLines)
            {
                Write-Host $line
            }
            $outputText = ($outputLines | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
            return @{
                ExitCode = $exitCode
                OutputText = $outputText
                AssessmentId = Find-AssessmentIdFromOutput -OutputText $outputText
            }
        }

        # Run directly against the console so the tool keeps its real console
        # handle (required by the Spectre.Console live rendering). The exit
        # code is read from $LASTEXITCODE by the caller.
        # IMPORTANT: the caller must NOT capture or assign this invocation
        # (no $x = Invoke-AssessmentTool ...), otherwise PowerShell pipes the
        # native output again and the console handle is lost.
        & $ToolPath @Arguments
    }
    finally
    {
        Pop-Location
    }
}

function New-StartArguments()
{
    if (-not [string]::IsNullOrWhiteSpace($SitesFile) -and $SitesList.Count -gt 0)
    {
        throw "SitesFile and SitesList cannot be combined."
    }

    Assert-AlyaManagementAuthentication

    $arguments = @(
        "start",
        "--mode",
        $Mode,
        "--authmode",
        "application",
        "--tenant",
        (Get-DefaultAssessmentTenant),
        "--applicationid",
        $env:AlyaManagementApp,
        "--certfile",
        $env:AlyaManagementCrt,
        "--certpassword",
        $env:AlyaManagementPwd,
        "--threads",
        $Threads.ToString()
    )

    if (-not [string]::IsNullOrWhiteSpace($SitesFile))
    {
        if (-not (Test-Path -Path $SitesFile))
        {
            throw "SitesFile '$SitesFile' does not exist."
        }
        $arguments += @("--sitesfile", (Resolve-Path -Path $SitesFile).Path)
    }
    elseif ($SitesList.Count -gt 0)
    {
        $arguments += @("--siteslist", ($SitesList -join ","))
    }

    return $arguments
}

function New-ReportArguments([string]$Id)
{
    if ([string]::IsNullOrWhiteSpace($Id))
    {
        throw "AssessmentId is required for report generation."
    }

    $arguments = @(
        "report",
        "--id",
        $Id,
        "--mode",
        $ReportMode,
        "--delimiter",
        "Semicolon",
        "--open",
        "false"
    )

    if (-not [string]::IsNullOrWhiteSpace($ReportPath))
    {
        $arguments += @("--path", $ReportPath)
    }

    return $arguments
}

function Wait-AssessmentCompletion(
    [string]$ToolPath,
    [string]$InstallPath,
    [string]$Id
)
{
    if ([string]::IsNullOrWhiteSpace($Id))
    {
        throw "Could not detect the started assessment id. Use -AssessmentId or run report separately after checking the list output."
    }

    $stopAt = (Get-Date).AddSeconds($WaitTimeoutSeconds)
    while ((Get-Date) -lt $stopAt)
    {
        $listResult = Invoke-AssessmentTool -ToolPath $ToolPath -Arguments @("list") -WorkingDirectory $InstallPath -CaptureOutput $true
        $assessmentStatus = Get-AssessmentStatusFromListOutput -OutputText $listResult.OutputText -Id $Id
        if ($assessmentStatus -eq "finished")
        {
            Write-Host "Assessment $Id finished." -ForegroundColor $CommandSuccess
            return
        }
        if ($assessmentStatus -eq "terminated")
        {
            throw "Assessment $Id is terminated."
        }

        Write-Host "Assessment $Id status is '$assessmentStatus'. Waiting $PollSeconds seconds." -ForegroundColor $CommandInfo
        Start-Sleep -Seconds $PollSeconds
    }

    throw "Timed out waiting for assessment $Id after $WaitTimeoutSeconds seconds."
}

try
{
    $installPath = Join-Path -Path $AlyaTools -ChildPath "pnpassessment"
    $toolPath = Install-PnPAssessmentTool -InstallPath $installPath -Force $ForceUpdate

    Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
    Write-Host "SharePoint | Run-PnPAssessment | Microsoft 365 Assessment" -ForegroundColor $CommandInfo
    Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

    $arguments = @()
    switch ($Action)
    {
        "Start" {
            $arguments = New-StartArguments
        }
        "List" {
            $arguments = @("list")
        }
        "Status" {
            $arguments = @("status")
        }
        "Report" {
            $arguments = New-ReportArguments -Id $AssessmentId
        }
        "Stop" {
            $arguments = @("stop")
        }
        "Pause" {
            if ([string]::IsNullOrWhiteSpace($AssessmentId))
            {
                $arguments = @("pause", "--all:`$true")
            }
            else
            {
                $arguments = @("pause", "--id", $AssessmentId)
            }
        }
        "Restart" {
            if ([string]::IsNullOrWhiteSpace($AssessmentId))
            {
                throw "AssessmentId is required for restart."
            }
            $arguments = @("restart", "--id", $AssessmentId, "--threads", $Threads.ToString())
        }
        "Cache" {
            $arguments = @("cache", "--clearauthentication")
        }
    }

    # Capturing is only needed when the output must be parsed: after a start,
    # the assessment id has to be read from the output, unless it was already
    # specified via -AssessmentId.
    $captureMainOutput = $false
    if ($Action -eq "Start" -and ($CreateReport -eq $true -or $WaitForCompletion -eq $true) -and [string]::IsNullOrWhiteSpace($AssessmentId))
    {
        $captureMainOutput = $true
    }

    $result = $null
    if ($captureMainOutput -eq $true)
    {
        $result = Invoke-AssessmentTool -ToolPath $toolPath -Arguments $arguments -WorkingDirectory $installPath -CaptureOutput $true
        if ($result.ExitCode -ne 0)
        {
            throw "Microsoft 365 Assessment tool exited with code $($result.ExitCode)."
        }
    }
    else
    {
        # Direct console execution (no output capturing). This call must stay
        # at statement position: assigning or piping it would redirect the
        # native output and break the Spectre.Console live rendering inside
        # the tool. Under Start-Transcript this direct native output is not
        # logged; this is accepted.
        Invoke-AssessmentTool -ToolPath $toolPath -Arguments $arguments -WorkingDirectory $installPath
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0)
        {
            throw "Microsoft 365 Assessment tool exited with code $($exitCode)."
        }
        $result = @{
            ExitCode = $exitCode
            OutputText = ""
            AssessmentId = $AssessmentId
        }
    }

    if ($Action -eq "Start" -and ($CreateReport -eq $true -or $WaitForCompletion -eq $true))
    {
        $effectiveAssessmentId = $AssessmentId
        if ([string]::IsNullOrWhiteSpace($effectiveAssessmentId))
        {
            $effectiveAssessmentId = $result.AssessmentId
        }

        if ($WaitForCompletion -eq $true)
        {
            Wait-AssessmentCompletion -ToolPath $toolPath -InstallPath $installPath -Id $effectiveAssessmentId
        }

        if ($CreateReport -eq $true)
        {
            $reportArguments = New-ReportArguments -Id $effectiveAssessmentId
            # Direct console execution, see above. The report output is not
            # parsed, so no capturing is needed.
            Invoke-AssessmentTool -ToolPath $toolPath -Arguments $reportArguments -WorkingDirectory $installPath
            if ($LASTEXITCODE -ne 0)
            {
                throw "Microsoft 365 Assessment report generation exited with code $($LASTEXITCODE)."
            }
        }
    }

    if ($PassThru -eq $true)
    {
        [pscustomobject]@{
            Action = $Action
            ToolPath = $toolPath
            InstallPath = $installPath
            ExitCode = $result.ExitCode
            AssessmentId = $result.AssessmentId
        }
    }
}
finally
{
    Stop-Transcript
}

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC0Kf73d13/N3K0
# TENaKHHblxIJDYk75ChfIQxL6QhJ9qCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICgnSvAI
# XH2aBuKb5xXhCC2NtN3PM82Ro7FbASr3TctGMA0GCSqGSIb3DQEBAQUABIICADQR
# 7tcI1qzws+5IbQpYhV1hfwpaITs+36YhxdLG7Lda5u/JNviuhE2S0nyGi/umuJVu
# HvHJcpE52PFbOnwkigOacL72E01vgT3NFy9F9n3RvfnEc8mrAI0YIiwVNjiiwvjF
# 3fBE+hXs3MYkwUmuWlktHKVq8xPE4z+QnkIPVBJhULYsVERXaiTQZTLU3XSpePzs
# nXuaefOjLIbr0VTfkM65MBuL41j2cu2mW1uh2tuE8IAjSlmBbhevbBuAp3BcHs8z
# rKvBSyQkL2o2fS74cTrjP2xXs3/WibDjy165ldjs4TbKqpxxUYrM5MfJUZd57r5y
# hgn8J5j3/Of1xcm7qDZmzgjd+HNuryF2qUA6sVJ7zTvYzFFbepAGIxOpsf5Ycc3w
# TbTNiNpkFr+2GvXE27+Ao0/1D94ZcgK3DnEmBM5jbzaEQbRSrfHiBngD4GQK5Qjw
# E0e0iWQHFAEIioLvixoU4yssUnlkU7jAKBMr5bHjqoSDFgs8mheBQbMQN8Jikx6h
# N29eKDALaAND4t38A9PkrxBavDMTZsu8FrczxVhugBg4bUNrJxMpSGeqp5N1lHfS
# 9Z76gq8Rf6PE70J+wCOhZeUEqHBX//ueg3hPJEVkKkF+al0cEaDDeaJrV1bMQbId
# yZ8T9pAXbSMnq+AiHsQr9dXcPfm5ctYcLTT6aDUooYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCA2pibxBw9l+NvwNehWd99iM66qklFi0Hn+FBNgJ3e63AIUagrJ
# Q8bpN1H4Hap9wjiBMJ4bNQcYDzIwMjYwOTEwMDc1NzU1WjADAgEBoF2kWzBZMQsw
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
# BDEyBDBRKvPEI3rYQUFWf40nijbh+MFxqSt1VvXyMVWrX3um9vQV1fsOCnYV+N4G
# 0CYi/xIwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAbokxKtbexXzNgQr5h2lUnwlZza9GVAZzwVCJu8J4uscH
# 3kIeUXDsGZ0ggcVtwVjHXIj+KCr/4Pr69FcwnCeP9ZmlSCcUudJQN/Kcic+RmXkD
# A3LP6eyvbD05Om2r6m5NByFU5WK6QdrkelSCxTQyQ/FANWu4VRrLvlZqi/pnXRPK
# XcDc8lkYVLqwoXmiVt2i4ZlnjVojAa4ftguJTcf/TCAHKCqOFdfjettrQQ93NCgu
# eYUPO7Su8ff3OcgIQVqUHB5Q86f21Wso0l6Z+TVJ3v6iv6J4KwNl27L8TxkYNj8W
# WXK+jhoWrjMvKtlBHxHtBtCrjBVQTRjbpXQuQRabhBfJy4lZE693DKH9P/435/vw
# efXLufDJ2MGFQXQXhawaaL7o+Emfm6i31jX/RqTm+lqnyeiHsPdNxjn63qMYa/g7
# JWuFFscF1cFQrrdsPvaQ6hr10+Ec+n90N6d4K+wdFkScdQx3us5koSEiDBsmcc42
# kfmQFrwzVhuzHIA/kB3s
# SIG # End signature block
