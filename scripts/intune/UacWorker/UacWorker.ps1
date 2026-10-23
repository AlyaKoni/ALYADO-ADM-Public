#Requires -Version 5.1

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
    19.10.2026 Konrad Brunner       Initial version
    19.10.2026 Konrad Brunner       Owner-SID-Vergleich: Fallback wenn (Get-Acl).Owner bereits ein SID-String ist (AzureAD-Konten S-1-12-1-* sind per NTAccount nicht immer uebersetzbar, Realfall LAPTOP-FK18B4TV)
    19.10.2026 Konrad Brunner       Loop-Haertung: Heartbeat-Write und Job-Auswahl mit try/catch - transiente Dateisystemfehler (z. B. Sharing Violation durch gleichzeitige Leser) beenden den Loop nicht mehr und lassen den Heartbeat nicht mehr stillstehen
    19.10.2026 Konrad Brunner       Exit-Code robust: parameterloses WaitForExit (Stream-Flush + ExitCode zuverlaessig) und Fallback auf job.exitcode, wenn der Prozess-ExitCode nicht lesbar ist (Realfall FortiClient: ExitCode-Read warf und machte einen erfolgreichen Job zu -1); result.json neu mit ExitCodeSource/ProcessExitCode/JobExitCode

#>

<#
.SYNOPSIS
Internal elevated worker of the Alya UAC worker message bus. Never call directly - use Start-UacWorker.

.DESCRIPTION
UacWorker.ps1 runs elevated (started by Start-UacWorker through a single UAC prompt) and processes job requests from the file based message bus under %ProgramData%\AlyaConsulting\UacWorker. It is self-contained by design: it does NOT dot-source 01_ConfigureEnv.ps1 to keep the elevated context free of heavy dependencies. Security model: no code is ever transferred over the bus - a job manifest (input\<guid>\job.json) references a signed job script in JobsRoot by plain file name only. Before execution the worker validates the session nonce (replay protection), the job name pattern, the canonical path inside JobsRoot (no reparse points), a valid Alya Consulting Authenticode signature, and that the caller SID in the manifest matches the real owner of the input folder (spoof protection). ACLs: input\ allows authenticated users to create own job folders only (Creator Owner FullControl), output\ is read-only for authenticated users with per-guid ownership transfer to the submitter, control\ is a signal dropbox, session.json and registry.jsonl are admin-written and user-readable. The registry (registry.jsonl) is an append-only audit log written exclusively by the worker: who started what, when, with which result. The worker ends on idle timeout, on control\stop.signal (graceful or force) and heartbeats every 10 seconds into session.json.

.INPUTS
None. Parameters are passed by Start-UacWorker only.

.OUTPUTS
None. Writes to the message bus and to its transcript under C:\ProgramData\AlyaConsulting\Logs.

.EXAMPLE
PS> powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File UacWorker.ps1 -Base C:\ProgramData\AlyaConsulting\UacWorker -Nonce <guid> -JobsRoot <repo>\scripts\intune\UacWorker\Jobs -InvokerSid <sid> -InvokerName <name>'
Internal start pattern (done by Start-UacWorker).

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$Base,
    [Parameter(Mandatory = $true)]
    [string]$Nonce,
    [Parameter(Mandatory = $true)]
    [string]$JobsRoot,
    [string]$InvokerSid = "",
    [string]$InvokerName = "",
    [int]$IdleTimeoutMin = 30
)

$ErrorActionPreference = "Stop"

# --- Transcript ---
$logDir = Join-Path $env:ProgramData "AlyaConsulting\Logs"
if (-Not (Test-Path $logDir))
{
    $null = New-Item -Path $logDir -ItemType Directory -Force
}
$nonceShort = $Nonce
if ($Nonce.Length -gt 8)
{
    $nonceShort = $Nonce.Substring(0, 8)
}
Start-Transcript -Path "$logDir\UacWorker-$nonceShort.log" -Force

# --- Helper functions ---

function Enable-UacTokenPrivilege
{
    [CmdletBinding()]
    param(
        [string]$Privilege
    )

    if (-Not ("Alya.Uac.TokenPrivileges" -as [type]))
    {
        Add-Type -Namespace "Alya.Uac" -Name "TokenPrivileges" -MemberDefinition @"
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct LUID { public uint LowPart; public int HighPart; }
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID Luid; public uint Attributes; }
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool LookupPrivilegeValue(string host, string name, out LUID luid);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
public static void Enable(string privilege)
{
    IntPtr token;
    OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x28, out token);
    TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
    tp.PrivilegeCount = 1;
    LookupPrivilegeValue(null, privilege, out tp.Luid);
    tp.Attributes = 0x2;
    AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
}
"@
    }
    [Alya.Uac.TokenPrivileges]::Enable($Privilege)
}

function Set-UacAcl
{
    [CmdletBinding()]
    param(
        [string]$Path,
        [string]$Kind
    )

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $sidAuthenticated = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
    $sidCreatorOwner = New-Object System.Security.Principal.SecurityIdentifier("S-1-3-0")
    $sidAdmins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $sidSystem = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $inheritAll = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $inheritNone = [System.Security.AccessControl.InheritanceFlags]"None"
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $null = $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidAdmins, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritAll, $inheritNone, $allow)))
    $null = $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidSystem, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritAll, $inheritNone, $allow)))
    if ($Kind -eq "Base")
    {
        # Everyone authenticated may read session.json/registry.jsonl (inherited by files), nothing more
        $null = $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidAuthenticated, [System.Security.AccessControl.FileSystemRights]"ReadAndExecute", $inheritAll, $inheritNone, $allow)))
    }
    elseif ($Kind -eq "Input")
    {
        # Authenticated users may create own job folders and traverse, but never modify foreign content.
        # Creator Owner FullControl (inheritable) gives each submitter full rights on own <guid> folder.
        $null = $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidAuthenticated, [System.Security.AccessControl.FileSystemRights]"CreateDirectories,ListDirectory", $inheritNone, $inheritNone, $allow)))
        $null = $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidCreatorOwner, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritAll, $inheritNone, $allow)))
    }
    elseif ($Kind -eq "Control")
    {
        # Signal dropbox: create files (stop.signal), own signals fully controlled
        $null = $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidAuthenticated, [System.Security.AccessControl.FileSystemRights]"CreateFiles,ListDirectory", $inheritNone, $inheritNone, $allow)))
        $null = $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidCreatorOwner, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritAll, $inheritNone, $allow)))
    }
    elseif ($Kind -eq "Output")
    {
        # Read-only for authenticated users; per-guid ownership is transferred to the submitter,
        # Creator Owner FullControl then lets the submitter clean up the folder after retrieval.
        $null = $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidAuthenticated, [System.Security.AccessControl.FileSystemRights]"ReadAndExecute", $inheritAll, $inheritNone, $allow)))
        $null = $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidCreatorOwner, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritAll, $inheritNone, $allow)))
    }
    Set-Acl -Path $Path -AclObject $acl
}

function Write-UacSessionAtomic
{
    [CmdletBinding()]
    param(
        [hashtable]$Session
    )

    $sessionFile = Join-Path $Base "session.json"
    $tmpFile = "$sessionFile.tmp"
    ($Session | ConvertTo-Json -Depth 4) | Set-Content -Path $tmpFile -Encoding UTF8 -Force
    Move-Item -Path $tmpFile -Destination $sessionFile -Force
}

function Add-UacRegistryEntry
{
    [CmdletBinding()]
    param(
        [hashtable]$Entry
    )

    $registryFile = Join-Path $Base "registry.jsonl"
    if ((Test-Path $registryFile) -and ((Get-Item $registryFile).Length -gt 5MB))
    {
        Move-Item -Path $registryFile -Destination "$registryFile.old" -Force
    }
    ($Entry | ConvertTo-Json -Depth 5 -Compress) | Add-Content -Path $registryFile -Encoding UTF8
}

function Set-UacFolderOwner
{
    [CmdletBinding()]
    param(
        [string]$Path,
        [string]$OwnerSid
    )

    Enable-UacTokenPrivilege -Privilege "SeRestorePrivilege"
    $acl = Get-Acl -Path $Path
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($OwnerSid)))
    Set-Acl -Path $Path -AclObject $acl
}

function Write-UacResultAtomic
{
    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [object]$Result
    )

    $resultFile = Join-Path $OutputDir "result.json"
    $resultTmpFile = "$resultFile.tmp"
    ($Result | ConvertTo-Json -Depth 5) | Set-Content -Path $resultTmpFile -Encoding UTF8 -Force
    Move-Item -Path $resultTmpFile -Destination $resultFile -Force
}

function Get-UacJobValidation
{
    [CmdletBinding()]
    param(
        [object]$Job,
        [string]$InputDir
    )

    $validation = [ordered]@{
        Valid   = $false
        Reason  = ""
        JobPath = ""
    }
    if ("$($Job.Nonce)" -ne $Nonce)
    {
        $validation.Reason = "nonce mismatch (stale or foreign session)"
    }
    elseif ("$($Job.Name)" -notmatch "^[A-Za-z0-9_.\-]+$")
    {
        $validation.Reason = "invalid job name pattern: $($Job.Name)"
    }
    else
    {
        $jobsRootFull = [System.IO.Path]::GetFullPath($JobsRoot)
        $jobPath = [System.IO.Path]::GetFullPath((Join-Path $JobsRoot "$($Job.Name).ps1"))
        if (-Not $jobPath.StartsWith($jobsRootFull + [System.IO.Path]::DirectorySeparatorChar))
        {
            $validation.Reason = "job path escapes JobsRoot: $jobPath"
        }
        elseif (-Not (Test-Path $jobPath))
        {
            $validation.Reason = "job script not found in JobsRoot: $($Job.Name).ps1"
        }
        elseif (((Get-Item $jobPath).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or ((Get-Item $jobsRootFull).Attributes -band [System.IO.FileAttributes]::ReparsePoint))
        {
            $validation.Reason = "reparse point detected (job script or JobsRoot)"
        }
        else
        {
            $signature = Get-AuthenticodeSignature -FilePath $jobPath
            if ($signature.Status -ne "Valid" -or "$($signature.SignerCertificate.Subject)" -notlike "*Alya Consulting*")
            {
                $validation.Reason = "job script signature not valid Alya Consulting signature (Status: $($signature.Status))"
            }
            else
            {
                $ownerSidValue = ""
                try
                {
                    $ownerAccount = (Get-Acl -Path $InputDir).Owner
                    if ("$ownerAccount" -match "^S-\d+-")
                    {
                        # Unresolvable account (e.g. AzureAD SID): Owner is already the SID string
                        $ownerSidValue = "$ownerAccount"
                    }
                    else
                    {
                        $ownerSidValue = (New-Object System.Security.Principal.NTAccount($ownerAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                    }
                }
                catch
                {
                    $ownerSidValue = ""
                }
                if ($ownerSidValue -ne "$($Job.CallerSid)")
                {
                    $validation.Reason = "caller SID does not match input folder owner (spoof protection)"
                }
                else
                {
                    $validation.Valid = $true
                    $validation.JobPath = $jobPath
                }
            }
        }
    }
    $validation
}

function Invoke-UacJob
{
    [CmdletBinding()]
    param(
        [string]$InputDir
    )

    $jobGuid = Split-Path $InputDir -Leaf
    $jobFile = Join-Path $InputDir "job.json"
    $outputRoot = Join-Path $Base "output"
    $outputDir = Join-Path $outputRoot $jobGuid
    $null = New-Item -Path $outputDir -ItemType Directory -Force

    $job = $null
    try
    {
        $job = Get-Content -Path $jobFile -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch
    {
        $job = $null
    }
    if ($null -eq $job)
    {
        Write-Warning "Unreadable job manifest: $jobFile - rejected"
        $rejectResult = [ordered]@{
            JobGuid = $jobGuid; Name = ""; ExitCode = -1; Validation = "rejected"
            Reason = "unreadable job manifest"; TimedOut = $false; Forced = $false
            Start = (Get-Date).ToString("o"); End = (Get-Date).ToString("o"); DurationSec = 0
        }
        Write-UacResultAtomic -OutputDir $outputDir -Result $rejectResult
        Add-UacRegistryEntry @{ ts = (Get-Date).ToString("o"); event = "rejected"; guid = $jobGuid; name = ""; reason = "unreadable job manifest" }
        Move-Item -Path $jobFile -Destination (Join-Path $outputDir "job.json") -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $InputDir -Recurse -Force -ErrorAction SilentlyContinue
        return
    }

    # Transfer output ownership to the submitter (same owner as the input folder),
    # so the submitter can retrieve files and clean up the folder afterwards.
    $callerSid = "$($job.CallerSid)"
    if ($callerSid -match "^S-\d+-")
    {
        try
        {
            Set-UacFolderOwner -Path $outputDir -OwnerSid $callerSid
        }
        catch
        {
            Write-Warning "Could not set output owner to ${callerSid}: $($_.Exception.Message)"
        }
    }

    $registryCommon = @{
        guid = $jobGuid; name = "$($job.Name)"; callerUser = "$($job.CallerUser)"
        callerSid = $callerSid; callerPid = "$($job.CallerPid)"
    }

    $validation = Get-UacJobValidation -Job $job -InputDir $InputDir
    if (-Not $validation.Valid)
    {
        Write-Warning "Job REJECTED ($jobGuid, $($job.Name)): $($validation.Reason)"
        $rejectResult = [ordered]@{
            JobGuid = $jobGuid; Name = "$($job.Name)"; ExitCode = -1; Validation = "rejected"
            Reason = "$($validation.Reason)"; TimedOut = $false; Forced = $false
            Start = (Get-Date).ToString("o"); End = (Get-Date).ToString("o"); DurationSec = 0
        }
        Write-UacResultAtomic -OutputDir $outputDir -Result $rejectResult
        Add-UacRegistryEntry (@{ ts = (Get-Date).ToString("o"); event = "rejected"; reason = "$($validation.Reason)" } + $registryCommon)
        Move-Item -Path $jobFile -Destination (Join-Path $outputDir "job.json") -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $InputDir -Recurse -Force -ErrorAction SilentlyContinue
        return
    }

    $argumentsJson = ""
    try
    {
        $argumentsJson = "$($job.Arguments | ConvertTo-Json -Depth 4 -Compress)"
    }
    catch
    {
        $argumentsJson = ""
    }
    Add-UacRegistryEntry (@{ ts = (Get-Date).ToString("o"); event = "started"; arguments = $argumentsJson } + $registryCommon)
    Write-Host "Job started: $($job.Name) ($jobGuid) - $($validation.JobPath)"

    $jobOutLog = Join-Path $outputDir "job.log"
    $jobErrLog = Join-Path $outputDir "job.err.log"
    $processArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$($validation.JobPath)`" -InputDir `"$InputDir`" -OutputDir `"$outputDir`" -ArgumentsFile `"$jobFile`""
    $jobStart = Get-Date
    $timeoutSeconds = 3600
    if ("$($job.TimeoutSec)" -match "^\d+$")
    {
        $timeoutSeconds = [int]"$($job.TimeoutSec)"
    }
    if ($timeoutSeconds -le 0)
    {
        $timeoutSeconds = 3600
    }
    $timedOut = $false
    $forced = $false
    $exitCode = -1
    $processExitCode = $null
    $jobExitCode = $null
    $exitCodeSource = "none"
    $signalFile = Join-Path (Join-Path $Base "control") "stop.signal"
    try
    {
        $process = Start-Process powershell -ArgumentList $processArgs -NoNewWindow -PassThru -RedirectStandardOutput $jobOutLog -RedirectStandardError $jobErrLog
        while (-Not $process.HasExited)
        {
            Start-Sleep -Seconds 1
            if (((Get-Date) - $jobStart).TotalSeconds -gt $timeoutSeconds)
            {
                $timedOut = $true
                Write-Warning "Job timeout after $($timeoutSeconds)s - killing process tree of PID $($process.Id)"
                $null = & taskkill /F /T /PID $process.Id 2>&1
                break
            }
            if (Test-Path $signalFile)
            {
                $signalContent = ""
                try
                {
                    $signalContent = Get-Content -Path $signalFile -Raw -ErrorAction SilentlyContinue
                }
                catch
                {
                    $signalContent = ""
                }
                if ("$signalContent".Trim() -eq "force")
                {
                    $forced = $true
                    $script:StopRequested = $true
                    Write-Warning "Force stop requested - killing process tree of PID $($process.Id)"
                    $null = & taskkill /F /T /PID $process.Id 2>&1
                    Remove-Item -Path $signalFile -Force -ErrorAction SilentlyContinue
                    break
                }
            }
        }
        # Parameterloses WaitForExit: flusht die umgeleiteten Streams vollstaendig
        # und liefert den ExitCode zuverlaessig (WaitForExit(int) garantiert beides nicht)
        $null = $process.WaitForExit()
        $processExitCode = $process.ExitCode
    }
    catch
    {
        Write-Warning "Job process handling failed: $($_.Exception.Message)"
        $processExitCode = $null
    }
    $jobEnd = Get-Date

    # Exit-Code-Ermittlung: Prozess-Code bevorzugen; Fallback auf die vom Job selbst
    # deklarierte job.exitcode (direkt vor dessen exit geschrieben), wenn der Prozess-
    # ExitCode nicht lesbar ist (Realfall 19.10.2026: ExitCode-Read warf Exception und
    # machte einen erfolgreich abgeschlossenen Job zu -1)
    $jobExitCodeFile = Join-Path $outputDir "job.exitcode"
    if (Test-Path $jobExitCodeFile)
    {
        $fileContent = ""
        try
        {
            $fileContent = (Get-Content -Path $jobExitCodeFile -Raw -ErrorAction SilentlyContinue).Trim()
        }
        catch
        {
            $fileContent = ""
        }
        if ("$fileContent" -match "^-?\d+$")
        {
            $jobExitCode = [int]"$fileContent"
        }
    }
    if ($null -ne $processExitCode)
    {
        $exitCode = $processExitCode
        $exitCodeSource = "process"
        if ($null -ne $jobExitCode -and $jobExitCode -ne $processExitCode)
        {
            Write-Warning "Exit code mismatch: process=$processExitCode, job.exitcode=$jobExitCode - using process code"
        }
    }
    elseif ($null -ne $jobExitCode)
    {
        $exitCode = $jobExitCode
        $exitCodeSource = "job.exitcode"
        Write-Warning "Process exit code unavailable - using job.exitcode ($jobExitCode)"
    }

    $result = [ordered]@{
        JobGuid = $jobGuid; Name = "$($job.Name)"; ExitCode = $exitCode; Validation = "ok"
        Reason = ""; TimedOut = $timedOut; Forced = $forced
        ExitCodeSource = $exitCodeSource; ProcessExitCode = $processExitCode; JobExitCode = $jobExitCode
        Start = $jobStart.ToString("o"); End = $jobEnd.ToString("o")
        DurationSec = [int]($jobEnd - $jobStart).TotalSeconds
    }
    Write-UacResultAtomic -OutputDir $outputDir -Result $result
    $registryEvent = "completed"
    if ($timedOut) { $registryEvent = "timeout" }
    Add-UacRegistryEntry (@{ ts = (Get-Date).ToString("o"); event = $registryEvent; exitCode = $exitCode; durationSec = $result.DurationSec } + $registryCommon)
    Move-Item -Path $jobFile -Destination (Join-Path $outputDir "job.json") -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $InputDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Job finished: $($job.Name) ($jobGuid) - ExitCode $exitCode, Duration $($result.DurationSec)s, Validation ok"
}

# --- Main ---

Write-Host "UacWorker starting: Base $Base, JobsRoot $JobsRoot, Nonce $Nonce, Invoker $InvokerName ($InvokerSid), Idle $IdleTimeoutMin min"

$controlDir = Join-Path $Base "control"
$inputRoot = Join-Path $Base "input"
$outputRoot = Join-Path $Base "output"
foreach ($dir in @($Base, $controlDir, $inputRoot, $outputRoot))
{
    if (-Not (Test-Path $dir))
    {
        $null = New-Item -Path $dir -ItemType Directory -Force
    }
}
Set-UacAcl -Path $Base -Kind "Base"
Set-UacAcl -Path $controlDir -Kind "Control"
Set-UacAcl -Path $inputRoot -Kind "Input"
Set-UacAcl -Path $outputRoot -Kind "Output"

# Housekeeping: old outputs (7 days) and orphaned input folders without job.json (24 hours)
$cutoffOutput = (Get-Date).AddDays(-7)
$oldOutputs = @(Get-ChildItem -Path $outputRoot -Directory -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoffOutput })
foreach ($oldOutput in $oldOutputs)
{
    Write-Host "Housekeeping: removing old output $($oldOutput.Name)"
    Remove-Item -Path $oldOutput.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
$cutoffInput = (Get-Date).AddHours(-24)
$orphanedInputs = @(Get-ChildItem -Path $inputRoot -Directory -ErrorAction SilentlyContinue | Where-Object { (-Not (Test-Path (Join-Path $_.FullName "job.json"))) -and ($_.LastWriteTime -lt $cutoffInput) })
foreach ($orphanedInput in $orphanedInputs)
{
    Write-Host "Housekeeping: removing orphaned input $($orphanedInput.Name)"
    Remove-Item -Path $orphanedInput.FullName -Recurse -Force -ErrorAction SilentlyContinue
}

$sessionState = @{
    WorkerPid      = $PID
    Nonce          = $Nonce
    JobsRoot       = $JobsRoot
    InvokerSid     = $InvokerSid
    InvokerName    = $InvokerName
    Started        = (Get-Date).ToString("o")
    Heartbeat      = (Get-Date).ToString("o")
    State          = "Running"
    IdleTimeoutMin = $IdleTimeoutMin
}
Write-UacSessionAtomic -Session $sessionState
Add-UacRegistryEntry @{ ts = (Get-Date).ToString("o"); event = "worker_started"; workerPid = $PID; nonce = $Nonce; jobsRoot = $JobsRoot; invokerName = $InvokerName; invokerSid = $InvokerSid }
Write-Host "UacWorker running: PID $PID"

$script:StopRequested = $false
$lastActivity = Get-Date
$lastBeat = Get-Date
$signalFile = Join-Path $controlDir "stop.signal"

while ($true)
{
    Start-Sleep -Seconds 1
    $now = Get-Date

    if (($now - $lastBeat).TotalSeconds -ge 10)
    {
        # Der Heartbeat darf den Loop nie toeten (transiente FS-/Sharing-Fehler): Versuch
        # verwerfen und naechsten Tick erneut probieren ($lastBeat bleibt alt).
        try
        {
            $sessionState["Heartbeat"] = $now.ToString("o")
            Write-UacSessionAtomic -Session $sessionState
            $lastBeat = $now
        }
        catch
        {
            Write-Warning "Heartbeat write failed (retrying next tick): $($_.Exception.Message)"
        }
    }

    if (Test-Path $signalFile)
    {
        $signalContent = ""
        try
        {
            $signalContent = Get-Content -Path $signalFile -Raw -ErrorAction SilentlyContinue
        }
        catch
        {
            $signalContent = ""
        }
        Remove-Item -Path $signalFile -Force -ErrorAction SilentlyContinue
        $script:StopRequested = $true
        if ("$signalContent".Trim() -eq "force")
        {
            Write-Host "Force stop requested (no job running) - exiting"
            break
        }
        Write-Host "Graceful stop requested - exiting after current work"
    }

    $jobDir = $null
    if (-Not $script:StopRequested)
    {
        $candidates = @()
        try
        {
            $candidates = @(Get-ChildItem -Path $inputRoot -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName "job.json") } | Sort-Object { (Get-Item (Join-Path $_.FullName "job.json")).LastWriteTime })
        }
        catch
        {
            Write-Warning "Job scan failed (retrying next tick): $($_.Exception.Message)"
        }
        if ($candidates.Count -gt 0)
        {
            $jobDir = $candidates[0]
        }
    }

    if ($null -ne $jobDir)
    {
        $lastActivity = Get-Date
        try
        {
            Invoke-UacJob -InputDir $jobDir.FullName
        }
        catch
        {
            Write-Warning "Unhandled job error: $($_.Exception.Message)"
        }
        if ($script:StopRequested)
        {
            break
        }
    }
    elseif ($script:StopRequested)
    {
        break
    }
    elseif (($now - $lastActivity).TotalMinutes -ge $IdleTimeoutMin)
    {
        Write-Host "Idle timeout reached ($IdleTimeoutMin min) - exiting"
        break
    }
}

$sessionState["State"] = "Stopped"
$sessionState["Heartbeat"] = (Get-Date).ToString("o")
Write-UacSessionAtomic -Session $sessionState
Add-UacRegistryEntry @{ ts = (Get-Date).ToString("o"); event = "worker_stopped"; workerPid = $PID }
Write-Host "UacWorker stopped"
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCXEzSffHkfaM+f
# JM1l1J2M600De1UaE/iHpiq2PZmaWqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBlHkmR8
# OeuLKQhEwroqmHKWZzpJysqa/Ct/i4HLG4GEMA0GCSqGSIb3DQEBAQUABIICAF2x
# LERka8ZQzTXdW4LMErpvH/PW+NV5Pb0a1qrc/y0D1P+XT68G9pXvbzoUoXwYo4SM
# tVkWBKcghLAEifdtIpcXncnjD6FQNrYCayNTY3TL2X+pUpCyPqn/7Mu9sV+a+Ev9
# V9qYA01pUzD+C+YbOpJhg1tf5g/0nT2N2NMsC+pwGDdFCI3NLQJzvCPVtjbP21Lo
# sr1ELUtdH0ZMIitwyk8YU7ZJAF5zwR1eezOPfFMSsyjDa7gW+QKzdN+R+rFd5g07
# 4xBFWbk8uDEOy0n8Na4N1Smc0uQYXR9zr52gyhzdViQM46/MI0cTnfzKrw78pT6m
# fTbAmtTdyNFmwmJU+D9IXqlA5ykzYOlVChXr7yRyzm9F7EbiWDFjsqzS50zd7D9V
# 5+hjDcstVmKRFRBvvsR13l1xPuKL1da8Yjkuf/+bqUi4yEKrF6AkybG49djeOsjS
# fsDB3iRfMqurEGPNIksm9+uXDHd1dSHfW8zQj86duLA3Tqe+ST1S1gpakLAXtn1x
# o5mj7o8yYYuGLeYL0UtA1pd8ytPYhZ2cEIsv8WSzkFMwbLjcjZlGBZhMaY/X69M+
# hTAuFg4acXYh+Vj71pIJIoMtOYFxyN8kAKTC0m6yGrBw7NfwinXX55ruFlLLb1Ew
# QtJ9aQdH/NOFHtLJwNzffxkYJLN31p3qjJmo/knAoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCB84ODAllRujQogtwFomUkQXqo4lNsEM3xV9z3fMkSJ4gIUBV0q
# 9RAf966IEhy29A5alOxHP+8YDzIwMjYxMDIwMTMzNTIxWjADAgEBoF2kWzBZMQsw
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
# BDEyBDBPFT0+c0chwJUSEfWm6HANrSNXcKzCXes6g/Vo/bYXMa+Elg8oTWsALp19
# R4jNeFowgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAv6mQhWAMDM19HTQdu0FaW0bw1HfGgoG1A049sbSG6Oj+
# c30xWj+qmXTzKJearl6Sl1pszzd5vZD1/HSzFaVULL92lECVqvGqLKRj72kdau86
# fejtEWFuS8mb6dzST15cByIaqkLooLtYC8KsqgIp44H3ipnsPukJEwRB82gQfEGq
# 1U3yX0tSXTFXy7WsK+yuQIIJauEU5TPhnxHUUD7f/idSprpN5bJsQK0KxXp5HrBq
# wJOkaCcvOUHClh9Lx3YpAvNj9XoShEAkmOsQTV13WFThzwgsoPitPYvIc8zVxHOz
# /3HshjI25ElSZDRoIL9S6gdvKHczz3jbuMAVE9mkeI5Wp+z0/2NzwEikHYq0MVdX
# zlGemiuE2cJlsapasIbiJqYu0ten/kh024ZU3IcQb2DUXM8k+s5w+uwIv8ha+9d2
# 7/yVfZ1HAfN3q8eUmp1YQRTc5s+LQgPx6GtMaGUiIGGpyG67oaJrI9wKh2On6s+k
# LtEK59gXeSgZwF0Ho0AD
# SIG # End signature block
