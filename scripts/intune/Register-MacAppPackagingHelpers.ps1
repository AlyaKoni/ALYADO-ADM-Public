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
    Foundation, entweder Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veröffentlichten Version, weiter verteilen und/oder modifizieren.
    Die Alya Basis Konfiguration wird in der Hoffnung, dass sie nützlich sein wird,
    aber OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
    https://www.gnu.org/licenses/gpl-3.0.txt


    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    11.11.2026 Konrad Brunner       Initial version: macOS-Disk-Image-Kompatibilitätsschicht; routet attach/detach/convert per Capability-Check auf 'diskutil image' (macOS 26+) oder 'hdiutil' (ältere Systeme), da Apple hdiutil deprecated hat

#>

<#
.SYNOPSIS
Shared helper functions for macOS disk image operations (hdiutil / diskutil image compatibility layer).

.DESCRIPTION
Apple has deprecated hdiutil: macOS 26 prints deprecation warnings for the attach, convert and detach verbs, and the macOS 27 man page marks the whole tool as deprecated. The replacement is the diskutil image subcommand family, which is only available on macOS 26 and newer. This library is dot-sourced by the MAC Intune packaging scripts (Download.ps1, RegenerateChoicesFile.ps1) and routes every disk image operation through a capability check: on systems providing diskutil image, the new subcommands are used; on older systems, the legacy hdiutil verbs remain in charge. The native tool output is passed through unchanged and the tool exit code is available in $LASTEXITCODE after each call.

.INPUTS
None. These functions do not accept pipeline input.

.OUTPUTS
Test-DiskUtilImageSupport returns a boolean. Mount-DmgImage, Dismount-DmgImage and Convert-DmgImage emit the native tool output.

.EXAMPLE
PS> . .\scripts\intune\Register-MacAppPackagingHelpers.ps1
PS> Convert-DmgImage -Source $oName -Format "UDRW" -Destination $nName
PS> Mount-DmgImage -Path $nName
PS> Dismount-DmgImage -Path $volume -Force $true

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

function Test-DiskUtilImageSupport {
    <#
    .SYNOPSIS
    Checks whether the running macOS provides the diskutil image subcommands (macOS 26+).

    .DESCRIPTION
    Uses a capability check instead of OS version parsing: 'diskutil image --help' exits non-zero on systems where the image verb does not exist. The result is cached for the session and the routing decision is logged once via Write-Host. On non-macOS systems (no diskutil binary) the function returns $false without executing anything.

    .OUTPUTS
    System.Boolean
    #>
    [CmdletBinding()]
    param()
    if ($null -eq $script:DuiImageSupported) {
        $script:DuiImageSupported = $false
        if (Get-Command -Name "diskutil" -CommandType Application -ErrorAction SilentlyContinue) {
            & /bin/sh -c "diskutil image --help >/dev/null 2>&1"
            $script:DuiImageSupported = ($LASTEXITCODE -eq 0)
        }
        if ($script:DuiImageSupported) {
            Write-Host "Register-MacAppPackagingHelpers: using 'diskutil image' (hdiutil is deprecated on this macOS)"
        }
        else {
            Write-Host "Register-MacAppPackagingHelpers: 'diskutil image' not available, falling back to 'hdiutil'"
        }
    }
    $script:DuiImageSupported
}

function Mount-DmgImage {
    <#
    .SYNOPSIS
    Attaches a disk image: 'diskutil image attach' on macOS 26+, 'hdiutil attach' on older systems.

    .DESCRIPTION
    Replaces 'hdiutil attach [-nobrowse] [-readonly] <image>'. The flags are mapped one-to-one to the diskutil options --nobrowse and --readOnly. Output and exit code of the native tool are passed through.

    .OUTPUTS
    Native tool output. Exit code available in $LASTEXITCODE.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [bool]$NoBrowse = $false,

        [bool]$ReadOnly = $false
    )
    if (Test-DiskUtilImageSupport) {
        $nativeArgs = @("image", "attach")
        if ($NoBrowse) {
            $nativeArgs += "--nobrowse"
        }
        if ($ReadOnly) {
            $nativeArgs += "--readOnly"
        }
        $nativeArgs += $Path
        & diskutil @nativeArgs
    }
    else {
        $nativeArgs = @("attach")
        if ($NoBrowse) {
            $nativeArgs += "-nobrowse"
        }
        if ($ReadOnly) {
            $nativeArgs += "-readonly"
        }
        $nativeArgs += $Path
        & hdiutil @nativeArgs
    }
}

function Dismount-DmgImage {
    <#
    .SYNOPSIS
    Detaches a disk image: 'diskutil eject [force]' on macOS 26+, 'hdiutil detach [-force]' on older systems.

    .DESCRIPTION
    Replaces 'hdiutil detach <volume|device> [-force]'. Apple maps the detach verb to 'diskutil eject'; the force variant is 'diskutil eject force'. Output and exit code of the native tool are passed through.

    .OUTPUTS
    Native tool output. Exit code available in $LASTEXITCODE.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [bool]$Force = $false
    )
    if (Test-DiskUtilImageSupport) {
        $nativeArgs = @("eject")
        if ($Force) {
            $nativeArgs += "force"
        }
        $nativeArgs += $Path
        & diskutil @nativeArgs
    }
    else {
        $nativeArgs = @("detach", $Path)
        if ($Force) {
            $nativeArgs += "-force"
        }
        & hdiutil @nativeArgs
    }
}

function Convert-DmgImage {
    <#
    .SYNOPSIS
    Converts a disk image: 'diskutil image create from --format' on macOS 26+, 'hdiutil convert' on older systems.

    .DESCRIPTION
    Replaces 'hdiutil convert <source> -format <format> -o <destination>'. The -Format parameter accepts the classic hdiutil format tokens (UDRW, UDRO, UDZO, ULFO); for the diskutil path, UDRW is translated to RAW (diskutil names the read-write format RAW, previously known as UDRW), all other tokens are identical. Output and exit code of the native tool are passed through.

    .OUTPUTS
    Native tool output. Exit code available in $LASTEXITCODE.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Format,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )
    if (Test-DiskUtilImageSupport) {
        $diskUtilFormat = $Format
        if ($diskUtilFormat -eq "UDRW") {
            $diskUtilFormat = "RAW"
        }
        & diskutil image create from --format $diskUtilFormat $Source $Destination
    }
    else {
        & hdiutil convert $Source -format $Format -o $Destination
    }
}
