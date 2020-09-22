#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This unpublished material is proprietary to Alya Consulting.
    All rights reserved. The methods and techniques described
    herein are considered trade secrets and/or confidential. 
    Reproduction or distribution, in whole or in part, is 
    forbidden except by express written permission of Alya Consulting.

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    23.04.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\test\13_updateLocalFiles_hpol001-$($AlyaTimeString).log" | Out-Null

# Constants
$ErrorActionPreference = "Stop"
$WvdHostName = "$($AlyaNamingPrefixTest)vd51-"
$NumberOfInstances = 3
$RootDir = "$AlyaRoot\scripts\wvd\admin\test"

# =============================================================
# OS stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 13_updateLocalFiles_hpol001 | OS" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
Write-Host "Updating files" -ForegroundColor $CommandInfo
for ($hi=0; $hi -lt $NumberOfInstances; $hi++)
{
    #$hi=0
    $actHostName = "$($WvdHostName)$($hi)"
    Write-Host "  $($actHostName)" -ForegroundColor $CommandInfo
    Write-Host "    Copying files"
    if (-Not (Test-Path "\\$($actHostName)\C$\$($AlyaCompanyName)"))
    {
        $tmp = New-Item -Path "\\$($actHostName)\C$" -Name $AlyaCompanyName -ItemType Directory
    }
    robocopy /mir "$($RootDir)\..\..\WvdIcons" "\\$($actHostName)\C$\$($AlyaCompanyName)\WvdIcons"
    robocopy /mir "$($RootDir)\..\..\WvdStartApps\$($AlyaCompanyName)" "\\$($actHostName)\C$\ProgramData\Microsoft\Windows\Start Menu\Programs\$($AlyaCompanyName)"
    #TODO $tmp = Copy-Item "$($RootDir)\..\..\..\..\o365\defenderatp\WindowsDefenderATPLocalOnboardingScript.cmd" "\\$($actHostName)\C$\$($AlyaCompanyName)\WindowsDefenderATPLocalOnboardingScript.cmd" -Force
    $tmp = Copy-Item "$($RootDir)\..\..\WvdTheme\$($AlyaCompanyName)Test.theme" "\\$($actHostName)\C$\Windows\resources\Themes\$($AlyaCompanyName).theme" -Force
}

#Stopping Transscript
Stop-Transcript