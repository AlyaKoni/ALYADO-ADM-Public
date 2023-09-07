#Requires -Version 2.0
#Requires -RunAsAdministrator

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
    10.08.2023 Konrad Brunner       Initial Version

#>
[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\data\security\hardeningKitty\Install-HardeningKitty-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# =============================================================
# Local stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "HardeningKitty | Install-HardeningKitty | Local" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Function InstallHardeningKitty() {
    $Version = ((Invoke-WebRequest "https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest" -UseBasicParsing) | ConvertFrom-Json).Name
    $HardeningKittyLatestVersionDownloadLink = ((Invoke-WebRequest "https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest" -UseBasicParsing) | ConvertFrom-Json).zipball_url
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest $HardeningKittyLatestVersionDownloadLink -Out HardeningKitty$Version.zip
    if (-Not (Test-Path ".\HardeningKitty$Version"))
    {
        New-Item -Path ".\HardeningKitty$Version" -ItemType Directory
    }
    $cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
    if ($cmdTst)
    {
        Expand-Archive -Path ".\HardeningKitty$Version.zip" -DestinationPath ".\HardeningKitty$Version" -Force
    }
    else
    {
        Expand-Archive -Path ".\HardeningKitty$Version.zip" -OutputPath ".\HardeningKitty$Version" -Force
    }
    $Folders = Get-ChildItem ".\HardeningKitty$Version" | Select-Object Name -ExpandProperty Name
    foreach ($Folder in $Folders)
    {
        Move-Item ".\HardeningKitty$Version\$Folder\*" ".\HardeningKitty$Version\"
        Remove-Item ".\HardeningKitty$Version\$Folder\" -Force
    }
    New-Item -Path "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version" -ItemType Directory -Force
    Push-Location ".\HardeningKitty$Version"
    Copy-Item -Path .\HardeningKitty.psd1,.\HardeningKitty.psm1,.\lists\ -Destination "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\" -Recurse -Force
    Pop-Location
    Remove-Item ".\HardeningKitty$Version.zip" -Force
    Remove-Item ".\HardeningKitty$Version" -Recurse -Force
    Import-Module "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\HardeningKitty.psm1"
}

Set-Location $PSScriptRoot
InstallHardeningKitty

#Stopping Transscript
Stop-Transcript
