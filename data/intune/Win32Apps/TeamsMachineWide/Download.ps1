#Requires -Version 2

<#
    Copyright (c) Alya Consulting, 2019-2024

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


#>

. "$PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1"

$pageUrl = "https://teams.microsoft.com/downloads/desktopurl?env=production&plat=windows&arch=x64&managedInstaller=true&download=true"
$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $null = New-Item -Path $contentRoot -ItemType Directory -Force
}
$resp = Invoke-WebRequestIndep -UseBasicParsing -Method Get -UserAgent "Wget" -Uri $pageUrl -Outfile "$contentRoot\Teams_windows_x64.msi"
if (-Not (Test-Path "$contentRoot\Teams_windows_x64.msi"))
{
    throw "Not able to download Teams_windows_x64.msi"
}

$pageUrl = "https://raw.githubusercontent.com/microsoft/TeamsMsiOverride/main/src/CheckMsiOverride.ps1"
$resp = Invoke-WebRequestIndep -UseBasicParsing -Method Get -UserAgent "Wget" -Uri $pageUrl -Outfile "$contentRoot\CheckMsiOverride.ps1"
if (-Not (Test-Path "$contentRoot\CheckMsiOverride.ps1"))
{
    throw "Not able to download CheckMsiOverride.ps1"
}
$content = Get-Content -Path "$contentRoot\CheckMsiOverride.ps1" -Encoding UTF8 -Raw
$content = $content.Replace("`$env:TEMP\msiOverrideCheck_", "C:\ProgramData\AlyaConsulting\Logs\TeamsMachineWide-Install-")
$content | Set-Content -Path "$contentRoot\CheckMsiOverride.ps1" -Encoding UTF8 -Force
