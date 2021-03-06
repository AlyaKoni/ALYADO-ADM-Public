#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2019, 2020

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
    24.10.2020 Konrad Brunner       Initial version
#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\05_CreateAlyaStick-$($AlyaTimeString).log" | Out-Null

#Main
. $PSScriptRoot\04_PrepareModulesAndPackages

Write-Host "Select stick to be used" -ForegroundColor $CommandInfo
$disk = $null
$usbDisk = Get-Disk | Where-Object BusType -eq USB
switch (($usbDisk | Measure-Object | Select-Object Count).Count)
{
    1 {
        $disk = $usbDisk[0]
    }
    {$_ -gt 1} {
        $disk = Get-Disk | Where-Object BusType -eq USB | Out-GridView -Title 'Select USB Drive to use' -OutputMode Single
    }
}
if ($disk)
{
    $vol = $disk | Get-Partition | Get-Volume
    $alyaDir = "$($vol.DriveLetter):\Alya"
    if (-Not (Test-Path $alyaDir))
    {
        New-Item -Path $alyaDir -ItemType Directory -Force | Out-Null
    }
    if (-Not (Test-Path "$alyaDir\tools"))
    {
        New-Item -Path "$alyaDir\tools" -ItemType Directory -Force | Out-Null
    }

    cmd /c robocopy "$($AlyaRoot)" "$($alyaDir)" /MIR /XD "%SourceDir%\scripts\solutions" /XD .git /XD PublishProfiles /XD .vs /XD .vscode /XD _temp /XD _logs

    $to = "$alyaDir\tools\WindowsPowerShell"

    $prop = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{F42EE2D3-909F-4907-8871-4C22FC0BF756}" -ErrorAction SilentlyContinue
    if ($prop -and $prop.'{F42EE2D3-909F-4907-8871-4C22FC0BF756}')
    {
        $from = "$($prop.'{F42EE2D3-909F-4907-8871-4C22FC0BF756}')\WindowsPowerShell"
    }
    else
    {
        $from = "$($env:USERPROFILE)\Documents\WindowsPowerShell"
    }
    cmd /c robocopy "$($from)" "$($to)" /MIR
}
else
{
    Write-Warning "No stick selected or detected!"
}

#Stopping Transscript
Stop-Transcript