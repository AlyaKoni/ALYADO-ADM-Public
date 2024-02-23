#Requires -Version 2.0

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


    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    24.10.2020 Konrad Brunner       Initial version
    05.10.2021 Konrad Brunner       Incorporated AlyaModulePath
    20.04.2023 Konrad Brunner       New locations on stick to minimize space

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\05_CreateAlyaStick-$($AlyaTimeString).log" | Out-Null

#Main
#pwsh.exe -NoLogo -File "$AlyaRoot\04_PrepareModulesAndPackages.ps1"

#Stick selection
$disk = $null
$usbDisk = Get-Disk | Where-Object { $_.BusType -eq "USB" }
switch (($usbDisk | Measure-Object | Select-Object Count).Count)
{
    1 {
        $disk = $usbDisk[0]
    }
    {$_ -gt 1} {
        Write-Host "Select stick to be used" -ForegroundColor $CommandInfo
        $disk = $usbDisk | Out-GridView -Title 'Select USB Drive to be used' -OutputMode Single
    }
}
if ($disk)
{
    #Volume selection
    $vols = $disk | Get-Partition | Get-Volume | Where-Object { -Not [string]::IsNullOrEmpty($_.DriveLetter) }
    if (($vols | Measure-Object | Select-Object Count).Count -ne 1)
    {
        Write-Host "Select volume to be used" -ForegroundColor $CommandInfo
        $vol = $vols | Out-GridView -Title 'Select volume to be used' -OutputMode Single
    }
    else
    {
        $vol = $vols[0]
    }
    $alyaDir = "$($vol.DriveLetter):\Alya$AlyaCompanyNameShortM365"
    if (-Not (Test-Path $alyaDir))
    {
        New-Item -Path $alyaDir -ItemType Directory -Force | Out-Null
    }

    #Copy alya dir
    cmd /c robocopy "$($AlyaRoot)" "$($alyaDir)" /MIR /XD "$($AlyaRoot)\solutions" /XD .git /XD .github /XD PublishProfiles /XD .vs /XD .vscode /XD _temp /XD _logs /XD _local

    #Copy modules
    if (-Not (Test-Path "$($vol.DriveLetter):\Tools\WindowsPowerShell"))
    {
        New-Item -Path "$($vol.DriveLetter):\Tools\WindowsPowerShell" -ItemType Directory -Force | Out-Null
    }
    $to = "$($vol.DriveLetter):\Tools\WindowsPowerShell"

    if ($AlyaModulePath -eq $AlyaDefaultModulePath)
    {
        $prop = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{F42EE2D3-909F-4907-8871-4C22FC0BF756}" -ErrorAction SilentlyContinue
        if ($prop -and $prop.'{F42EE2D3-909F-4907-8871-4C22FC0BF756}')
        {
            $from = "$($prop.'{F42EE2D3-909F-4907-8871-4C22FC0BF756}')\WindowsPowerShell"
        }
        else
        {
            $from = Join-Path ([Environment]::GetFolderPath("MyDocuments"))  "WindowsPowerShell"
        }
    }
    else
    {
        $from = $AlyaModulePath.Replace("\Modules\", "").Replace("\Modules", "")
    }
    cmd /c robocopy "$($from)" "$($to)" /MIR
    $scriptPathFrom = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "WindowsPowerShell\Scripts"
    $scriptPathTo = "$($vol.DriveLetter):\Tools\WindowsPowerShell\Scripts"
    cmd /c xcopy /d /e /v /i /h /r /k /y "$($scriptPathFrom)" "$($scriptPathTo)"

    #Configure AlyaModulePath
    $localDir = "$($vol.DriveLetter):\Alya$AlyaCompanyNameShortM365\_local"
    if (-Not (Test-Path $localDir))
    {
        New-Item -Path $localDir -ItemType Directory -Force | Out-Null
    }
    @"
Push-Location `"`$AlyaRoot\..\Tools\WindowsPowerShell\Modules`"
`$AlyaModulePath = `$pwd
Pop-Location 
Push-Location `"`$AlyaRoot\..\Tools\WindowsPowerShell\Scripts`"
`$AlyaScriptPath = `$pwd
Pop-Location 
"@ | Set-Content -Path "$($vol.DriveLetter):\Alya$AlyaCompanyNameShortM365\_local\ConfigureEnv.ps1" -Encoding UTF8
}
else
{
    Write-Warning "No stick selected or detected!"
}

#Stopping Transscript
Stop-Transcript
