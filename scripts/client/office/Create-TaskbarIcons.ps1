#Requires -Version 3.0

<#
    Copyright (c) Alya Consulting, 2019-2021

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
    07.11.2019 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

throw "Pinning is not supported any more by Microsoft. You have to use the official XML method!"

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\client\office\CreateTaskbarIcons-$($AlyaTimeString).log" | Out-Null

#throw "We do not yet have a solution! Sorry."
$FromPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\"
$ToPath = "$env:Appdata\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\"

#Preparing verb
$KeyPath1  = "HKCU:\SOFTWARE\Classes"
$KeyPath2  = "*"
$KeyPath3  = "shell"
$KeyPath4  = "{:}"
$ValueName = "ExplorerCommandHandler"
$ValueData = (Get-ItemProperty `
    ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.taskbarpin")
).ExplorerCommandHandler
$Key2 = (Get-Item $KeyPath1).OpenSubKey($KeyPath2, $true)
$Key3 = $Key2.OpenSubKey($KeyPath3, $true)
if ($Key3) { $Key3WasPresent = $true }
else { $Key3 = $Key2.CreateSubKey($KeyPath3, $true) }
$Key4 = $Key3.CreateSubKey($KeyPath4, $true)
$Key4.SetValue($ValueName, $ValueData)

#Preparing Shell
$Shell = New-Object -ComObject "Shell.Application"
$Folder = $Shell.Namespace($FromPath)

#Pinning
foreach($OfficeTool in $AlyaOfficeToolsOnTaskbar)
{
    $source = Get-Item -Path ($FromPath + $OfficeTool + ".lnk") -ErrorAction SilentlyContinue
    $destin = $ToPath + $OfficeTool + ".lnk"
    if (-Not $source.Exists)
    {
        Write-Error "$($OfficeTool) not found in $($FromPath)" -ErrorAction Continue
    }
    Copy-Item -Path $source -Destination $destin -Force

    $ItemLnk = $Folder.ParseName($OfficeTool + ".lnk")
    $ItemLnkVerb = $ItemLnk.Verbs() | where { $_.Name.Replace("&", "") -eq $KeyPath4 }
    $ItemLnkVerb.DoIt()
    $ItemLnk.InvokeVerb("{:}")
}

#Removing own verb
$Key3.DeleteSubKey($KeyPath4)
if ((-Not $Key3WasPresent) -and $Key3.SubKeyCount -eq 0 -and $Key3.ValueCount -eq 0) {
    $Key2.DeleteSubKey($KeyPath3)
}

#Restarting explorer
Stop-Process -Name "explorer" -Force

#Stopping Transscript
Stop-Transcript | Out-Null
