#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This file is part of the Alya Base Configuration.
    The Alya Base Configuration is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
	Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
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
    01.04.2020 Konrad Brunner       Initial Version

#>

param (
    [String]$StartFrom = $null
)

if (-Not $StartFrom -or $StartFrom -ne "ScheduledJob")
{
    $ProgramsPath = "$($env:systemRoot)\System32\GroupPolicy\Machine\Scripts\Startup"
    $ActPath = $PSCommandPath
    $ScriptName = "ConfigureFirewallForTeamsInProfiles.ps1"
    $ScriptPath = Join-Path -Path $ProgramsPath -ChildPath $ScriptName
    if (-Not (Test-Path $ProgramsPath -PathType Container))
    {
        New-Item -Path $ProgramsPath -Force -ItemType Directory
    }
    Copy-Item -Path $ActPath -Destination $ScriptPath -Force -Confirm:$false

    $path = "$($env:systemRoot)\System32\GroupPolicy\Machine\Scripts\Startup"
    if (-not (Test-Path $path -PathType Container)) {
        New-Item -path $path -itemType Directory -Force
    }
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\0" |
      ForEach-Object { 
        if (-not (Test-Path $_)) {
            New-Item -path $_ -force
        }
      }
    #TODO support already existing script!!
    $prop = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0" -Name Script1 -ErrorAction SilentlyContinue
    if ($prop)
    {
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0" |
          ForEach-Object {
            New-ItemProperty -path "$_" -name DisplayName -propertyType String -value "Local Group Policy" 
            New-ItemProperty -path "$_" -name FileSysPath -propertyType String -value "$($env:systemRoot)\System32\GroupPolicy\Machine" 
            New-ItemProperty -path "$_" -name GPO-ID -propertyType String -value "LocalGPO"
            New-ItemProperty -path "$_" -name GPOName -propertyType String -value "Local Group Policy"
            New-ItemProperty -path "$_" -name PSScriptOrder -propertyType DWord -value 2 
            New-ItemProperty -path "$_" -name SOM-ID -propertyType String -value "Local"
          }
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\0" |
          ForEach-Object {
            New-ItemProperty -path "$_" -name Script -propertyType String -value $ScriptPath
            New-ItemProperty -path "$_" -name Parameters -propertyType String -value "-StartFrom ScheduledJob"
            New-ItemProperty -path "$_" -name IsPowershell -propertyType DWord -value 1
            New-ItemProperty -path "$_" -name ExecTime -propertyType QWord -value 0
          }
    }
    else
    {
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0" |
          ForEach-Object {
            Set-ItemProperty -path "$_" -name DisplayName -value "Local Group Policy" 
            Set-ItemProperty -path "$_" -name FileSysPath -value "$($env:systemRoot)\System32\GroupPolicy\Machine" 
            Set-ItemProperty -path "$_" -name GPO-ID -value "LocalGPO"
            Set-ItemProperty -path "$_" -name GPOName -value "Local Group Policy"
            Set-ItemProperty -path "$_" -name PSScriptOrder -value 2 
            Set-ItemProperty -path "$_" -name SOM-ID -value "Local"
          }
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\0" |
          ForEach-Object {
            Set-ItemProperty -path "$_" -name Script -value $ScriptName
            Set-ItemProperty -path "$_" -name Parameters -value "-StartFrom ScheduledJob"
            Set-ItemProperty -path "$_" -name IsPowershell -value 1
            Set-ItemProperty -path "$_" -name ExecTime -value 0
          }
    }
    $path = "$($env:systemRoot)\System32\GroupPolicy\Machine\Scripts\psscripts.ini"
    $iniContent = @"

[Startup]
0CmdLine=$($ScriptName)
0Parameters=-StartFrom ScheduledJob
"@
    $iniContent | Set-Content -Path $path -Force -Encoding Unicode
    (Get-ChildItem $path -Force).Attributes += "Hidden"
}

# Run the script
$protcols = "UDP", "TCP"
$users = Get-ChildItem (Join-Path -Path $env:SystemDrive -ChildPath 'Users') -Exclude 'Public'
if ($null -ne $users)
{
    foreach ($user in $users)
    {
        $progPath = Join-Path -Path $user.FullName -ChildPath "AppData\Local\Microsoft\Teams\Current\Teams.exe"
        if (Test-Path $progPath)
        {
            foreach ($prot in $protcols)
            {
                $ruleName = "Teams.exe-$($prot)-$($user.Name)"
                $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                if (-not $rule)
                {
                    $tmp = New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Profile Domain -Program $progPath -Action Allow -Protocol $prot
                    Clear-Variable ruleName
                }
            }
        }
        Clear-Variable progPath
    }
}
