#Requires -Version 2.0

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
    01.04.2020 Konrad Brunner       Initial Version
    21.10.2020 Konrad Brunner       64bit and better logging

#>

[CmdletBinding()]
param (
    [String]$StartFrom = $null
)

$exitCode = 0
$AlyaTimeString = (Get-Date).ToString("yyyyMMddHHmmssfff")
$AlyaScriptName = Split-Path $PSCommandPath -Leaf
$AlyaScriptDir = Split-Path $PSCommandPath -Parent

if (![System.Environment]::Is64BitProcess)
{
    Write-Host "Launching 64bit PowerShell"
    $arguments = ""
    foreach($key in $MyInvocation.BoundParameters.keys)
    {
        switch($MyInvocation.BoundParameters[$key].GetType().Name)
        {
            "SwitchParameter" {if($MyInvocation.BoundParameters[$k].IsPresent) { $arguments += "-$key " } }
            "String"          { $arguments += "-$key `"$($MyInvocation.BoundParameters[$key])`" " }
            "Int32"           { $arguments += "-$key $($MyInvocation.BoundParameters[$key]) " }
            "Boolean"         { $arguments += "-$key `$$($MyInvocation.BoundParameters[$key]) " }
        }
    }
    $sysNativePowerShell = "$($PSHOME.ToLower().Replace("syswow64", "sysnative"))\powershell.exe"
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $sysNativePowerShell
    $pinfo.Arguments = "-ex bypass -file `"$PSCommandPath`" $arguments"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.CreateNoWindow = $true
    $pinfo.UseShellExecute = $false
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $stdout = $p.StandardOutput.ReadToEnd()
    if (-Not [string]::IsNullOrEmpty($stdout)) { Write-Host $stdout }
    $stderr = $p.StandardError.ReadToEnd()
    if (-Not [string]::IsNullOrEmpty($stderr)) { Write-Error $stderr }
    $exitCode = $p.ExitCode
}
else
{
    Start-Transcript -Path "C:\ProgramData\AlyaConsulting\Logs\$($AlyaScriptName)-ConfigureFirewall-$($AlyaTimeString).log" -Force

    try
    {
        $ErrorActionPreference = "Stop"

        if (-Not $StartFrom -or $StartFrom -ne "ScheduledJob")
        {
            Write-Host "No start parameter provided, implementing script autostart"
            $StartupPath = "$($env:systemRoot)\System32\GroupPolicy\Machine\Scripts\Startup"
            $ActPath = $PSCommandPath
            $ScriptName = "ConfigureFirewallForTeamsInProfiles.ps1"
            $ScriptPath = Join-Path $StartupPath $ScriptName
            if (-Not (Test-Path $StartupPath -PathType Container))
            {
                New-Item -Path $StartupPath -Force -ItemType Directory
            }
            Write-Host "Copy script"
            Write-Host "  from $ActPath"
            Write-Host "  to $ScriptPath"
            Copy-Item -Path $ActPath -Destination $ScriptPath -Force -Confirm:$false

            Write-Host "Preparing registry paths"
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\0" |
                ForEach-Object { 
                    if (-not (Test-Path $_)) {
                        New-Item -path $_ -force
                    }
                }

            Write-Host "Preparing registry values"
            #TODO support already existing other script!!
            $prop = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0" -Name Script -ErrorAction SilentlyContinue
            if (-Not $prop)
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
                        New-ItemProperty -path "$_" -name Script -propertyType String -value $ScriptName
                        New-ItemProperty -path "$_" -name Parameters -propertyType String -value "-StartFrom ScheduledJob"
                        New-ItemProperty -path "$_" -name IsPowershell -propertyType DWord -value 1
                        New-ItemProperty -path "$_" -name ExecTime -propertyType QWord -value ([Int64]0)
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
                        Set-ItemProperty -path "$_" -name ExecTime -value ([Int64]0)
                    }
            }
            $StartupIniPath = "$($env:systemRoot)\System32\GroupPolicy\Machine\Scripts\psscripts.ini"
            $iniContent = @"

[Startup]
0CmdLine=$($ScriptName)
0Parameters=-StartFrom ScheduledJob
"@
            $iniContent | Set-Content -Path $StartupIniPath -Force -Encoding Unicode
            (Get-Item -Path $StartupIniPath -Force).Attributes += "Hidden"
        }

        # Run the script
        Write-Host "Checking firewall rules"
        $protcols = "UDP", "TCP"
        $users = Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Exclude 'Public'
        if ($users)
        {
            foreach ($user in $users)
            {
                Write-Host "User $($user.Name)"
                $progPath = Join-Path $user.FullName "AppData\Local\Microsoft\Teams\Current\Teams.exe"
                $err = $false
                $fnd = $false
                try {
                    $fnd = (Test-Path $progPath)
                } catch { $err = $true }
                if ($fnd -or $err)
                {
                    if ($fnd) { Write-Host "Found teams in $($teamsExe.FullName)" }
                    if ($err) { Write-Host "Guessed teams in $($teamsExe.FullName)" }
                    foreach ($prot in $protcols)
                    {
                        $ruleName = "Teams.exe-Inbound-$($prot)-$($user.Name)"
                        $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                        if (-not $rule)
                        {
                            $tmp = New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Profile Any -Program $progPath -Action Allow -Protocol $prot
                        }
                    }
                }
                else
                {
                    Write-Host "No teams installation for this user"
                }
            }
        }

    }
    catch
    {   
        try { Write-Error ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
        Write-Error ($_.Exception) -ErrorAction Continue
        $exitCode = -1
    }

    Stop-Transcript
}

exit $exitCode
