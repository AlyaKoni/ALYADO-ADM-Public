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
    24.08.2023 Konrad Brunner       Initial Version

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
    Start-Transcript -Path "C:\ProgramData\AlyaConsulting\Logs\$($AlyaScriptName)-ClickShare-ConfigureFirewall-$($AlyaTimeString).log" -Force

    try
    {
        $ErrorActionPreference = "Stop"

        if (-Not $StartFrom -or $StartFrom -ne "ScheduledJob")
        {
            Write-Host "No start parameter provided, implementing script autostart"
            $StartupPath = "$($env:systemRoot)\System32\GroupPolicy\Machine\Scripts\Startup"
            $ActPath = $PSCommandPath
            $ScriptName = "ConfigureFirewallForClickShareInProfiles.ps1"
            $ScriptPath = Join-Path $StartupPath $ScriptName
            if (-Not (Test-Path $StartupPath -PathType Container))
            {
                New-Item -Path $StartupPath -Force -ItemType Directory
            }
            Write-Host "Copy script"
            Write-Host "  from $ActPath"
            Write-Host "  to $ScriptPath"
            Copy-Item -Path $ActPath -Destination $ScriptPath -Force -Confirm:$false

            Write-Host "Preparing registry parent"
            $prop = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0" -ErrorAction SilentlyContinue
            if (-Not $prop)
            {
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0" |
                    ForEach-Object { 
                        if (-not (Test-Path $_)) {
                            New-Item -path $_ -force
                        }
                    }
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
            }

            Write-Host "Preparing registry script"
            $existScripts = @()
            while ($true)
            {
                $cnt = $existScripts.Count
                $prop = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\$cnt" -ErrorAction SilentlyContinue
                if ($prop)
                {
                    $existScripts += $prop
                }
                else
                {
                    break
                }
            }

            $prop = $existScripts | Where-Object { $_.GetValue("Script") -eq $ScriptName }
            if (-Not $prop)
            {
                $scriptId = $existScripts.Count
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\$scriptId",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\$scriptId" |
                    ForEach-Object { 
                        if (-not (Test-Path $_)) {
                            New-Item -path $_ -force
                        }
                    }
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\$scriptId",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\$scriptId" |
                    ForEach-Object {
                        New-ItemProperty -path "$_" -name Script -propertyType String -value $ScriptName
                        New-ItemProperty -path "$_" -name Parameters -propertyType String -value "-StartFrom ScheduledJob"
                        New-ItemProperty -path "$_" -name IsPowershell -propertyType DWord -value 1
                        New-ItemProperty -path "$_" -name ExecTime -propertyType QWord -value ([Int64]0)
                    }
            }
            else
            {
                $scriptId = $prop.PSChildName
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\$scriptId",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\$scriptId" |
                    ForEach-Object {
                        Set-ItemProperty -path "$_" -name Script -value $ScriptName
                        Set-ItemProperty -path "$_" -name Parameters -value "-StartFrom ScheduledJob"
                        Set-ItemProperty -path "$_" -name IsPowershell -value 1
                        Set-ItemProperty -path "$_" -name ExecTime -value ([Int64]0)
                    }
            }
            $existScripts = @()
            while ($true)
            {
                $cnt = $existScripts.Count
                $prop = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\$cnt" -ErrorAction SilentlyContinue
                if ($prop)
                {
                    $existScripts += $prop
                }
                else
                {
                    break
                }
            }

            $StartupIniPath = "$($env:systemRoot)\System32\GroupPolicy\Machine\Scripts\psscripts.ini"
            if (-Not (Test-Path $StartupIniPath))
            {
                $iniContent = @"

[Startup]
0CmdLine=$($ScriptName)
0Parameters=-StartFrom ScheduledJob
"@
                $iniContent | Set-Content -Path $StartupIniPath -Force -Encoding Unicode
            }
            $iniContent = Get-Content -Path $StartupIniPath -Encoding Unicode

            $inStartup = $false
            $pos = 0
            $insPos = 0
            foreach($existScript in $existScripts)
            {
                $scriptId = $existScript.PSChildName
                $fnd = $false
                $lastLine = ""
                foreach($line in $iniContent)
                {
                    $pos++
                    if ($inStartup)
                    {
                        if ($line.StartsWith("$($scriptId)CmdLine")) {
                            $line = $existScript.GetValue("Script")
                            $fnd = $true
                        }
                        if ($line.StartsWith("$($scriptId)Parameters")) { $line = $existScript.GetValue("Parameters") }
                        if ($line.StartsWith("[")) {
                            $inStartup = $false
                            $insPos = $pos-1
                            if ([string]::IsNullOrEmpty($lastLine)) { $insPos = $pos-2 }
                        }
                    }
                    if ($line.StartsWith("[Startup")) { $inStartup = $true }
                    $lastLine = $line
                }
                if ($insPos -eq 0) { $insPos = $pos }
                if (-Not $fnd)
                {
                    $iniContent += ""
                    for ($p=($iniContent.Length-1); $p -gt $insPos; $p--)
                    {
                        $iniContent[$p] = $iniContent[$p-1]
                    }
                    $iniContent += ""
                    for ($p=($iniContent.Length-1); $p -gt $insPos; $p--)
                    {
                        $iniContent[$p] = $iniContent[$p-1]
                    }
                    $iniContent[$insPos] = "$($scriptId)CmdLine=$($existScript.GetValue("Script"))"
                    $iniContent[$insPos+1] = "$($scriptId)Parameters=$($existScript.GetValue("Parameters"))"
                }
            }

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
                $progPath = Join-Path $user.FullName "AppData\Local\ClickShare\Current\clickshare_native.exe"
                $err = $false
                $fnd = $false
                try {
                    $fnd = (Test-Path $progPath)
                } catch { $err = $true }
                if ($fnd -or $err)
                {
                    if ($fnd) { Write-Host "Found ClickShare in $($progPath)" }
                    if ($err) { Write-Host "Guessed ClickShare in $($progPath)" }
                    foreach ($prot in $protcols)
                    {
                        $ruleName = "ClickShare.exe-Inbound-$($prot)-$($user.Name)"
                        $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                        if (-not $rule)
                        {
                            $null = New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Profile Any -Program $progPath -Action Allow -Protocol $prot
                        }
                    }
                }
                else
                {
                    Write-Host "No ClickShare installation for this user"
                }
            }
        }

    }
    catch
    {   
        try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
        Write-Error ($_.Exception) -ErrorAction Continue
        $exitCode = -1
    }

    Stop-Transcript
}

exit $exitCode
