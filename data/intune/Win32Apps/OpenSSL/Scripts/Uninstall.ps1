﻿#Requires -Version 2.0

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
    29.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
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
    Start-Transcript -Path "C:\ProgramData\AlyaConsulting\Logs\$($AlyaScriptName)-$($AlyaTimeString).log" -Force

    try
    {
        $ErrorActionPreference = "Stop"

        $regPlats = @("","\WOW6432Node")
        foreach($regPlat in $regPlats)
        {
            foreach($reg in (Get-ChildItem -Path "HKLM:\SOFTWARE$regPlat\Microsoft\Windows\CurrentVersion\Uninstall"))
            {
                $displayName = $null
                $publisher = $null
                $uninstallString = $null
                try {
                    $displayName = Get-ItemPropertyValue -Path $reg.PSPath -Name "DisplayName" -ErrorAction SilentlyContinue
                } catch {}
                try {
                    $publisher = Get-ItemPropertyValue -Path $reg.PSPath -Name "Publisher" -ErrorAction SilentlyContinue
                } catch {}
                if ($displayName -like "OpenSSL*" -and $publisher -eq "OpenSSL Win64 Installer Team")
                {
                    Write-Host "Uninstalling $displayName"
                    Write-Host "with infos from $($reg.Name)"
					try {
						$uninstallString = Get-ItemPropertyValue -Path $reg.PSPath -Name "QuietUninstallString" -ErrorAction SilentlyContinue
					} catch {}
                    if (-Not $uninstallString)
                    {
                        $uninstallString = (Get-ItemPropertyValue -Path $reg.PSPath -Name "UninstallString") + " /qn /norestart" -replace "/I", "/X"
                    }
                    if (-Not $uninstallString.Contains("msiexec"))
                    {
                        $uninstallStringNew = ""
                        $uninstallParts = $uninstallString.Split()
                        foreach($uninstallPart in $uninstallParts)
                        {
                            if (($uninstallStringNew -eq "") -and (-Not $uninstallPart.StartsWith("`"")))
                            {
                                $uninstallStringNew += "`""
                            }
                            if ($uninstallPart.Contains(".exe") -and -not $uninstallPart.Contains("`""))
                            {
                                $uninstallPart = $uninstallPart + "`""
                            }
                            $uninstallStringNew += $uninstallPart + " "
                        }
                        $uninstallString = $uninstallStringNew
                    }
                    $uninstallString += " /L* `"C:\ProgramData\AlyaConsulting\Logs\OpenSSL-Uninstall-$AlyaTimeString.log`""
                    Write-Host "command: $uninstallString"
                    Write-Host "MSI Start: $((Get-Date).ToString("yyyyMMddHHmmssfff"))"
                    cmd /c "$uninstallString"
					Write-Host "CMD returned: $LASTEXITCODE at $((Get-Date).ToString("yyyyMMddHHmmssfff"))"
                    do
                    {
                        Start-Sleep -Seconds 5
                        $process = Get-Process -Name "msiexec.exe" -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -notlike "*\SYSTEM" }
                    } while ($process)
                    Write-Host "MSI End: $((Get-Date).ToString("yyyyMMddHHmmssfff"))"
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
