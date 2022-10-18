#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2022

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
    08.07.2022 Konrad Brunner       Initial Version

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

        <#
        $VerbosePreference = 'Continue'
        if (-not $env:ChocolateyInstall) {
            $message = @(
                "The ChocolateyInstall environment variable was not found."
                "Chocolatey is not detected as installed. Nothing to do."
            ) -join "`n"

            Write-Warning $message
            return
        }

        if (-not (Test-Path $env:ChocolateyInstall)) {
            $message = @(
                "No Chocolatey installation detected at '$env:ChocolateyInstall'."
                "Nothing to do."
            ) -join "`n"

            Write-Warning $message
            return
        }

        $userKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment')
        $userPath = $userKey.GetValue('PATH', [string]::Empty, 'DoNotExpandEnvironmentNames').ToString()

        $machineKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\ControlSet001\Control\Session Manager\Environment\')
        $machinePath = $machineKey.GetValue('PATH', [string]::Empty, 'DoNotExpandEnvironmentNames').ToString()

        $backupPATHs = @(
            "User PATH: $userPath"
            "Machine PATH: $machinePath"
        )
        $backupFile = "C:\PATH_backups_ChocolateyUninstall.txt"
        $backupPATHs | Set-Content -Path $backupFile -Encoding UTF8 -Force

        $warningMessage = @"
            This could cause issues after reboot where nothing is found if something goes wrong.
            In that case, look at the backup file for the original PATH values in '$backupFile'.
"@

        if ($userPath -like "*$env:ChocolateyInstall*") {
            Write-Verbose "Chocolatey Install location found in User Path. Removing..."
            Write-Warning $warningMessage

            $newUserPATH = @(
                $userPath -split [System.IO.Path]::PathSeparator |
                    Where-Object { $_ -and $_ -ne "$env:ChocolateyInstall\bin" }
            ) -join [System.IO.Path]::PathSeparator

            # NEVER use [Environment]::SetEnvironmentVariable() for PATH values; see https://github.com/dotnet/corefx/issues/36449
            # This issue exists in ALL released versions of .NET and .NET Core as of 12/19/2019
            $userKey.SetValue('PATH', $newUserPATH, 'ExpandString')
        }

        if ($machinePath -like "*$env:ChocolateyInstall*") {
            Write-Verbose "Chocolatey Install location found in Machine Path. Removing..."
            Write-Warning $warningMessage

            $newMachinePATH = @(
                $machinePath -split [System.IO.Path]::PathSeparator |
                    Where-Object { $_ -and $_ -ne "$env:ChocolateyInstall\bin" }
            ) -join [System.IO.Path]::PathSeparator

            # NEVER use [Environment]::SetEnvironmentVariable() for PATH values; see https://github.com/dotnet/corefx/issues/36449
            # This issue exists in ALL released versions of .NET and .NET Core as of 12/19/2019
            $machineKey.SetValue('PATH', $newMachinePATH, 'ExpandString')
        }

        # Adapt for any services running in subfolders of ChocolateyInstall
        $agentService = Get-Service -Name chocolatey-agent -ErrorAction SilentlyContinue
        if ($agentService -and $agentService.Status -eq 'Running') {
            $agentService.Stop()
        }
        # TODO: add other services here

        Remove-Item -Path $env:ChocolateyInstall -Recurse -Force -WhatIf

        'ChocolateyInstall', 'ChocolateyLastPathUpdate' | ForEach-Object {
            foreach ($scope in 'User', 'Machine') {
                [Environment]::SetEnvironmentVariable($_, [string]::Empty, $scope)
            }
        }

        $machineKey.Close()
        $userKey.Close()
        #>

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
