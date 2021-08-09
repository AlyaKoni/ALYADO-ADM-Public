#Requires -Version 2.0

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

        # Install msi
        $toInstall = Get-ChildItem -Path $AlyaScriptDir -Filter "*.msi"
        foreach($toInst in $toInstall)
        {
            Write-Host "Installing $($toInst.FullName)"
            Write-Host "MSI Start: $((Get-Date).ToString("yyyyMMddHHmmssfff"))"
            $installString = "msiexec.exe /i `"$($toInst.FullName)`" /qn /norestart /L* `"C:\ProgramData\AlyaConsulting\Logs\WindowsVirtualDesktopClient-Install-$AlyaTimeString.log`" ALLUSERS=1"
            Write-Host "command: $installString"
            cmd /c "$installString"
			Write-Host "CMD returned: $LASTEXITCODE at $((Get-Date).ToString("yyyyMMddHHmmssfff"))"
            do
            {
                Start-Sleep -Seconds 5
                $process = Get-Process -Name "msiexec" -IncludeUserName -ErrorAction SilentlyContinue | where { $_.UserName -notlike "*\SYSTEM" }
                if (-Not $process)
                {
                    $process = Get-Process -Name "msiexec.exe" -IncludeUserName -ErrorAction SilentlyContinue | where { $_.UserName -notlike "*\SYSTEM" }
                }
            } while ($process)
            Write-Host "MSI End: $((Get-Date).ToString("yyyyMMddHHmmssfff"))"
        }

        # Configure registry
        Write-Host "Configuring registry"
        $rdpRegPath = "HKLM:\SOFTWARE\Microsoft\MSRDC\Policies"
        if (!(Test-Path $rdpRegPath))
        {
            New-Item -Path $rdpRegPath -Force
        }
        $prop = Get-ItemProperty -Path $rdpRegPath -Name "AutomaticUpdates" -ErrorAction SilentlyContinue
        if (-Not $prop)
        {
            New-ItemProperty -Path $rdpRegPath -Name "AutomaticUpdates" -Value "0" -PropertyType DWORD -Force
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
