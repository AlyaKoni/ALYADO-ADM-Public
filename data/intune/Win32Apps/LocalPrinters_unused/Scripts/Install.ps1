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

        # Unpacking content
        Expand-Archive -Path "$AlyaScriptDir\Content.zip" -DestinationPath "$AlyaScriptDir" -Force
        $driverRoot = Join-Path $AlyaScriptDir "ContentZip"

        # Defining members
        $driverSharpName = "SHARP MX-2651 PCL6"
        $driverHpPclUniversalName = "HP Universal Printing PCL 6"
        $driverHpPsUniversalName = "HP Universal Printing PS"

        $printers = @(
            @("YourPrinterName1","192.168.45.93",$driverHpPclUniversalName),
            @("YourPrinterName2","192.168.45.92",$driverHpPclUniversalName))
        $addSDDL = "(A;OIIO;RPWPSDRCWDWO;;;WD)"

        $driverSharpDir = "$driverRoot\SharpPcl6"
        $driverHpPclDir = "$driverRoot\HpPcl6"
        $driverHpPsDir = "$driverRoot\HpPs"

        # Installing drivers
        Write-Host "Checking Sharp driver"
        $driverSharp = Get-PrinterDriver | where { $_.Name -eq $driverSharpName } -ErrorAction SilentlyContinue
        if (-Not $driverSharp)
        {
            Write-Host "  Installing Sharp driver"
            Invoke-Command { pnputil.exe -a "$driverSharpDir\app\German\PCL6\64bit\su2emdeu.inf" }
            Start-Sleep -Seconds 10
            Add-PrinterDriver -Name $driverSharpName
            Start-Sleep -Seconds 10
            $driverSharp = Get-PrinterDriver | where { $_.Name -eq $driverSharpName } -ErrorAction SilentlyContinue
            if (-Not $driverSharp)
            {
                throw "Not able to install the Sharp driver"
            }
        }

        Write-Host "Checking Hp PCL driver"
        $driverHpPcl = Get-PrinterDriver | where { $_.Name -eq $driverHpPclUniversalName } -ErrorAction SilentlyContinue
        if (-Not $driverHpPcl)
        {
            Write-Host "  Installing Hp Universal PCL driver"
            pushd $driverHpPclDir
            .\Install.exe /infstage /h /q
            popd
            Start-Sleep -Seconds 10
            Add-PrinterDriver -Name $driverHpPclUniversalName
            Start-Sleep -Seconds 10
            $driverHpPcl = Get-PrinterDriver | where { $_.Name -eq $driverHpPclUniversalName } -ErrorAction SilentlyContinue
            if (-Not $driverHpPcl)
            {
                throw "Not able to install the Hp PCL driver"
            }
        }

        Write-Host "Checking Hp Ps driver"
        $driverHpPs = Get-PrinterDriver | where { $_.Name -eq $driverHpPsUniversalName } -ErrorAction SilentlyContinue
        if (-Not $driverHpPs)
        {
            Write-Host "  Installing Hp Universal Ps driver"
            pushd $driverHpPsDir
            .\Install.exe /infstage /h /q
            popd
            Start-Sleep -Seconds 10
            Add-PrinterDriver -Name $driverHpPsUniversalName
            Start-Sleep -Seconds 10
            $driverHpPs = Get-PrinterDriver | where { $_.Name -eq $driverHpPsUniversalName } -ErrorAction SilentlyContinue
            if (-Not $driverHpPs)
            {
                throw "Not able to install the Hp Ps driver"
            }
        }

        # Installing printers
        foreach($printerDef in $printers)
        {

            $printerName = $printerDef[0]
            $portIp = $printerDef[1]
            $driverName = $printerDef[2]

            Write-Host "Checking $($printerName) port"
            $port = Get-PrinterPort -Name "IP_$portIp" -ErrorAction SilentlyContinue
            if (-Not $port)
            {
                Write-Host "  Installing port"
                Add-PrinterPort -Name "IP_$portIp" -PrinterHostAddress $portIp
                Start-Sleep 10
                $port = Get-PrinterPort -Name "IP_$portIp" -ErrorAction SilentlyContinue
                if (-Not $port)
                {
                    throw "Not able to install the $($printerName) port"
                }
            }

            Write-Host "Checking $($printerName) printer"
            $printer = Get-Printer -Name $printerName -ErrorAction SilentlyContinue
            if (-Not $printer)
            {
                Write-Host "  Installing printer"
                Add-Printer -Name $printerName -PortName "IP_$portIp" -DriverName $driverSharpName
                Start-Sleep 10
                $printer = Get-Printer -Name $printerName -ErrorAction SilentlyContinue
                if (-Not $printer)
                {
                    throw "Not able to install the $($printerName) printer"
                }

                Write-Host "  Setting properties"
                if ((Test-Path "$driverRoot\Settings$($printerName).dat"))
                {
                    rundll32 printui.dll,PrintUIEntry /Sr /n "$printerName" /a "$driverRoot\Settings$($printerName).dat" m f g p
                }

                Write-Host "  Setting access"
                #$PermissionSDDL = Get-Printer -full -Name $printerName | select PermissionSDDL -ExpandProperty PermissionSDDL
                $newSDDL = (Get-Printer -full -Name $printerName | select PermissionSDDL -ExpandProperty PermissionSDDL)+$addSDDL
                Set-Printer -Name $printerName -PermissionSDDL $newSDDL
            }

        }

        # Setting version in registry
        $versionFile = Join-Path $AlyaScriptDir "version.json"
        $versionObj = Get-Content -Path $versionFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $version = [Version]$versionObj.version
        $regPath = "HKLM:\SOFTWARE\AlyaConsulting\Intune\Win32AppVersions"
        $valueName = "LocalPrinters"
        if (!(Test-Path $regPath))
        {
            New-Item -Path $regPath -Force
        }
        $prop = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
        if (-Not $prop)
        {
            New-ItemProperty -Path $regPath -Name $valueName -Value $version -PropertyType DWORD -Force
        }
        else
        {
            Set-ItemProperty -Path $regPath -Name $valueName -Value $version -Force
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
