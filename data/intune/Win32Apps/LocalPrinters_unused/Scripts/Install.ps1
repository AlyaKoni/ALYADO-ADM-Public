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
    29.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

$exitCode = 0
$AlyaTimeString = (Get-Date).ToString("yyyyMMddHHmmssfff")
$AlyaScriptName = Split-Path $PSCommandPath -Leaf
$AlyaScriptDir = Split-Path $PSCommandPath -Parent

function Wait-UntilProcessEnds(
    [string] [Parameter(Mandatory = $true)] $processName)
{
    $maxStartTries = 10
    $startTried = 0
    do
    {
        $prc = Get-Process -Name $processName -ErrorAction SilentlyContinue
        $startTried = $startTried + 1
        if ($startTried -gt $maxStartTries)
        {
            $prc = "Continue"
        }
    } while (-Not $prc)
    do
    {
        Start-Sleep -Seconds 5
        $prc = Get-Process -Name $processName -ErrorAction SilentlyContinue
    } while ($prc)
}

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
    Start-Transcript -Path "C:\ProgramData\AlyaConsulting\Logs\$($AlyaScriptName)-LocalPrinters-$($AlyaTimeString).log" -Force

    try
    {
        $ErrorActionPreference = "Stop"

        # Running version
        Write-Host "Running version:"
        $versionFile = Join-Path $AlyaScriptDir "version.json"
        Get-Content -Path $versionFile -Raw -Encoding UTF8

        # Unpacking content
        $cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
        if ($cmdTst)
        {
            Expand-Archive -Path "$AlyaScriptDir\Content.zip" -DestinationPath "$AlyaScriptDir" -Force #AlyaAutofixed
        }
        else
        {
            Expand-Archive -Path "$AlyaScriptDir\Content.zip" -OutputPath "$AlyaScriptDir" -Force #AlyaAutofixed
        }
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
        
        # Installing driver certificates
        #Write-Host "Installing driver certificates"
        #Import-Certificate -FilePath "$driverRoot\MinoltaTrustedPublisher.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher

        # Installing drivers
        Write-Host "Checking Sharp driver"
        $driverSharp = Get-PrinterDriver | Where-Object { $_.Name -eq $driverSharpName } -ErrorAction SilentlyContinue
        if (-Not $driverSharp)
        {
            Write-Host "  Installing Sharp driver"
            Push-Location $driverSharpDir
            Invoke-Command { pnputil.exe -i -a *.inf }
            Wait-UntilProcessEnds "pnputil"
            Pop-Location 
            Start-Sleep -Seconds 30
            Restart-Service -Name Spooler -Force
            Add-PrinterDriver -Name $driverSharpName
            Start-Sleep -Seconds 10
            $driverSharp = Get-PrinterDriver | Where-Object { $_.Name -eq $driverSharpName } -ErrorAction SilentlyContinue
            if (-Not $driverSharp)
            {
                throw "Not able to install the Sharp driver"
            }
        }

        Write-Host "Checking Hp PCL driver"
        $driverHpPcl = Get-PrinterDriver | Where-Object { $_.Name -eq $driverHpPclUniversalName } -ErrorAction SilentlyContinue
        if (-Not $driverHpPcl)
        {
            Write-Host "  Installing Hp Universal PCL driver"
            Push-Location $driverHpPclDir
            .\Install.exe /infstage /h /q
			Wait-UntilProcessEnds "Install"
            Pop-Location 
            Start-Sleep -Seconds 30
            Restart-Service -Name Spooler -Force
            Start-Sleep -Seconds 10
            Add-PrinterDriver -Name $driverHpPclUniversalName
            Start-Sleep -Seconds 10
            $driverHpPcl = Get-PrinterDriver | Where-Object { $_.Name -eq $driverHpPclUniversalName } -ErrorAction SilentlyContinue
            if (-Not $driverHpPcl)
            {
                throw "Not able to install the Hp PCL driver"
            }
        }

        Write-Host "Checking Hp Ps driver"
        $driverHpPs = Get-PrinterDriver | Where-Object { $_.Name -eq $driverHpPsUniversalName } -ErrorAction SilentlyContinue
        if (-Not $driverHpPs)
        {
            Write-Host "  Installing Hp Universal Ps driver"
            Push-Location $driverHpPsDir
            .\Install.exe /infstage /h /q
			Wait-UntilProcessEnds "Install"
            Pop-Location 
            Start-Sleep -Seconds 30
            Restart-Service -Name Spooler -Force
            Add-PrinterDriver -Name $driverHpPsUniversalName
            Start-Sleep -Seconds 10
            $driverHpPs = Get-PrinterDriver | Where-Object { $_.Name -eq $driverHpPsUniversalName } -ErrorAction SilentlyContinue
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
                Add-Printer -Name $printerName -PortName "IP_$portIp" -DriverName $driverName
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
                #$PermissionSDDL = Get-Printer -full -Name $printerName | Select-Object PermissionSDDL -ExpandProperty PermissionSDDL
                $newSDDL = (Get-Printer -full -Name $printerName | Select-Object PermissionSDDL -ExpandProperty PermissionSDDL)+$addSDDL
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
            New-ItemProperty -Path $regPath -Name $valueName -Value $version -PropertyType String -Force
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
