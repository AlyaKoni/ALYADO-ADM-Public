#Requires -Version 2.0
#Requires -RunAsAdministrator

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
    16.10.2020 Konrad Brunner       Initial Version
    15.03.2023 Konrad Brunner       Keep running for non blocking updates

#>

[CmdletBinding()]
Param(
    [int]$retryCount = 0,
    [bool]$installUpgrades = $false
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
$logPath = "$($AlyaLogs)\scripts\client\os\Install-Updates-$($AlyaTimeString).log"
Start-Transcript -Path $logPath | Out-Null
# Functions
function Restart-Transscipt
{
    try
    {
        $oFile = New-Object System.IO.FileInfo $logPath
        $oStream = $oFile.Open([System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        if ($oStream) { $oStream.Close() }
        Start-Transcript -Path $logPath -Append -IncludeInvocationHeader:$false | Out-Null
    } catch { }
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PSWindowsUpdate"

# Preparing service manager
Write-Host "Preparing service manager" -ForegroundColor $CommandInfo
$serviceMgrs = Get-WUServiceManager | Select-Object -Property ServiceID
if ($serviceMgrs.ServiceID -notcontains "7971f918-a847-4430-9279-4a52d1efe18d")
{
    Add-WUServiceManager -ServiceID "7971f918-a847-4430-9279-4a52d1efe18d" -AddServiceFlag 7
}
if ($serviceMgrs.ServiceID -notcontains "9482f4b4-e343-43b6-b170-9a65bc822c77")
{
    Add-WUServiceManager -ServiceID "9482f4b4-e343-43b6-b170-9a65bc822c77"
}
do
{
    $status = Get-WUInstallerStatus
    if ($status.IsBusy)
    {
        Write-Host "WSUS is busy. Waiting..."
        Start-Sleep -Seconds 30
    }
    else
    {
        break
    }
} while ($true)

# Main
Write-Host "Last WSUS result" -ForegroundColor $CommandInfo
$result = Get-WULastResults
Restart-Transscipt
Write-Host ($result | Format-List | Out-String)

if ($retryCount -gt 5)
{
    Write-Error "Too much tetries, stopping" -ErrorAction Continue
    Exit 99
}

$restartScript = [io.path]::GetFullPath($env:AllUsersProfile) + "\Microsoft\Windows\Start Menu\Programs\Startup\AlyaUpdateRestart.cmd"

Write-Host "Checking for updates" -ForegroundColor $CommandInfo
$availableUpdates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll
Restart-Transscipt
Write-Host ($availableUpdates | Format-List | Out-String)
if ($availableUpdates.Count -gt 0)
{
    Write-Host "We have $($availableUpdates.Count) updates to install"
    Write-Host "Preparing restart after reboot"
    "powershell.exe -NoLogo -ExecutionPolicy Bypass -Command `"Start-Process powershell.exe -ArgumentList '-NoLogo -ExecutionPolicy Bypass -File \`"$PSCommandPath\`" -retryCount $($retryCount+1)' -Verb RunAs`"" | Set-Content -Path $restartScript -Force
    #Start-WUScan #-SearchCriteria "IsInstalled=0 and IsHidden=0"
    Write-Host "Installing updates"
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
    do
    {
        $done = -Not (Get-WUInstallerStatus).IsBusy
        if ($done) { $done = (Get-WUInstall).Count -eq 0 }
        if ($done)
        {
            $availableUpdates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll
            foreach($update in $availableUpdates)
            {
                if ($update.Result -ne "")
                {
                    $done = $false
                    break
                }
            }
        }
        if ($done)
        {
            break
        }
        else
        {
            Write-Host "  Still installing. Waiting..."
            Start-Sleep -Seconds 30
        }
    } while ($true)
    cmd /c shutdown /r /t 0
}
else
{
    if ($installUpgrades -and (Get-ComputerInfo).OsProductType -like "*server*")
    {
        Write-Warning "Upgrade not supported on server"
        $installUpgrades = $false
    }
    if ($installUpgrades)
    {
	    Write-Host "Checking for upgrades" -ForegroundColor $CommandInfo
	    $toolsDir = "$AlyaTools\Win10Upgrade"
	    $exeFile = "$toolsDir\Win10Upgrade.exe"
	    if (-Not (Test-Path $toolsDir))
	    {
	        New-Item -Path $toolsDir -ItemType Directory -Force | Out-Null
	    }
	    if ((Test-Path $exeFile))
	    {
	        Remove-Item -Path $exeFile -Force | Out-Null
	    }
	    $url = "https://go.microsoft.com/fwlink/?LinkID=799445"
	    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $exeFile
	    $file = Get-Item -Path $exeFile -Force
	    $toBeUpgraded = $true
	    if ((Test-Path "$exeFile.$($env:COMPUTERNAME).txt"))
	    {
	        $actVersion = Get-Content -Path "$exeFile.$($env:COMPUTERNAME).txt" -Raw -Encoding UTF8
	        if ($file.VersionInfo.ProductVersion.Trim() -eq $actVersion.Trim())
	        {
	            $toBeUpgraded = $false
	        }
	    }
	    if ($toBeUpgraded)
	    {
            Write-Host "Preparing restart after reboot"
            "powershell.exe -NoLogo -ExecutionPolicy Bypass -Command `"Start-Process powershell.exe -ArgumentList '-NoLogo -ExecutionPolicy Bypass -File \`"$PSCommandPath\`" -retryCount $($retryCount+1)' -Verb RunAs`"" | Set-Content -Path $restartScript -Force
	        Write-Host "Launching $exeFile"
	        cmd /c $exeFile /quiet /skipeula /auto upgrade /telemetry Disable /copylogs "$toolsDir"
	        $file.VersionInfo.ProductVersion | Set-Content -Path "$exeFile.$($env:COMPUTERNAME).txt" -Force -Encoding UTF8
	        Wait-UntilProcessEnds "Windows10UpgraderApp"
            cmd /c shutdown /r /t 0
	    }
	    else
	    {
		    if ((Test-Path $restartScript))
		    {
		        $tmp = Remove-Item -Path $restartScript -Force
		    }
		    Write-Host "Device has all actual updates and upgrades installed!" -ForegroundColor $CommandSuccess
	    }
    }
    else
    {
        if ((Test-Path $restartScript))
        {
            $tmp = Remove-Item -Path $restartScript -Force
        }
        Write-Host "Device has all actual updates installed!" -ForegroundColor $CommandSuccess
    }
}

#Stopping Transscript
Stop-Transcript
