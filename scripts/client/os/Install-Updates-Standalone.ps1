#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    14.05.2023 Konrad Brunner       Next script, log location, module path
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Installs Windows updates and optionally Windows upgrades in a standalone execution context, ensuring the system remains up to date and ready for subsequent scripts or configurations.

.DESCRIPTION
The Install-Updates-Standalone.ps1 script automates the process of checking, downloading, and installing Microsoft Windows updates using the PSWindowsUpdate module. It supports automatic retries, reboots, and optional OS upgrades. The script can be configured to execute another script after completion or reboot and maintains a log of its operations. It ensures all necessary modules are installed and properly configured before performing updates, and includes built-in handling for network connectivity and repository setup.

.PARAMETER retryCount
The number of times the script has retried the update process. Used internally to prevent infinite retry loops.

.PARAMETER installUpgrades
A boolean flag indicating whether to check and install Windows upgrades (e.g., feature updates).

.PARAMETER installUpgradesStr
A string representation of the installUpgrades parameter, used for compatibility when passing parameters across script restarts.

.PARAMETER nextScriptToLaunch
Specifies the full path to another PowerShell script to be executed after updates or upgrades are completed.

.PARAMETER rebootForNextScriptToLaunch
Indicates whether a reboot should occur before executing the next script.

.PARAMETER logLocation
Defines the directory where log files and related output will be stored. Defaults to the script root if not specified.

.INPUTS
None. This script does not accept pipeline input.

.OUTPUTS
None. The script writes informational and log output to the console and transcript log files.

.EXAMPLE
PS> .\Install-Updates-Standalone.ps1 -installUpgrades $true -nextScriptToLaunch "C:\Scripts\PostUpdate.ps1" -logLocation "C:\Logs"

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [int]$retryCount = 0,
    [bool]$installUpgrades = $false,
    [string]$installUpgradesStr = $null,
    [string]$nextScriptToLaunch = $null,
    [bool]$rebootForNextScriptToLaunch = $false,
    [string]$logLocation = $null
)
if ($installUpgradesStr) { $installUpgrades = [bool]::Parse($installUpgradesStr) }

# Starting Transcript
$AlyaTimeString = (Get-Date).ToString("yyyyMMddHHmmssfff")
if (-Not $logLocation) { $logLocation = $PSScriptRoot }
$logPath = "$logLocation\Logs\Install-Updates-Standalone-$($AlyaTimeString).log"
Start-Transcript -Path $logPath -IncludeInvocationHeader | Out-Null

#Members
$CommandInfo = "Cyan"
$CommandSuccess = "Cyan"
Write-Host "Constants and Preparation" -ForegroundColor $CommandInfo
$Global:ErrorActionPreference = "Stop"
$Global:ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$AlyaDefaultModulePath = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "WindowsPowerShell\Modules"
if (Test-Path "$PSScriptRoot\..\Modules")
{
    Push-Location "$PSScriptRoot\..\Modules"
    $AlyaModulePath = $pwd
    Pop-Location
}
if (Test-Path "$PSScriptRoot\Modules")
{
    Push-Location "$PSScriptRoot\Modules"
    $AlyaModulePath = $pwd
    Pop-Location
}
if (-Not $AlyaModulePath)
{
    $AlyaModulePath = $AlyaDefaultModulePath
}
if ($AlyaModulePath -ne $AlyaDefaultModulePath)
{
    if (-Not (Test-Path $AlyaModulePath))
    {
        New-Item -Path $AlyaModulePath -ItemType Directory -Force
    }
    if (-Not $env:PSModulePath.StartsWith("$($AlyaModulePath)"))
    {
        $env:PSModulePath = "$($AlyaModulePath);"+$env:PSModulePath
    }
}
#Functions
function Is-InternetConnected()
{
    $ret = Test-NetConnection -ComputerName 8.8.8.8 -Port 443 -ErrorAction SilentlyContinue -InformationLevel Quiet
    if (-Not $ret)
    {
        $ret = Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -ErrorAction SilentlyContinue -InformationLevel Quiet
    }
    return $ret
}
function Get-PublishedModuleVersion(
    [string] [Parameter(Mandatory = $true)] $moduleName
)
{
   $url = "https://www.powershellgallery.com/packages/$moduleName/?dummy=$(Get-Random)"
   $request = [System.Net.WebRequest]::Create($url)
   $request.AllowAutoRedirect=$false
   try
   {
     $response = $request.GetResponse()
     $response.GetResponseHeader("Location").Split("/")[-1] -as [Version]
     $response.Close()
     $response.Dispose()
   }
   catch
   {
     Write-Warning $_.Exception.Message
   }
}
function Install-ModuleIfNotInstalled (
    [string] [Parameter(Mandatory = $true)] $moduleName,
    [Version] $minimalVersion = "0.0.0.0",
    [Version] $exactVersion = "0.0.0.0",
    [bool] $autoUpdate = $true
)
{
    if (-Not (Is-InternetConnected))
    {
        Write-Warning "No internet connection. Not able to check any module!"
        return
    }
    $gmCmd = Get-Command Get-Module
    if (-Not $gmCmd)
    {
        throw "Can't find cmdlt Get-Module"
    }
    $pkg = Get-Module -Name "PackageManagement" -ListAvailable | Sort-Object -Property Version | Select-Object -Last 1
    if ($moduleName -ne "PackageManagement" -and (-Not $pkg -or $pkg.Version -lt [Version]"1.4.7"))
    {
        Install-ModuleIfNotInstalled "PackageManagement"
        throw "PackageManagement updated! Please restart your powershell session"
    }
    $repCmd = Get-Command Get-PSRepository -ErrorAction SilentlyContinue
    if (-Not $repCmd)
    {
        $ModuleContentUrl = "https://www.powershellgallery.com/api/v2/package/PackageManagement"
        do {
            $ModuleContentUrl = (Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore).Headers.Location 
        } while (!$ModuleContentUrl.Contains(".nupkg"))
        $WebClient = New-Object System.Net.WebClient
        $PathFolderName = New-Guid
        $ModuleContentZip = Join-Path $env:TEMP ("$PathFolderName.zip")
        $WebClient.DownloadFile($ModuleContentUrl, $ModuleContentZip)
        $ModuleContentDir = Join-Path $env:TEMP $PathFolderName
        $cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
        if ($cmdTst)
        {
            Expand-Archive -Path $ModuleContentZip -DestinationPath $ModuleContentDir -Force
        }
        else
        {
            Expand-Archive -Path $ModuleContentZip -OutputPath $ModuleContentDir -Force
        }
        Import-Module "$ModuleContentDir\PackageManagement.psd1" -Force -Verbose
    }

    $regRep = Get-PSRepository -Name "PSGallery" -ErrorAction SilentlyContinue
    if (-Not $regRep)
    {
        Register-PSRepository -Name "PSGallery" -SourceLocation "https://www.powershellgallery.com/api/v2/" -PublishLocation "https://www.powershellgallery.com/api/v2/package/" -ScriptSourceLocation "https://www.powershellgallery.com/api/v2/items/psscript/" -ScriptPublishLocation "https://www.powershellgallery.com/api/v2/package/" -InstallationPolicy Trusted -PackageManagementProvider NuGet
    }
    $regRep = Get-PSRepository -Name "PSGallery" -ErrorAction SilentlyContinue
    if ($regRep.InstallationPolicy -ne "Trusted")
    {
	    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
    }
    $psg = Get-Module -Name PowerShellGet -ListAvailable | Sort-Object -Property Version | Select-Object -Last 1
    if ($moduleName -ne "PackageManagement" -and $moduleName -ne "PowerShellGet" -and (-Not $psg -or $psg.Version -lt [Version]"2.0.0.0"))
    {
        Install-ModuleIfNotInstalled "PowerShellGet"
        throw "PowerShellGet updated! Please restart your powershell session"
    }
    if ((Get-PackageProvider -Name NuGet -Force).Version -lt '2.8.5.201')
    {
        Write-Warning "Installing nuget package provider"
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
    }
    $requestedVersion = $minimalVersion
    [Version] $newestVersion = Get-PublishedModuleVersion $moduleName
    if (-Not $newestVersion)
    {
        Write-Warning "Module '$moduleName' does not looks like a module from Powershell Gallery"
        return
    }
    if ($exactVersion -ne "0.0.0.0")
    {
        $module = Get-Module -Name $moduleName -ListAvailable |`
            Where-Object { $_.Version -eq $exactVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            try
            {
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                    Where-Object { $_.Version -eq $exactVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            catch
            {
                Import-Module -Name PowerShellGet
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                    Where-Object { $_.Version -eq $exactVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            if (-Not $module)
            {
                $module = Get-Module -FullyQualifiedName "$AlyaModulePath\$moduleName" -ListAvailable -ErrorAction SilentlyContinue | Sort-Object -Property Version | Select-Object -Last 1
            }
        }
        $autoUpdate = $false
        $requestedVersion = $exactVersion
    }
    else
    {
        $module = Get-Module -Name $moduleName -ListAvailable |`
            Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            try
            {
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                    Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            catch
            {
                Import-Module -Name PowerShellGet
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                    Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            if (-Not $module)
            {
                $module = Get-Module -FullyQualifiedName "$AlyaModulePath\$moduleName" -ListAvailable -ErrorAction SilentlyContinue | Sort-Object -Property Version | Select-Object -Last 1
            }
        }
        $requestedVersion = $newestVersion
    }
    if ($module)
    {
        Write-Host ('Module {0} is installed. Used:v{1} Requested:v{2}' -f $moduleName, $module.Version, $requestedVersion)
        if ((-Not $autoUpdate) -and ($newestVersion -gt $module.Version))
        {
            Write-Warning ("A newer version (v{0}) is available. Consider upgrading!" -f $newestVersion)
        }
        if ($newestVersion -eq $module.Version)
        {
            $autoUpdate = $false
        }
    }
    else
    {
        Write-Host ('Module {0} not found with requested version v{1}. Installing now...' -f $moduleName, $requestedVersion)
        $autoUpdate = $true
    }
    if ($autoUpdate)
    {
        $instCmd = Get-Command Install-Module
        if (-Not $instCmd)
        {
            throw "Please install the powershell package management"
        }
        $optionalArgs = New-Object -TypeName Hashtable
        $optionalArgs['RequiredVersion'] = $requestedVersion
        Write-Warning ('Installing/Updating module {0} to version [{1}] within scope of the current user.' -f $moduleName, $requestedVersion)
        #TODO Unload module
        $paramIM = (Get-Command Install-Module).ParameterSets | Select -ExpandProperty Parameters | where { $_.Name -eq "AcceptLicense" }
        if ($paramIM)
        {
	        if ($AlyaModulePath -eq $AlyaDefaultModulePath)
	        {
	            Install-Module -Name $moduleName @optionalArgs -Scope CurrentUser -AllowClobber -Force -Verbose -AcceptLicense
	        }
	        else
	        {
                Save-Module -Name $moduleName -RequiredVersion $requestedVersion -Path $AlyaModulePath -Force -Verbose -AcceptLicense
	        }
        }
        else
        {
	        if ($AlyaModulePath -eq $AlyaDefaultModulePath)
	        {
	            Install-Module -Name $moduleName @optionalArgs -Scope CurrentUser -AllowClobber -Force -Verbose
	        }
	        else
	        {
                Save-Module -Name $moduleName -RequiredVersion $requestedVersion -Path $AlyaModulePath -Force -Verbose
	        }
        }
        $module = Get-Module -Name $moduleName -ListAvailable |`
            Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            try
            {
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                    Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            catch
            {
                Import-Module -Name PowerShellGet
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                    Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            if (-Not $module)
            {
                $module = Get-Module -FullyQualifiedName "$AlyaModulePath\$moduleName" -ListAvailable -ErrorAction SilentlyContinue | Sort-Object -Property Version | Select-Object -Last 1
                if (-Not $module)
	            {
	                Write-Error "Not able to install the module!" -ErrorAction Continue
	                exit
	            }
	        }
	    }
    }
    if ($exactVersion -ne "0.0.0.0")
    {
        $module = Get-Module -Name $moduleName
        if ($module -and $module.Version -ne $exactVersion)
        {
            Remove-Module -Name $moduleName
        }
        Import-Module -Name $moduleName -RequiredVersion $exactVersion -DisableNameChecking
    }
}
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
$serviceMgrs = Get-WUServiceManager | Select -Property ServiceID
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
Write-Host ($result | fl | Out-String)

if ($retryCount -gt 5)
{
    Write-Error "Too much tetries, stopping" -ErrorAction Continue
    Exit 99
}

$restartScript = [io.path]::GetFullPath($env:AllUsersProfile) + "\Microsoft\Windows\Start Menu\Programs\Startup\AlyaUpdateRestart.cmd"

Write-Host "Checking for updates" -ForegroundColor $CommandInfo
$availableUpdates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll
Restart-Transscipt
Write-Host ($availableUpdates | fl | Out-String)
if ($availableUpdates.Count -gt 0)
{
    Write-Host "We have $($availableUpdates.Count) updates to install"
    Write-Host "Preparing restart after reboot"

    $parms = "-retryCount $($retryCount+1) -installUpgradesStr $($installUpgrades)"
    if ($nextScriptToLaunch) { $parms += " -nextScriptToLaunch \`"$($nextScriptToLaunch)\`"" }
    if ($logLocation) { $parms += " -logLocation \`"$($logLocation)\`"" }
    "powershell.exe -NoLogo -ExecutionPolicy Bypass -Command `"Start-Process powershell.exe -ArgumentList '-NoLogo -ExecutionPolicy Bypass -File \`"$PSCommandPath\`" $parms' -Verb RunAs`"" | Set-Content -Path $restartScript -Force
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
        $toolsDir = "$PSScriptRoot\tools"
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
            $actVersion = Get-Content -Path "$exeFile.$($env:COMPUTERNAME).txt" -Raw -Encoding $AlyaUtf8Encoding
            if ($file.VersionInfo.ProductVersion.Trim() -eq $actVersion.Trim())
            {
                $toBeUpgraded = $false
            }
        }
        if ($toBeUpgraded)
        {
            Write-Host "Preparing restart after reboot"
            $parms = "-retryCount $($retryCount+1)"
            if ($nextScriptToLaunch) { $parms += " -nextScriptToLaunch \`"$($nextScriptToLaunch)\`"" }
            if ($logLocation) { $parms += " -logLocation \`"$($logLocation)\`"" }
            "powershell.exe -NoLogo -ExecutionPolicy Bypass -Command `"Start-Process powershell.exe -ArgumentList '-NoLogo -ExecutionPolicy Bypass -File \`"$PSCommandPath\`" $parms' -Verb RunAs`"" | Set-Content -Path $restartScript -Force
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
                $null = Remove-Item -Path $restartScript -Force
            }
            Write-Host "Device has all actual updates and upgrades installed!" -ForegroundColor $CommandSuccess
            if ($nextScriptToLaunch)
            {
                Write-Host "Launching now script $($nextScriptToLaunch)"
                if ($rebootForNextScriptToLaunch)
                {
                    "powershell.exe -NoLogo -ExecutionPolicy Bypass -Command `"Start-Process powershell.exe -ArgumentList '-NoLogo -ExecutionPolicy Bypass -File \`"$nextScriptToLaunch\`"' -Verb RunAs`"" | Set-Content -Path $restartScript -Force
                    cmd /c shutdown /r /t 0
                }
                else
                {
                    & $nextScriptToLaunch
                }
            }
        }
    }
    else
    {
        if ((Test-Path $restartScript))
        {
            $null = Remove-Item -Path $restartScript -Force
        }
        Write-Host "Device has all actual updates installed!" -ForegroundColor $CommandSuccess
        if ($nextScriptToLaunch)
        {
            Write-Host "Launching now script $($nextScriptToLaunch)"
            if ($rebootForNextScriptToLaunch)
            {
                "powershell.exe -NoLogo -ExecutionPolicy Bypass -Command `"Start-Process powershell.exe -ArgumentList '-NoLogo -ExecutionPolicy Bypass -File \`"$nextScriptToLaunch\`"' -Verb RunAs`"" | Set-Content -Path $restartScript -Force
                cmd /c shutdown /r /t 0
            }
            else
            {
                & $nextScriptToLaunch
            }
        }
    }
}

# Stopping Transcript
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAu3AXpV/75VOwv
# POtMx703jEFApmL4Za8O5IA8dzSDfaCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDj5iHHd
# abrGReZRIbOxEAW+DqeJ7f+qM++HPmbk98/9MA0GCSqGSIb3DQEBAQUABIICAJCi
# QVytzLuYtGMoM+rU08037c4eI47J5u5NX4JQS+o0ziIx5J1VvAvYhPxn6m2D3XbX
# CflkSOuoI+lKYyF/K11rDtArJulMkHrLcEBhA5HG+CqKsmSJOzTozzgRwqkkKBlG
# VsRuFbnhlDk0HZGGF8O46mpXq84tZIJzv/YnyVuVzZTZ2ThEWGuL8X37ZrI6ATp5
# XQeV/wGAetHUZg3pp1oF/MxMqyv6ST8V/IsCemDdWtvgt3BdFRB1Z67OaUrT4MWD
# mpiKMc5V6RftpcO32Sz6pxXOqtjMOEomM5RpFpDdwmU8N5GTtYBDy192/jQYxFcP
# sxuOqIoCZctS/pd4Z0C/GkDQx91B1emYWdzu2B1BRBBQBX08B0VDZzJarTXi8Ub6
# 4gHR8IX6cK/OS45slVLs4hGxQbN5zxqqa6RN13Ji3pbyrvuJZOCayqC1MU+rYvRp
# Vf3YPgiVsmwaYs32F5P7FBUOXfLYzqpn6UNvZf5QaJ7vXWXeSershXSN+eMrjzUf
# XXssEEPq8o3XFsKOYbisBFP7ytLFHcUlZgYj+tTag/LXQsWlUGvcm0B/CLZdVxBQ
# xz/wvfq8msF1jMxPP7Y1pD7tffA0xZdoQlpE+W6t1Tk7fpIxz57Q5BwOzbzg6m2W
# 4X09GNBSm6Ei/ljcQ2ojuz5l5/nk03Kp4pmmGZ0uoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCBqGq50hbDNtM9fT/WwBuOrstPB+pE0FypQTTt9FtpRoAIUQVJD
# 9oMf91uhCZ+Da8sKwEK3ZCQYDzIwMjYwODI5MTUyMDMyWjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDDMY0s7/9DRzL3OEo8Tgt/0qmbQEuLqoEjfANgkViawLG3OlsMaJ2/IV2/h
# mXrcIHIwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGATFjsFCyO3MO7k0OkDLTF5Eal4Lb75xrzM1qUVdnTDzG3
# ozpXtvL1iC51VFyGgjUVj8W9zzN4IB4I5MzyDNOAighHzsMMfM/Ai+Mejc3RFRmh
# XKmjHeoFbrVjAVQk1jKf6PPaV9gfgaC4R/CiTCQI+P0DxeTVczljLmK97X2oKOUD
# ZertuWHx36TrK6ygTHVPn0aNVqvWe62HilLLkt93vXjvu68Yx/kfrK5U+i5OVh1u
# c6f1V2r6yqgOOa02McY8MDXcYmiA1/piKLikUBE0Sx3fEJJRhDzcGY7OMgoExItS
# 5WxGgQoTILrfzZeIIqjF9ssHtpI0yJA6oWdgvk5/d43LSwvEYA6NmuHdBAgc74ZH
# fEr7se6WYUFXcOfeNGoraL2UZgTKUyjzRy2z4In8lB9LES3diBO77i1BMv0J3bM5
# RIkN7WVWQywbD/HbxXdQGZssVK9m3rFaHV10yzxunG26XM+U+FES1BwqCdYdPWkD
# r/mouRnx62YsIxQT8gX0
# SIG # End signature block
