#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2019-2025

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
    14.05.2023 Konrad Brunner       Next script, log location, module path

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

#Starting Transscript
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

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA0i8t2+f6hn8ue
# wHooiy3ScuQburCbgWVZLzuxqDvTK6CCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILfFC0tRFGVAewNs
# RW+LwuScIvKSyQqI7LeNOrwBSzw1MA0GCSqGSIb3DQEBAQUABIICACoFXnEx9yQ8
# MP7yqePUnINtWnEZA3Ix3q0i0bLqIm2gF9kr/X4fPmCP50wczbiY3NoOVIAXCUWR
# JHhJLe0Hi+gVD8Casqmzu573SgdQbP3urEW7lyZ8t8JWZeh5nS8zAN0y9CNVb80x
# hdSf1iyNdcfpI3KT8bYOfUSzWSItaoFTOV/6gEAXl79HtNvCIzMjP/y3ssAIAaKg
# wDlUOcawcZnuj31EVlOCs1VYw90lghDQw6SVrbwv7ytjXVRvgBDuwByu9pg7zuOu
# /Q+vFnJVCzPTEGsbX/BErLI5Me6oCnPA3Yz/2y9UCccCQGfO+nZZ0tBStmrLFbA+
# p/HAzmzwGwg1DCeHbcmDHAmicoEvg+N/HBuqG9HaLEbXtNM50SanJzxaXbabasSs
# xTvPhO16D/6cL30HWikiNvkPBEi0i/NIwePSBrjDML+FXCVU/Dgz9NsNToNq/kov
# 1nXYB6Oceq0f24WfWbKiWvRrn6ZVP8r3CWjAKOwnZjQBcaxh2Ws/tV7hdAs5XcMC
# LB6pkF0YHbBj+JOTsVJs/81v3G5LjRpBOQmQlNBbOTjBrHfCPFkl4Jp3qKIjj1rM
# tz6dJAJ5G8RRiF7Hh5qtfa29FIqvXMo/ICG+39DZC8fwULrobHAHFTPL5Tzf81k0
# /AJprDikjx4R1ySALhLRpdlJS87CidbEoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCBD2S7KCxL2QolnAlXRXC+iB7KRrtIWGKZ4XzZXoGyGfAIUPvbzV3xE3RAg
# FLdv3lNVJd9iSbMYDzIwMjUwODI1MTUzMjQ5WjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
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
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# IOuscXPmwgVDA2X/I3AqZS7JzXVqM3GRnFM7NKpcPBgYMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAGUJO0HjCro/c
# qxUqIvlQSEMsV3tf+FzhTj/bFh8rGGXEaoeNaqe3BF1+5ipCbsPfxAvK3a8+GA7o
# hl4avA6OQDI52Y8prx4SXO4JYzh0IYLEGACi5joWm4V9r12ZlJF7kUiyVTVaf0Gw
# OZoXnkYqV2LtW/+KS2S9PwGplld3S/ZVfzaypIzXMjc9aCZnJZsaekv0Na/dHmUW
# mhD5iVcYAYkjv/gc23pSUu0XLMDoxU4Aa9WXtCvE0iCZOJGvoyUM1jfQyO5XA+09
# kIgUHmoDImhWXCxbDY0gFkVAL9NMv0younteuoSRHPm+JDl5yFHMqMZHeGge4j+y
# D6kPXO/D9Lpm0O8pc8WQ2aoJCfkcw7bwGFkp006nw+LqFcHVOKnS6traO0kYl9lJ
# 7bPoIB1JBgH+PjwfJFtkdYPBXRU0ym8ucNKCbNCPLqeYHexiWrLWs7OT639WN9p+
# xwTYDdNyaLTiTYGwv5SVjKf0fJzlj9YaWrFX0AQ40tv/aSbAvcmI
# SIG # End signature block
