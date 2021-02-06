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
    06.11.2019 Konrad Brunner       Initial version
    25.02.2020 Konrad Brunner       Changed login functions
    02.03.2020 Konrad Brunner       Added network functions
    10.03.2020 Konrad Brunner       Added wvd stuff
    07.04.2020 Konrad Brunner       Added aip stuff
    21.04.2020 Konrad Brunner       Service principal recognition in LoginTo-Az
    09.09.2020 Konrad Brunner       Changed context naming
    14.09.2020 Konrad Brunner       Moved Alya global variables to data\ConfigureEnv.ps1
    17.09.2020 Konrad Brunner       Added custom property checks
    24.09.2020 Konrad Brunner       LoginTo-EXO and LoginTo-IPPS

#>

[CmdletBinding()]
Param(
)

<# COLORS will be overwritten by custom configuration #>
$CommandInfo = "Cyan"
$CommandSuccess = "Green"
$CommandError = "Red"
$CommandWarning = "Yellow"
$AlyaColor = "White"
$TitleColor = "Green"
$MenuColor = "Magenta"
$QuestionColor = "Magenta"

# Loading custom configuration
Write-Host "Loading configuration" -ForegroundColor Cyan
if ((Test-Path $PSScriptRoot\data\ConfigureEnv.ps1))
{
    . $PSScriptRoot\data\ConfigureEnv.ps1
}

<# POWERSHELL #>
$ErrorActionPreference = "Stop"

<# TLS Connections #>
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

<# PATHS #>
$AlyaRoot = "$PSScriptRoot"
$AlyaLogs = "$AlyaRoot\_logs"
$AlyaTemp = "$AlyaRoot\_temp"
$AlyaLocal = "$AlyaRoot\_local"
$AlyaData = "$AlyaRoot\data"
$AlyaScripts = "$AlyaRoot\scripts"
$AlyaTools = "$AlyaRoot\tools"
$AlyaOfficeRoot = "C:\Program Files\Microsoft Office\root\Office16"
$AlyaGitRoot = Join-Path (Join-Path $AlyaRoot "tools") "git"
$AlyaDeployToolRoot = Join-Path (Join-Path $AlyaRoot "tools") "officedeploy"
if (-Not (Test-Path "$AlyaLogs"))
{
    $tmp = New-Item -Path "$AlyaLogs" -ItemType Directory -Force
}
#Env required for WinPE and sticks
if ((Test-Path "$($AlyaTools)\WindowsPowerShell\Modules") -and `
     -Not $env:PSModulePath.Contains("$($AlyaTools)\WindowsPowerShell\Modules"))
{
    Write-Host "Adding tools\WindowsPowerShell\Modules to PSModulePath"
    $env:PSModulePath = "$($AlyaTools)\WindowsPowerShell\Modules;"+$env:PSModulePath
}
if ((Test-Path "$($AlyaTools)\WindowsPowerShell\Scripts") -and `
     -Not $env:Path.Contains("$($AlyaTools)\WindowsPowerShell\Scripts"))
{
    Write-Host "Adding tools\WindowsPowerShell\Scripts to Path"
    $env:Path = "$($AlyaTools)\WindowsPowerShell\Scripts;"+$env:Path
}

<# CLIENT SETTINGS #>
$AlyaOfficeToolsOnTaskbar = @("OUTLOOK.EXE", "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE") #WINPROJ.EXE, VISIO.EXE, ONENOTE.EXE, MSPUB.EXE, MSACCESS.EXE

<# URLS #>
$AlyaGitDownload = "https://git-scm.com/download/win"
$AlyaDeployToolDownload = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=49117"
$AlyaAipClientDownload = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=53018"
$AlyaIntuneWinAppUtilDownload = "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool.git"
$AlyaAzCopyDownload = "https://aka.ms/downloadazcopy-v10-windows"
$AlyaAdkDownload = "https://go.microsoft.com/fwlink/?linkid=2120254"
$AlyaAdkPeDownload = "https://go.microsoft.com/fwlink/?linkid=2120253"

<# LOCAL CONFIGURATION #>
$Global:AlyaLocalConfig = [ordered]@{
    user= @{
        email = ""
        ssh = ""
    }
}
Function Save-LocalConfig()
{
    $tmp = $Global:AlyaLocalConfig | ConvertTo-Json | Set-Content -Path "$AlyaLocal\LocalConfig.json" -Encoding UTF8 -Force
}
Function Read-LocalConfig()
{
    $Global:AlyaLocalConfig = Get-Content -Path "$AlyaLocal\LocalConfig.json" -Raw -Encoding UTF8 | ConvertFrom-Json
}
if (-Not (Test-Path "$AlyaLocal\LocalConfig.json"))
{
    $tmp = New-Item -Path "$AlyaLocal" -ItemType Directory -Force
}
if ((Test-Path "$AlyaLocal\LocalConfig.json"))
{
    Read-LocalConfig
}
else
{
    Save-LocalConfig
}

<# GLOBAL CONFIGURATION #>
$Global:AlyaGlobalConfig = [ordered]@{
    source= @{
        devops = ""
    }
}
Function Save-GlobalConfig()
{
    $tmp = $Global:AlyaGlobalConfig | ConvertTo-Json | Set-Content -Path "$AlyaData\GlobalConfig.json" -Encoding UTF8 -Force
}
Function Read-GlobalConfig()
{
    $Global:AlyaGlobalConfig = Get-Content -Path "$AlyaData\GlobalConfig.json" -Raw -Encoding UTF8 | ConvertFrom-Json
}
if (-Not (Test-Path "$AlyaData\GlobalConfig.json"))
{
    $tmp = New-Item -Path "$AlyaData\" -ItemType Directory -Force
}
if ((Test-Path "$AlyaData\GlobalConfig.json"))
{
    Read-GlobalConfig
}
else
{
    Save-GlobalConfig
}

<# OTHERS #>
$AlyaTimeString = (Get-Date).ToString("yyyyMMddHHmmss")

<# FUNCTIONS #>
function Is-InternetConnected()
{
    if ((test-connection 8.8.8.8 -Count 1 -Quiet -ErrorAction SilentlyContinue))
    {
        return $true
    }
    else
    {
        return $false
    }
}

function Reset-ConsoleWidth()
{
    try
    {
        $pshost = Get-Host
        $pswindow = $pshost.UI.RawUI
        if ($Global:AlyaConsoleBufferSize)
        {
            $newsize = $pswindow.BufferSize
            if ($newsize)
            {
                $newsize.width = $Global:AlyaConsoleBufferSize
                $pswindow.buffersize = $newsize
            }
        }
        if ($Global:AlyaConsoleWindowsSize)
        {
            $newsize = $pswindow.windowsize
            if ($newsize)
            {
                $newsize.width = $Global:AlyaConsoleWindowsSize
                $pswindow.windowsize = $newsize
            }
        }
    } catch {
        Write-Error $_.Exception -ErrorAction Continue
    }
}

function Increase-ConsoleWidth(
    [int] [Parameter(Mandatory = $false)] $newWidth = 8192)
{
    try
    {
        $pshost = Get-Host
        $pswindow = $pshost.UI.RawUI
        $newsize = $pswindow.BufferSize
        if ($newsize)
        {
            if (-Not $Global:AlyaConsoleBufferSize -or $Global:AlyaConsoleBufferSize -ne $newWidth)
            {
                $Global:AlyaConsoleBufferSize = $newsize.width
            }
            $newsize.width = $newWidth
            $pswindow.buffersize = $newsize
        }
        $newsize = $pswindow.windowsize
        if ($newsize)
        {
            if (-Not $Global:AlyaConsoleWindowsSize -or $Global:AlyaConsoleWindowsSize -ne $newWidth)
            {
                $Global:AlyaConsoleWindowsSize = $newsize.width
            }
            $newsize.width = $newWidth
            $pswindow.windowsize = $newsize
        }
    } catch {
        Write-Error $_.Exception -ErrorAction Continue
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

function Check-Module (
    [string] [Parameter(Mandatory = $true)] $moduleName,
    [Version] $minimalVersion = "0.0.0.0",
    [Version] $exactVersion = "0.0.0.0"
)
{
    if ($exactVersion -ne "0.0.0.0")
    {
        $module = Get-Module -Name $moduleName -ListAvailable |`
            Where-Object { $_.Version -eq $exactVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                Where-Object { $_.Version -eq $exactVersion } | Sort-Object -Property Version | Select-Object -Last 1
        }
    }
    else
    {
        $module = Get-Module -Name $moduleName -ListAvailable |`
            Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
        }
    }
    if (-Not $module)
    {
        Write-Error "Can't find module $moduleName" -ErrorAction Continue
        Write-Error "Please install the module and restart" -ErrorAction Continue
        exit
    }
}

function DownloadAndInstall-Package($packageName, $nuvrs, $nusrc)
{
	$fileName = "$($AlyaTools)\Packages\$packageName_" + $nuvrs + ".nupkg"
	Invoke-WebRequest -Uri $nusrc.href -OutFile $fileName
	if (-not (Test-Path $fileName))
	{
		Write-Error "    Was not able to download $packageName which is a prerequisite for this script" -ErrorAction Continue
		break
	}
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($fileName, "$($AlyaTools)\Packages\$packageName")
    Remove-Item $fileName
}

function Install-PackageIfNotInstalled (
    [string] [Parameter(Mandatory = $true)] $packageName,
    [bool] $autoUpdate = $true
)
{
    if (-Not (Is-InternetConnected))
    {
        Write-Warning "No internet connection. Not able to check any package!"
        return
    }
    if (-Not (Test-Path "$($AlyaTools)\Packages"))
    {
        $tmp = New-Item -Path "$($AlyaTools)\Packages" -ItemType Directory -Force
    }
    $resp = Invoke-WebRequest -Uri "https://www.nuget.org/packages/$packageName" -UseBasicParsing
    $nusrc = ($resp).Links | where { $_.outerText -eq "Download package" -or $_.outerText -eq "Manual download" -or $_."data-track" -eq "outbound-manual-download"}
    $nuvrs = $nusrc.href.Substring($nusrc.href.LastIndexOf("/") + 1, $nusrc.href.Length - $nusrc.href.LastIndexOf("/") - 1)
    if (-not (Test-Path "$($AlyaTools)\Packages\$packageName\$packageName.nuspec"))
    {
        DownloadAndInstall-Package -packageName $packageName -nuvrs $nuvrs -nusrc $nusrc
    }
    else
    {
        # Checking package version, updating if required
        if ($autoUpdate)
        {
            $nuspec = [xml](Get-Content "$($AlyaTools)\Packages\$packageName\$packageName.nuspec")
            if ($nuspec.package.metadata.version -ne $nuvrs)
            {
                Write-Host "    There is a newer CSOM package available. Downloading and installing it."
                Remove-Item -Recurse -Force "$($AlyaTools)\Packages\$packageName"
                DownloadAndInstall-Package -packageName $packageName -nuvrs $nuvrs -nusrc $nusrc
            }
        }
    }
}

function Uninstall-ModuleIfInstalled (
    [string] [Parameter(Mandatory = $true)] $moduleName,
    [Version] $exactVersion = "0.0.0.0"
)
{
    if ($exactVersion -ne "0.0.0.0")
    {
        $module = Get-Module -Name $moduleName -ListAvailable |`
            Where-Object { $_.Version -eq $exactVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                Where-Object { $_.Version -eq $exactVersion } | Sort-Object -Property Version | Select-Object -Last 1
        }
    }
    else
    {
        $module = Get-Module -Name $moduleName -ListAvailable | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | Sort-Object -Property Version | Select-Object -Last 1
        }
    }
    if ($module)
    {
        Remove-Module -Name $moduleName -Force -ErrorAction SilentlyContinue
        if ($exactVersion -ne "0.0.0.0")
        {
            Write-Host ('Uninstalling requested version v{1} from module {0}.' -f $moduleName, $exactVersion)
            Uninstall-Module -Name $moduleName -RequiredVersion $exactVersion -Force
        }
        else
        {
            Write-Host ('Uninstalling all versions from module {0}.' -f $moduleName)
            Uninstall-Module -Name $moduleName -AllVersions -Force
        }
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
    $requestedVersion = $minimalVersion
    [Version] $newestVersion = Get-PublishedModuleVersion $moduleName
    if (-Not $newestVersion)
    {
        Write-Warning "This does not looks like a module from Powershell Gallery"
        return
    }
    if ($exactVersion -ne "0.0.0.0")
    {
        $module = Get-Module -Name $moduleName -ListAvailable |`
            Where-Object { $_.Version -eq $exactVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                Where-Object { $_.Version -eq $exactVersion } | Sort-Object -Property Version | Select-Object -Last 1
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
            $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
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
        Import-Module -Name 'PowershellGet'
        if ((Get-PackageProvider -Name NuGet -Force).Version -lt '2.8.5.201')
        {
            Write-Warning "Installing nuget"
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
        }
        $regRep = Get-PSRepository -Name "PSGallery" -ErrorAction SilentlyContinue
        if (-Not $regRep)
        {
            Register-PSRepository -Name "PSGallery" -SourceLocation "https://www.powershellgallery.com/api/v2/" -PublishLocation "https://www.powershellgallery.com/api/v2/package/" -ScriptSourceLocation "https://www.powershellgallery.com/api/v2/items/psscript/" -ScriptPublishLocation "https://www.powershellgallery.com/api/v2/package/" -InstallationPolicy Trusted -PackageManagementProvider NuGet
        }
        else
        {
            if ($regRep.InstallationPolicy -ne "Trusted")
            {
	            Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
            }
        }
        $optionalArgs = New-Object -TypeName Hashtable
        $optionalArgs['RequiredVersion'] = $requestedVersion
        Write-Warning ('Installing/Updating module {0} to version [{1}] within scope of the current user.' -f $moduleName, $requestedVersion)
        #TODO Unload module
        Install-Module -Name $moduleName @optionalArgs -Scope CurrentUser -AllowClobber -Force -Verbose
        $module = Get-Module -Name $moduleName -ListAvailable |`
            Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
            if (-Not $module)
            {
                Write-Error "Not able to install the module!" -ErrorAction Continue
                exit
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
#Install-ModuleIfNotInstalled "Az"
#Install-ModuleIfNotInstalled -moduleName "Az" -exactVersion "4.6.0"
#Get-Module -Name Az
#Get-InstalledModule -Name Az

function Install-ScriptIfNotInstalled (
    [string] [Parameter(Mandatory = $true)] $scriptName,
    [Version] $minimalVersion = "0.0.0.0",
    [Version] $exactVersion = "0.0.0.0",
    [bool] $autoUpdate = $true
)
{
    if (-Not (Is-InternetConnected))
    {
        Write-Warning "No internet connection. Not able to check any script!"
        return
    }
    $requestedVersion = $minimalVersion
    [Version] $newestVersion = Get-PublishedModuleVersion $scriptName
    if (-Not $newestVersion)
    {
        Write-Warning "This does not looks like a script from Powershell Gallery"
        return
    }
    if ($exactVersion -ne "0.0.0.0")
    {
        $script = Get-InstalledScript -Name $scriptName -ErrorAction SilentlyContinue |`
            Where-Object { $_.Version -eq $exactVersion } | Sort-Object -Property Version | Select-Object -Last 1
        $autoUpdate = $false
        $requestedVersion = $exactVersion
    }
    else
    {
        $script = Get-InstalledScript -Name $scriptName -ErrorAction SilentlyContinue |`
            Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
        $requestedVersion = $newestVersion
    }
    if ($script)
    {
        Write-Host ('Module {0} is installed. Used:v{1} Requested:v{2}' -f $scriptName, $script.Version, $requestedVersion)
        if ((-Not $autoUpdate) -and ($newestVersion -gt $script.Version))
        {
            Write-Warning ("A newer version (v{0}) is available. Consider upgrading!" -f $script.Version)
        }
        if ($newestVersion -eq $script.Version)
        {
            $autoUpdate = $false
        }
    }
    else
    {
        Write-Host ('Module {0} not found with requested version v{1}. Installing now...' -f $scriptName, $requestedVersion)
        $autoUpdate = $true
    }
    if ($autoUpdate)
    {
        $instCmd = Get-Command Install-Script
        if (-Not $instCmd)
        {
            throw "Please install the powershell package management"
        }
        Import-Module -Name 'PowershellGet'
        if ((Get-PackageProvider -Name NuGet -Force).Version -lt '2.8.5.201')
        {
            Write-Warning "Installing nuget"
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
        }
        $regRep = Get-PSRepository -Name "PSGallery"
        if (-Not $regRep)
        {
	        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
        }
        $optionalArgs = New-Object -TypeName Hashtable
        $optionalArgs['RequiredVersion'] = $requestedVersion
        Write-Warning ('Installing/Updating script {0} to version [{1}] within scope of the current user.' -f $scriptName, $requestedVersion)
        #TODO Unload script
        Install-Script -Name $scriptName @optionalArgs -Scope CurrentUser -AcceptLicense -Force -Verbose
        $script = Get-InstalledScript -Name $scriptName -ErrorAction SilentlyContinue |`
        Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $script)
        {
            Write-Error "Not able to install the script!" -ErrorAction Continue
            exit
        }
    }
}
#Install-ScriptIfNotInstalled "Get-WindowsAutoPilotInfo"

<# LOGIN FUNCTIONS #>
function LogoutAllFrom-Az()
{
    Clear-AzContext -Scope Process -Force
    Clear-AzContext -Scope CurrentUser -Force
}
function Get-CustomersContext(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId)
{
    $context = $null
    if ($SubscriptionId)
    {
        $context = Get-AzContext -ListAvailable | where { $_.Name -like "*$SubscriptionId*$AlyaTenantId*" }
    }
    elseif ($SubscriptionName)
    {
        $context = Get-AzContext -ListAvailable | where { $_.Name -like "*$SubscriptionName*$AlyaTenantId*" }
    }
    else
    {
        $context = Get-AzContext -ListAvailable | where { $_.Name -like "*$AlyaTenantId*" }
        if ($context -and $context.Count -gt 1) { $context = $context[0] }
    }
    return $context
}
function LogoutFrom-Az(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId)
{
    $AlyaContext = Get-CustomersContext -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    if ($AlyaContext)
    {
        Logout-AzAccount -ContextName $AlyaContext.Name | Out-Null
        Remove-AzAccount -ContextName $AlyaContext.Name | Out-Null
        Remove-AzContext -InputObject $AlyaContext | Out-Null
        $AlyaContext = $null
    }
}
function LoginTo-Az(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId)
{
    Write-Host "Login to Az" -ForegroundColor $CommandInfo

    $AlyaContext = Get-CustomersContext -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    if ($AlyaContext)
    {
        if ($AlyaContext.Tenant.Id -ne $AlyaTenantId)
        {
            Logout-AzAccount -ContextName $AlyaContext.Name | Out-Null
            Remove-AzAccount -ContextName $AlyaContext.Name | Out-Null
            Remove-AzContext -InputObject $AlyaContext | Out-Null
            $AlyaContext = $null
        }
        else
        {
            $actContext = Get-AzContext
            if ($actContext.Name -ne $AlyaContext.Name)
            {
                Set-AzContext -Context $AlyaContext -Force | Out-Null
            }
            $chk = Get-AzADServicePrincipal -First 1 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if (-Not $chk)
            {
                Logout-AzAccount -ContextName $AlyaContext.Name | Out-Null
                Remove-AzAccount -ContextName $AlyaContext.Name | Out-Null
                Remove-AzContext -InputObject $AlyaContext | Out-Null
                $AlyaContext = $null
            }
        }
    }
    if (-Not $AlyaContext)
    {
        if ($SubscriptionId)
        {
            Connect-AzAccount -Tenant $AlyaTenantId -Subscription $SubscriptionId | Out-Null
        }
        if ($SubscriptionName)
        {
            Connect-AzAccount -Tenant $AlyaTenantId -Subscription $SubscriptionName | Out-Null
        }
        else
        {
            Connect-AzAccount -Tenant $AlyaTenantId | Out-Null
        }
        $AlyaContext = Get-CustomersContext -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    }
    else
    {
        Set-AzContext -Context $AlyaContext | Out-Null
    }
    if (-Not $AlyaContext)
    {
        Write-Error "Not logged in to Az!" -ErrorAction Continue
        Exit 1
    }
    $sameSub = $false
    if ($SubscriptionId)
    {
        $sameSub = ($AlyaContext.Subscription.Id -eq $SubscriptionId)
    }
    else
    {
        $sameSub = ($AlyaContext.Subscription.Name -eq $SubscriptionName)
    }
    if (-Not $sameSub)
    {
        Write-Host "Selecting subscription" -ForegroundColor $CommandInfo
        if ($SubscriptionId)
        {
            $sub = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop
            Set-AzContext -SubscriptionObject $sub  | Out-Null
        }
        elseif ($SubscriptionName)
        {
            $sub = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Stop | Out-Null
            Set-AzContext -SubscriptionObject $sub  | Out-Null
        }
    }
}
#LoginTo-Az -SubscriptionName $AlyaSubscriptionName


function Get-AzAccessToken(
    $audience = "74658136-14ec-4630-ad9b-26e160ff0fc6",
    [string] [Parameter(Mandatory = $false)] $SubscriptionName,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId)
{
    $AlyaContext = Get-CustomersContext -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($AlyaContext.Account, $AlyaContext.Environment, $AlyaContext.Tenant.Id, $null, "Never", $null, $audience)
    if (-Not $token -or -Not $token.AccessToken)
    {
        throw "Can't aquire an access token."
    }
    return $token.AccessToken
}

function Get-AdalAccessToken(
    [String] [Parameter(Mandatory = $false)] $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",
    [String] [Parameter(Mandatory = $false)] $redirectUri = "urn:ietf:wg:oauth:2.0:oob",
    [string] [Parameter(Mandatory = $false)] $SubscriptionName,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId)
{
	#TODO check first if type exists
    $module = Get-Module "AzureAdPreview"
    if (-Not $module)
    {
        throw "This function requires the AzureAdPreview module loaded"
    }
    $dll = $module.FileList | where { $_ -like "*Microsoft.IdentityModel.Clients.ActiveDirectory.dll" }
    Add-Type -Path $dll
    $resourceAppIdURI = "https://graph.microsoft.com"
    $authority = "https://login.microsoftonline.com/$AlyaTenantName"
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    $AlyaContext = Get-CustomersContext -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    $userUpn = $AlyaContext.Account.Id
    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($userUpn, "OptionalDisplayableId")
    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result
    return $authResult.AccessToken
}

function LoginTo-Ad(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId)
{
    Write-Host "Login to AzureAd" -ForegroundColor $CommandInfo
    try { Disconnect-AzureAD -ErrorAction SilentlyContinue } catch {}
    $AlyaContext = Get-CustomersContext -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    if (-Not $AlyaContext)
    {
        throw "Please login first to Az to minimize number of logins"
    }
    $graphToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($AlyaContext.Account, $AlyaContext.Environment, $AlyaContext.Tenant.Id, $null, "Never", $null, "https://graph.microsoft.com").AccessToken
    $aadToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($AlyaContext.Account, $AlyaContext.Environment, $AlyaContext.Tenant.Id, $null, "Never", $null, "https://graph.windows.net").AccessToken
    Connect-AzureAD -AadAccessToken $aadToken -MsAccessToken $graphToken -AccountId $AlyaContext.Account.Id -TenantId $AlyaContext.tenant.id -AzureEnvironmentName $AlyaContext.Environment.Name
    try { $TenantDetail = Get-AzureADTenantDetail -ErrorAction SilentlyContinue } catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {}
    if (-Not $TenantDetail)
    {
        Write-Error "Not logged in to AzureAd!" -ErrorAction Continue
        Exit 1
    }
}

function ReloginTo-Wvd(
    [String] [Parameter(Mandatory = $false)] $AppId,
    [SecureString] [Parameter(Mandatory = $false)] $SecPwd)
{
    throw "TODO: Kontext issues if using this function"
    Write-Host "Relogin to WVD" -ForegroundColor $CommandInfo
    if ($AppId)
    {
        $creds = New-Object System.Management.Automation.PSCredential($AppId, $SecPwd)
        Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $creds -ServicePrincipal -AadTenantId $AlyaTenantId
    }
    else
    {
        Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker
    }
}

function LoginTo-Wvd(
    [String] [Parameter(Mandatory = $false)] $AppId,
    [SecureString] [Parameter(Mandatory = $false)] $SecPwd)
{
    throw "TODO: Kontext issues if using this function"
    Write-Host "Login to WVD" -ForegroundColor $CommandInfo
    $Context = $null
    $Context = Get-RdsContext -DeploymentUrl $AlyaWvdRDBroker -ErrorAction SilentlyContinue
    if (-Not $Context)
    {
        if ($AppId)
        {
            $creds = New-Object System.Management.Automation.PSCredential($AppId, $SecPwd)
            Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $creds -ServicePrincipal -AadTenantId $AlyaTenantId
        }
        else
        {
            Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker
        }
    }
    else
    {
        if ($AppId -and $Context.UserName)
        {
            $creds = New-Object System.Management.Automation.PSCredential($AppId, $SecPwd)
            Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $creds -ServicePrincipal -AadTenantId $AlyaTenantId -ErrorAction Stop
        }
    }
    $Context = Get-RdsContext -ErrorAction SilentlyContinue
    if (-Not $Context)
    {
        Write-Error "Not logged in to WVD!" -ErrorAction Continue
        Exit 1
    }
}

function LoginTo-EXO([String[]]$commandsToLoad = $null)
{
    Write-Host "Login to EXO" -ForegroundColor $CommandInfo

    if ($commandsToLoad)
    {
        Connect-ExchangeOnline -ShowProgress $true -CommandName $commandsToLoad
    }
    else
    {
        Connect-ExchangeOnline -ShowProgress $true
    }
}

function LoginTo-IPPS()
{
    Write-Host "Login to IPPS" -ForegroundColor $CommandInfo
    $extRunspaces = Get-Runspace | where { $_.ConnectionInfo.ComputerName -like "*compliance.protection.outlook.com" }
    $actConnection = $extRunspaces | where { $_.RunspaceStateInfo.State -eq "Opened" }
    if (-Not $actConnection)
    {
        foreach($extRunspace in $extRunspaces)
        {
            $extRunspace.Dispose()
        }
        Connect-IPPSSession
    }
}

function DisconnectFrom-EXOandIPPS()
{
    Write-Host "Disconnecting from EXO and IPPS" -ForegroundColor $CommandInfo
    Disconnect-ExchangeOnline -Confirm:$false
    <#
    $extRunspaces = Get-Runspace | where { $_.ConnectionInfo.ComputerName -like "*compliance.protection.outlook.com" }
    foreach($extRunspace in $extRunspaces)
    {
        $extRunspace.Dispose()
    }
    Connect-IPPSSession
    #>
}

function LoginTo-Msol(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId)
{
    Write-Host "Login to AzureAd" -ForegroundColor $CommandInfo
    $AlyaContext = Get-CustomersContext -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    if (-Not $AlyaContext)
    {
        throw "Please login first to Az to minimize number of logins"
    }
    $graphToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($AlyaContext.Account, $AlyaContext.Environment, $AlyaContext.Tenant.Id, $null, "Never", $null, "https://graph.microsoft.com").AccessToken
    $aadToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($AlyaContext.Account, $AlyaContext.Environment, $AlyaContext.Tenant.Id, $null, "Never", $null, "https://graph.windows.net").AccessToken
    Connect-MsolService -AdGraphAccessToken $aadToken -MsGraphAccessToken $graphToken -AzureEnvironment $AlyaContext.Environment.Name
    try { $TenantDetail = Get-MsolCompanyInformation -ErrorAction SilentlyContinue } catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {}
    if (-Not $TenantDetail)
    {
        Write-Error "Not logged in to AzureAd!" -ErrorAction Continue
        Exit 1
    }
}

function LoginTo-MsolInteractive()
{
    Write-Host "Login to MSOL" -ForegroundColor $CommandInfo
    $TenantDetail = $null
    try { $TenantDetail = Get-MsolDomain -ErrorAction SilentlyContinue } catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {}
    if (-Not $TenantDetail)
    {
        Connect-MsolService
    }
    else
    {
        if (-Not ($TenantDetail.Name -contains $AlyaTenantName))
        {
            Connect-MsolService
        }
    }
    try { $TenantDetail = Get-MsolDomain -ErrorAction SilentlyContinue } catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {}
    if (-Not $TenantDetail)
    {
        Write-Error "Not logged in to Msol!" -ErrorAction Continue
        Exit 1
    }
}

function LoginTo-SPO()
{
    Write-Host "Login to SPO" -ForegroundColor $CommandInfo
    $Site = $null
    try { $Site = Get-SPOSite -Identity $AlyaSharePointAdminUrl -ErrorAction SilentlyContinue } catch {}
    if (-Not $Site)
    {
        Connect-SPOService -Url $AlyaSharePointAdminUrl
    }
    try { $Site = Get-SPOSite -Identity $AlyaSharePointAdminUrl -ErrorAction SilentlyContinue } catch {}
    if (-Not $Site)
    {
        Write-Error "Not logged in to SPO!" -ErrorAction Continue
        Exit 1
    }
}

function ReloginTo-PnP(
    [string] [Parameter(Mandatory = $true)] $Url,
    [string] [Parameter(Mandatory = $false)] $ClientId = $null,
    [string] [Parameter(Mandatory = $false)] $Thumbprint = $null
    )
{
    Write-Host "Relogin to SharePointPnPPowerShellOnline '$($Url)'" -ForegroundColor $CommandInfo
    try { $AlyaConnection = Disconnect-PnPOnline } catch {}
    $AlyaConnection = $null
    if ($ClientId -and $Thumbprint)
    {
        $AlyaConnection = Connect-PnPOnline -Url $Url -ReturnConnection -ClientId $ClientId -Thumbprint $Thumbprint -Tenant $AlyaTenantName -NoTelemetry
    }
    else
    {
        $AlyaConnection = Connect-PnPOnline -Url $Url -ReturnConnection -UseWebLogin -NoTelemetry
    }
    $AlyaContext = $null
    try { $AlyaContext = Get-PnPContext -ErrorAction SilentlyContinue } catch [System.InvalidOperationException] {}
    if (-Not $AlyaContext)
    {
        Write-Error "Not logged in to SharePointPnPPowerShellOnline!" -ErrorAction Continue
        Exit 1
    }
    return $AlyaConnection
}

function LoginTo-PnP(
    [string] [Parameter(Mandatory = $true)] $Url,
    [string] [Parameter(Mandatory = $false)] $ClientId = $null,
    [string] [Parameter(Mandatory = $false)] $Thumbprint = $null
    )
{
    Write-Host "Login to SharePointPnPPowerShellOnline '$($Url)'" -ForegroundColor $CommandInfo
    $AlyaConnection = $null
    try { $AlyaConnection = Get-PnPConnection -ErrorAction SilentlyContinue } catch [System.InvalidOperationException] {}
    if ($AlyaConnection -and $Url -ne "$($AlyaConnection.Url)")
    {
        try { $AlyaConnection = Disconnect-PnPOnline } catch {}
        $AlyaConnection = $null
    }
    if (-Not $AlyaConnection)
    {
        if ($ClientId -and $Thumbprint)
        {
            $AlyaConnection = Connect-PnPOnline -Url $Url -ReturnConnection -ClientId $ClientId -Thumbprint $Thumbprint -Tenant $AlyaTenantName -NoTelemetry
        }
        else
        {
            $AlyaConnection = Connect-PnPOnline -Url $Url -ReturnConnection -UseWebLogin -NoTelemetry
        }
    }
    $AlyaContext = $null
    try { $AlyaContext = Get-PnPContext -ErrorAction SilentlyContinue } catch [System.InvalidOperationException] {}
    if (-Not $AlyaContext)
    {
        Write-Error "Not logged in to SharePointPnPPowerShellOnline!" -ErrorAction Continue
        Exit 1
    }
    return $AlyaConnection
}

function LoginTo-PowerApps()
{
    Write-Host "Login to PowerApps" -ForegroundColor $CommandInfo
    $AlyaConnection = $null
    try { $AlyaConnection = Get-PowerAppConnection -ErrorAction SilentlyContinue } catch [System.Management.Automation.MethodInvocationException] {}
    if (-Not $AlyaConnection)
    {
        Add-PowerAppsAccount
    }
    $AlyaConnection = $null
    try { $AlyaConnection = Get-PowerAppConnection -ErrorAction SilentlyContinue } catch [System.Management.Automation.MethodInvocationException] {}
    if (-Not $AlyaConnection)
    {
        Write-Error "Not logged in to PowerApps!" -ErrorAction Continue
        Exit 1
    }
}

function LoginTo-AADRM()
{
    Write-Host "Login to AADRM" -ForegroundColor $CommandInfo
    $ServiceDetail = $null
    try { $ServiceDetail = Get-Aadrm -ErrorAction SilentlyContinue } catch [Exception] {}
    if (-Not $ServiceDetail)
    {
        Connect-AadrmService
    }
    try { $ServiceDetail = Get-Aadrm -ErrorAction SilentlyContinue } catch [Microsoft.RightsManagementServices.Online.Admin.PowerShell.AdminClientException] {}
    if (-Not $ServiceDetail)
    {
        Write-Error "Not logged in to AADRM!" -ErrorAction Continue
        Exit 1
    }
}

function LoginTo-AIP()
{
    Write-Host "Login to AIP" -ForegroundColor $CommandInfo
    $ServiceDetail = $null
    try { $ServiceDetail = Get-AipService -ErrorAction SilentlyContinue } catch [Microsoft.RightsManagementServices.Online.Admin.PowerShell.AdminClientException] {}
    if (-Not $ServiceDetail)
    {
        Connect-AipService
    }
    try { $ServiceDetail = Get-AipService -ErrorAction SilentlyContinue } catch [Microsoft.RightsManagementServices.Online.Admin.PowerShell.AdminClientException] {}
    if (-Not $ServiceDetail)
    {
        Write-Error "Not logged in to AIP!" -ErrorAction Continue
        Exit 1
    }
}

<# STRING FUNCTIONS #>
function Make-PascalCase(
    [string]$string)
{
    if ([string]::IsNullOrEmpty($string)) {return $string}
    return (Get-Culture).TextInfo.ToTitleCase($string)
}

<# MICROSOFT GRAPH FUNCTIONS #>
function Connect-MsGraphAsDelegated
{
    param (
        [string]$ClientID,
        [string]$ClientSecret
    )
    $Resource = "https://graph.microsoft.com"
    $RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    Add-Type -AssemblyName System.Web
    $ClientIDEncoded = [System.Web.HttpUtility]::UrlEncode($ClientID)
    $ClientSecretEncoded = [System.Web.HttpUtility]::UrlEncode($ClientSecret)
    $ResourceEncoded = [System.Web.HttpUtility]::UrlEncode($Resource)
    $RedirectUriEncoded = [System.Web.HttpUtility]::UrlEncode($RedirectUri)
    function Get-AuthCode {
        Add-Type -AssemblyName System.Windows.Forms
        $Form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width = 880; Height = 1280 }
        $Web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width = 840; Height = 1200; Url = ($Url -f ($Scope -join "%20")) }
        $DocComp = {
            $Global:TokenUri = $Web.Url.AbsoluteUri        
            if ($Global:TokenUri -match "error=[^&]*|code=[^&]*") { $Form.Close() }
        }
        $Web.ScriptErrorsSuppressed = $true
        $Web.Add_DocumentCompleted($DocComp)
        $Form.Controls.Add($Web)
        $Form.Add_Shown( { $Form.Activate() })
        $Form.ShowDialog() | Out-Null
        $QueryOutput = [System.Web.HttpUtility]::ParseQueryString($Web.Url.Query)
        $Output = @{ }

        foreach ($Key in $QueryOutput.Keys) {
            $Output["$Key"] = $QueryOutput[$Key]
        }
    }
    $Url = "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&redirect_uri=$RedirectUriEncoded&client_id=$ClientID&resource=$ResourceEncoded&prompt=admin_consent&scope=$ScopeEncoded"
    Get-AuthCode
    $Regex = '(?<=code=)(.*)(?=&)'
    $AuthCode = ($TokenUri | Select-string -pattern $Regex).Matches[0].Value
    $Body = "grant_type=authorization_code&redirect_uri=$RedirectUri&client_id=$ClientId&client_secret=$ClientSecretEncoded&code=$AuthCode&resource=$Resource"
    $TokenResponse = Invoke-RestMethod https://login.microsoftonline.com/common/oauth2/token -Method Post -ContentType "application/x-www-form-urlencoded" -Body $Body -ErrorAction "Stop"
    $TokenResponse.access_token
}

function Get-MsGraphToken
{
    return Get-AzAccessToken("https://graph.microsoft.com/")
}

function Get-MsGraph
{
    param (
        [parameter(Mandatory = $true)]
        $AccessToken,
        [parameter(Mandatory = $true)]
        $Uri
    )
    return Get-MsGraphCollection -AccessToken $AccessToken -Uri $Uri
}

function Get-MsGraphCollection
{
    param (
        [parameter(Mandatory = $true)]
        $Uri,
        [parameter(Mandatory = $false)]
        $AccessToken = $null,
        [parameter(Mandatory = $false)]
        $DontThrowIfStatusEquals = $null
    )
    if ($AccessToken) {
        $HeaderParams = @{
            'Content-Type'  = "application/json"
            'Authorization' = "Bearer $AccessToken"
        }
    }
    else {
        $HeaderParams = @{
            'Content-Type'  = "application/json"
        }
    }
    $QueryResults = @()
    $NextLink = $Uri
    do {
        $Results = ""
        $StatusCode = ""
        do {
            try {
                $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $NextLink -UseBasicParsing -Method "GET" -ContentType "application/json"
                $StatusCode = $Results.StatusCode
            } catch {
                $StatusCode = $_.Exception.Response.StatusCode.value__
                if ($StatusCode -eq 429) {
                    Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                    Start-Sleep -Seconds 45
                }
                else {
                    if (-Not $DontThrowIfStatusEquals -or $StatusCode -ne $DontThrowIfStatusEquals)
                    {
                        try { Write-Host ($_.Exception | ConvertTo-Json -Depth 2) -ForegroundColor $CommandError } catch {}
                        throw
                    }
                }
            }
        } while ($StatusCode -eq 429)
        if ($Results.value) {
            $QueryResults += $Results.value
        }
        if ($Results.'@odata.nextLink' -ne $NextLink)
        {
            $NextLink = $Results.'@odata.nextLink'
        }
    } while ($NextLink -ne $null)
    return $QueryResults
}

function Get-MsGraphObject
{
    param (
        [parameter(Mandatory = $true)]
        $Uri,
        [parameter(Mandatory = $false)]
        $AccessToken = $null,
        [parameter(Mandatory = $false)]
        $DontThrowIfStatusEquals = $null
    )
    if ($AccessToken) {
        $HeaderParams = @{
            'Content-Type'  = "application/json"
            'Authorization' = "Bearer $AccessToken"
        }
    }
    else {
        $HeaderParams = @{
            'Content-Type'  = "application/json"
        }
    }
    $Result = ""
    $StatusCode = ""
    do {
        try {
            $Result = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "GET" -ContentType "application/json"
            $StatusCode = $Results.StatusCode
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 429) {
                Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                Start-Sleep -Seconds 45
            }
            else {
                if (-Not $DontThrowIfStatusEquals -or $StatusCode -ne $DontThrowIfStatusEquals)
                {
                    try { Write-Host ($_.Exception | ConvertTo-Json -Depth 2) -ForegroundColor $CommandError } catch {}
                    throw
                }
            }
        }
    } while ($StatusCode -eq 429)
    return $Result
}

function Delete-MsGraphObject
{
    param (
        [parameter(Mandatory = $true)]
        $Uri,
        [parameter(Mandatory = $false)]
        $AccessToken = $null
    )
    if ($AccessToken) {
        $HeaderParams = @{
            'Content-Type'  = "application/json"
            'Authorization' = "Bearer $AccessToken"
        }
    }
    else {
        $HeaderParams = @{
            'Content-Type'  = "application/json"
        }
    }
    $Result = ""
    $StatusCode = ""
    do {
        try {
            $Result = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -Method "DELETE"
            $StatusCode = $Results.StatusCode
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 429) {
                Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                Start-Sleep -Seconds 45
            }
            else {
                try { Write-Host ($_.Exception | ConvertTo-Json -Depth 2) -ForegroundColor $CommandError } catch {}
                throw
            }
        }
    } while ($StatusCode -eq 429)
    return $Result
}

function Post-MsGraph
{
    param (
        [parameter(Mandatory = $true)]
        $Uri,
        [parameter(Mandatory = $false)]
        $AccessToken = $null,
        [parameter(Mandatory = $true)]
        $Body
    )
    if ($AccessToken) {
        $HeaderParams = @{
            'Content-Type'  = "application/json"
            'Authorization' = "Bearer $AccessToken"
        }
    }
    else {
        $HeaderParams = @{
            'Content-Type'  = "application/json"
        }
    }
    $Results = ""
    $StatusCode = ""
    do {
        try {
            $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "POST" -ContentType "application/json; charset=UTF-8" -Body $Body
            $StatusCode = $Results.StatusCode
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 429) {
                Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                Start-Sleep -Seconds 45
            }
            else {
                try { Write-Host ($_.Exception | ConvertTo-Json -Depth 2) -ForegroundColor $CommandError } catch {}
                throw
            }
        }
    } while ($StatusCode -eq 429)
    if ($Results.value) {
        $Results.value
    }
    else {
        $Results
    }
}

function Patch-MsGraph
{
    param (
        [parameter(Mandatory = $true)]
        $Uri,
        [parameter(Mandatory = $false)]
        $AccessToken = $null,
        [parameter(Mandatory = $true)]
        $Body
    )
    if ($AccessToken) {
        $HeaderParams = @{
            'Content-Type'  = "application/json"
            'Authorization' = "Bearer $AccessToken"
        }
    }
    else {
        $HeaderParams = @{
            'Content-Type'  = "application/json"
        }
    }
    $Results = ""
    $StatusCode = ""
    do {
        try {
            $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "PATCH" -ContentType "application/json; charset=UTF-8" -Body $Body
            $StatusCode = $Results.StatusCode
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 429) {
                Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                Start-Sleep -Seconds 45
            }
            else {
                try { Write-Host ($_.Exception | ConvertTo-Json -Depth 2) -ForegroundColor $CommandError } catch {}
                throw
            }
        }
    } while ($StatusCode -eq 429)
    if ($Results.value) {
        $Results.value
    }
    else {
        $Results
    }
}

<# NETWORKING FUNCTIONS #>
$AlyaWOctet = 16777216
$AlyaXOctet = 65536
$AlyaYOctet = 256
$AlyaZOctet = 1
function IP-toINT64()
{
    param ($ip)
    $octets = $ip.split(".")
    return [int64]([int64]$octets[0]*$AlyaWOctet +[int64]$octets[1]*$AlyaXOctet +[int64]$octets[2]*$AlyaYOctet +[int64]$octets[3])
}
function INT64-toIP()
{
    param ([int64]$int)
    return (([math]::truncate($int/$AlyaWOctet)).tostring()+"."+([math]::truncate(($int%$AlyaWOctet)/$AlyaXOctet)).tostring()+"."+([math]::truncate(($int%$AlyaXOctet)/$AlyaYOctet)).tostring()+"."+([math]::truncate($int%$AlyaYOctet)).tostring() )
}
function IP-toBinary()
{
    param ($ip)
    return [convert]::ToString((IP-toINT64 -ip $ip),2)
}
function CIDR-toMask()
{
    param ([int]$cidr)
    return ([Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2))))).IPAddressToString
}
function Mask-toCIDR()
{
    param ($mask)
    return (IP-toBinary -ip $mask).IndexOf("0")
}
function CIDR-toINT64 ([int]$sub)
{
    return IP-toINT64(CIDR-toMask($sub))
}
function Get-NetworkAddress()
{
    param ($ip, $mask, [int]$cidr)
    $ipaddr = [Net.IPAddress]::Parse($ip)
    if ($cidr)
    {
        $maskaddr = [Net.IPAddress]::Parse((CIDR-toMask -cidr $cidr))
    }
    else
    {
        $maskaddr = [Net.IPAddress]::Parse($mask)
    }
    return (new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)).IPAddressToString
}
function Get-BroadcastAddress()
{
    param ($ip, $netw, $mask, [int]$cidr)
    if (-not $ip -and -not $netw)
    {
        throw "At least ip or netw has to be provided"
    }
    if (-not $mask -and -not $cidr)
    {
        throw "At least mask or cidr has to be provided"
    }
    if ($ip)
    {
        $ipaddr = [Net.IPAddress]::Parse($ip)
        if ($cidr)
        {
            $networkaddr = [Net.IPAddress]::Parse((Get-NetworkAddress -ip $ip -cidr $cidr))
        }
        else
        {
            $networkaddr = [Net.IPAddress]::Parse((Get-NetworkAddress -ip $ip -mask $mask))
        }
    }
    else
    {
        $networkaddr = [Net.IPAddress]::Parse($netw)
    }
    if ($cidr)
    {
        $maskaddr = [Net.IPAddress]::Parse((CIDR-toMask -cidr $cidr))
    }
    else
    {
        $maskaddr = [Net.IPAddress]::Parse($mask)
    }
    return (new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))).IPAddressToString
}
function Get-GatewayNetworkAddress()
{
    param ($netw, $nwmask, [int]$nwcidr, $netwandcidr, $gwmask, [int]$gwcidr)
    if ($netwandcidr)
    {
        $parts = $netwandcidr.Split("/")
        $netw = $parts[0]
        $nwcidr = [int]$parts[1]
    }
    $ipi = IP-toINT64($netw)
    if ($nwmask)
    {
        $n = Mask-toCIDR -mask $nwmask
    }
    else
    {
        $n = $nwcidr
    }
    if ($gwmask)
    {
        $g = Mask-toCIDR -mask $gwmask
    }
    else
    {
        $g = $gwcidr
    }
    for ($i = $n + 1; $i -lt $g + 1; $i++) 
    { 
        $ipi = $ipi + [math]::pow(2, 32 - $i) 
    }
    INT64-toIP($ipi)
}
function Split-NetworkAddressWithGateway()
{
    param ($netw, $nwmask, [int]$nwcidr, $netwandcidr, $gwmask, [int]$gwcidr, [int]$splitcidr)
    if ($netwandcidr)
    {
        $parts = $netwandcidr.Split("/")
        $netw = $parts[0]
        $nwcidr = [int]$parts[1]
    }
    if ($nwmask -and -not $nwcidr)
    {
        $nwcidr = Mask-toCIDR -mask $nwmask
    }
    if ($gwmask -and -not $gwcidr)
    {
        $gwcidr = Mask-toCIDR -mask $gwmask
    }
    $cidr = $splitcidr
    $StartIp = IP-toINT64($netw)
    $GwIp = IP-toINT64((Get-GatewayNetworkAddress -netw $netw -nwcidr $nwcidr -gwcidr $gwcidr))
    $NextIp = $StartIp
    $networks = @()
    $networks += (INT64-toIP -int $NextIp) + "/$cidr"
    while($true)
    {
        $NextIp = $NextIp + [math]::pow(2, 32 - $cidr)
        if ($NextIp -ge $GwIp) { break }
        if ((IP-toINT64(Get-BroadcastAddress -netw $NextIp -cidr $cidr)) -gt $GwIp)
        { 
            $NextIp = $NextIp - [math]::pow(2, 32 - ($cidr + 1))
            $cidr = $cidr + 1
            continue
        }
        $networks += (INT64-toIP -int $NextIp) + "/$cidr"
    }
    $networks += (INT64-toIP -int $GwIp) + "/$gwcidr"
    return $networks
}
function Split-NetworkAddressWithoutGateway()
{
    param ($netw, $nwmask, [int]$nwcidr, $netwandcidr, [int]$splitcidr)
    if ($netwandcidr)
    {
        $parts = $netwandcidr.Split("/")
        $netw = $parts[0]
        $nwcidr = [int]$parts[1]
    }
    if ($nwmask -and -not $nwcidr)
    {
        $nwcidr = Mask-toCIDR -mask $nwmask
    }
    $cidr = $splitcidr
    $StartIp = IP-toINT64($netw)
    $GwIp = IP-toINT64((Get-BroadcastAddress -netw $netw -cidr $nwcidr))
    $NextIp = $StartIp
    $networks = @()
    $networks += (INT64-toIP -int $NextIp) + "/$cidr"
    while($true)
    {
        $NextIp = $NextIp + [math]::pow(2, 32 - $cidr)
        if ($NextIp -ge $GwIp) { break }
        if ((IP-toINT64(Get-BroadcastAddress -netw $NextIp -cidr $cidr)) -gt $GwIp)
        { 
            $NextIp = $NextIp - [math]::pow(2, 32 - ($cidr + 1))
            $cidr = $cidr + 1
            continue
        }
        $networks += (INT64-toIP -int $NextIp) + "/$cidr"
    }
    return $networks
}
function CheckSubnetInSubnet ([string]$addr1, [string]$addr2)
{
    $network1, [int]$subnetlen1 = $addr1.Split('/')
    $network2, [int]$subnetlen2 = $addr2.Split('/')
    [int64] $unetwork1 = IP-toINT64 $network1
    [int64] $unetwork2 = IP-toINT64 $network2
    if($subnetlen1 -lt 32)
	{
        [int64] $mask1 = CIDR-toINT64 $subnetlen1
    }
    if($subnetlen2 -lt 32)
	{
        [int64] $mask2 = CIDR-toINT64 $subnetlen2
    }
    if($mask1 -and $mask2){
        if($mask1 -lt $mask2){
            return $False
        }else{
            return CheckNetworkToSubnet $unetwork2 $mask2 $unetwork1
        }
    }ElseIf($mask1){
        return CheckSubnetToNetwork $unetwork1 $mask1 $unetwork2
    }ElseIf($mask2){
        return CheckNetworkToSubnet $unetwork2 $mask2 $unetwork1
    }Else{
        CheckNetworkToNetwork $unetwork1 $unetwork2
    }
}
#CheckSubnetInSubnet "172.16.72.0/24" "172.16.0.0/16" true
#CheckSubnetInSubnet "172.16.72.1" "172.16.0.0/16" true
#CheckSubnetInSubnet "172.16.0.0/28" "172.16.72.0/24" false
#CheckSubnetInSubnet "172.16.72.0/24" "172.16.0.0/28" false
#CheckSubnetInSubnet "172.16.72.0" "172.16.0.0/28" fals
function CheckNetworkToSubnet ([int64]$un2, [int64]$ma2, [int64]$un1)
{
    $ReturnArray = "" | Select-Object -Property Condition,Direction

    if($un2 -eq ($ma2 -band $un1)){
        return $True
    }else{
        return $False
    }
}
function CheckSubnetToNetwork ([int64]$un1, [int64]$ma1, [int64]$un2)
{
    $ReturnArray = "" | Select-Object -Property Condition,Direction

    if($un1 -eq ($ma1 -band $un2)){
        return $False
    }else{
        return $True
    }
}
function CheckNetworkToNetwork ([int64]$un1, [int64]$un2)
{
    $ReturnArray = "" | Select-Object -Property Condition,Direction

    if($un1 -eq $un2){
        return $True
    }else{
        return $False
    }
}

# Checking custom properties
if ($AlyaNamingPrefix.Length -gt 8)
{
    Write-Error "Max 8 chars allowed for AlyaNamingPrefix '$($AlyaNamingPrefix)' which is $($AlyaNamingPrefix.Length) long" -ErrorAction Continue
    exit
}
if ($AlyaNamingPrefixTest.Length -gt 8)
{
    Write-Error "Max 8 chars allowed for AlyaNamingPrefixTest '$($AlyaNamingPrefixTest)' which is $($AlyaNamingPrefixTest.Length) long" -ErrorAction Continue
    exit
}
if ($AlyaAzureNetwork -and $AlyaProdNetwork -and $AlyaAzureNetwork -ne "PleaseSpecify" -and $AlyaProdNetwork -ne "PleaseSpecify")
{
    if (-Not (CheckSubnetInSubnet $AlyaProdNetwork $AlyaAzureNetwork))
    {
        Write-Error "AlyaProdNetwork '$($AlyaProdNetwork)' is not within AlyaAzureNetwork '$($AlyaAzureNetwork)'" -ErrorAction Continue
        exit
    }
}
if ($AlyaAzureNetwork -and $AlyaTestNetwork -and $AlyaAzureNetwork -ne "PleaseSpecify" -and $AlyaTestNetwork -ne "PleaseSpecify")
{
    if (-Not (CheckSubnetInSubnet $AlyaTestNetwork $AlyaAzureNetwork))
    {
        Write-Error "AlyaTestNetwork '$($AlyaTestNetwork)' is not within AlyaAzureNetwork '$($AlyaAzureNetwork)'" -ErrorAction Continue
        exit
    }
}
