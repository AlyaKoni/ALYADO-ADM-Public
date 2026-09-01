#Requires -Version 2.0

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
    12.04.2021 Konrad Brunner       Added DevOps login
    12.07.2021 Konrad Brunner       Added own module path
    04.10.2021 Konrad Brunner       Proxy default credentials
    04.08.2022 Konrad Brunner       Added simple password generator
    18.08.2022 Konrad Brunner       Select-Item
    18.10.2022 Konrad Brunner       LoginTo-MgGraph
    20.12.2022 Konrad Brunner       LoginTo-DataGateway
    22.03.2023 Konrad Brunner       Check for existing PowerShell Modules in default module path
    10.04.2023 Konrad Brunner       Reuse connection in PnP Powershell
	20.04.2023 Konrad Brunner		Added Mime Mapping function for PS7
	14.05.2023 Konrad Brunner		Fixed package management update
	12.06.2023 Konrad Brunner		Scripts path
	22.07.2023 Konrad Brunner		Added non Public Cloud Environment Support
    16.10.2023 Konrad Brunner       Install-ModuleIfNotInstalled new param: doNotLoadModules
    01.05.2024 Konrad Brunner       Supporting MAC
    13.09.2024 Konrad Brunner       AlyaPnPAppId
    04.12.2024 Konrad Brunner       New EXO login behaviour
    11.07.2025 Konrad Brunner       Added Graph DevOps login
    30.09.2025 Konrad Brunner       Added Microsoft.VSCode_profile.ps1
    03.10.2025 Konrad Brunner       New AIP app login
    19.10.2025 Konrad Brunner       LoginTo-MgGraph with clientid and cert
    06.01.2026 Konrad Brunner       LoginTo-Entra
    06.02.2026 Konrad Brunner       Added powershell documentation
    21.05.2026 Konrad Brunner       Management app authentication
    30.08.2026 Konrad Brunner       Added Make-JsonGitReady
    30.08.2026 Konrad Brunner       Make-JsonGitReady strips volatile attributes; appregistrationSummary: DateTime columns removed

#>

<#
.SYNOPSIS
Initializes and configures the Alya PowerShell environment, setting global variables, paths, modules, and helper functions.

.DESCRIPTION
The 01_ConfigureEnv.ps1 script bootstraps the Alya environment by defining color schemes, root paths, PowerShell behaviors, proxy settings, environment variables, and module paths. It loads custom and local configuration files, sets up logging and temporary directories, and initializes PowerShell settings. The script also defines comprehensive helper functions for configuration persistence, package management, module management, authentication (Azure, Graph, Teams, SharePoint, PowerApps, Exchange, etc.), networking utilities, string replacements, and browser automation using Selenium. Its purpose is to prepare a consistent execution environment across different systems and scenarios, including local development and CI/CD pipelines.

.INPUTS
None. The script does not accept piped input.

.OUTPUTS
None. The script primarily sets up environment variables and functions; it does not return objects.

.EXAMPLE
PS> .\01_ConfigureEnv.ps1

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
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

<# ROOT PATHS #>
$AlyaAzureEnvironment = "AzureCloud"
$AlyaPnpEnvironment = "Production"
$AlyaGraphEnvironment = "Global"
$AlyaExchangeEnvironment = "O365Default"
$AlyaSharePointEnvironment = "Default"
$AlyaTeamsEnvironment = $null
$AlyaGraphAppId = $null
$AlyaPnPAppId = $null
$AlyaGraphEndpoint = "https://graph.microsoft.com"
$AlyaADGraphEndpoint = "https://graph.windows.net"
$AlyaOpenIDEndpoint = "https://login.microsoftonline.com"
$AlyaLoginEndpoint = "https://login.microsoftonline.com"
$AlyaM365AdminPortalRoot = "https://admin.microsoft.com/AdminPortal"
$AlyaRoot = "$PSScriptRoot"
$AlyaLogs = "$AlyaRoot\_logs"
$AlyaTemp = "$AlyaRoot\_temp"
$AlyaLocal = "$AlyaRoot\_local"
$AlyaData = "$AlyaRoot\data"
$AlyaScripts = "$AlyaRoot\scripts"
$AlyaSolutions = "$AlyaRoot\solutions"
$AlyaTools = "$AlyaRoot\tools"
$AlyaEnvSwitch = ""
$AlyaModuleVersionOverwrite = @( <#@{Name="PnP.PowerShell";Version="2.4.0"}#> )
$AlyaPackageVersionOverwrite = @( <#@{Name="Selenium.WebDriver";Version="4.10.0"}#> )
$AlyaWamEnabled = $false

if (-Not (Test-Path $AlyaTemp))
{
    $null = New-Item -Path $AlyaTemp -ItemType "Directory" -Force
}

# Switching env if required
if ((Test-Path $AlyaLocal\EnvSwitch.ps1))
{
    Write-Host "Switching environment" -ForegroundColor $MenuColor
    . $AlyaLocal\EnvSwitch.ps1
    Write-Host " to $AlyaEnvSwitch" -ForegroundColor $MenuColor
}

# Loading custom configuration
Write-Host "Loading configuration" -ForegroundColor $CommandInfo
if ((Test-Path $PSScriptRoot\data\ConfigureEnv.ps1))
{
    . $PSScriptRoot\data\ConfigureEnv$AlyaEnvSwitch.ps1
}

<# POWERSHELL #>
$ExecutionContext.SessionState.LanguageMode = "FullLanguage"
$Global:ErrorActionPreference = "Stop"
$Global:ProgressPreference = "SilentlyContinue"
$AlyaIsPsCore = ($PSVersionTable).PSEdition -eq "Core"
$AlyaIsPsUnix = ($PSVersionTable).Platform -eq "Unix"
$AlyaUtf8Encoding = "UTF8"
if ($AlyaIsPsCore) { $AlyaUtf8Encoding = "utf8BOM" }
$AlyaPowerShellExe = "powershell.exe"
if ($AlyaIsPsCore) { $AlyaPowerShellExe = "pwsh.exe" }
$AlyaPathSep = ";"
if ($AlyaIsPsUnix) {
    $AlyaPowerShellExe = "pwsh"
    $AlyaPathSep = ":"
}
$PSDefaultParameterValues["out-file:width"] = 2000
$PSSessionConfigurationName = "PowerShell.7"
$AlyaIsDevOpsPipeline = $false
if (-Not [string]::IsNullOrEmpty($env:AZURE_DEVOPS_CACHE_DIR))
{
    $AlyaIsDevOpsPipeline = $true
}

<# TLS Connections #>
[Net.ServicePointManager]::SecurityProtocol = @([Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13)
$proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

<# OTHER PATHS #>
if ($AlyaIsPsUnix) { 
    $AlyaDefaultModulePath = Join-Path ([Environment]::GetFolderPath("UserProfile")) ".local/share/windowspowershell/Modules"
    $AlyaDefaultModulePathCore = Join-Path ([Environment]::GetFolderPath("UserProfile")) ".local/share/powershell/Modules"
    $AlyaDefaultScriptPath = Join-Path ([Environment]::GetFolderPath("UserProfile")) ".local/share/windowspowershell/Scripts"
    $AlyaDefaultScriptPathCore = Join-Path ([Environment]::GetFolderPath("UserProfile")) ".local/share/powershell/Scripts"
} else {
    $AlyaDefaultModulePath = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "WindowsPowerShell\Modules"
    $AlyaDefaultModulePathCore = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "PowerShell\Modules"
    $AlyaDefaultScriptPath = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "WindowsPowerShell\Scripts"
    $AlyaDefaultScriptPathCore = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "PowerShell\Scripts"
}
if (-Not $AlyaModulePath) {
    if ($AlyaIsPsCore) {
        $AlyaModulePath = $AlyaDefaultModulePathCore
    } else {
        $AlyaModulePath = $AlyaDefaultModulePath
    }
}
if (-Not $AlyaScriptPath) {
    if ($AlyaIsPsCore) {
        $AlyaScriptPath = $AlyaDefaultScriptPathCore
    } else {
        $AlyaScriptPath = $AlyaDefaultScriptPath
    }
}
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
    if (-Not $env:PSModulePath.StartsWith("$($AlyaTools)\WindowsPowerShell\Modules"))
    {
        $env:PSModulePath = "$($AlyaTools)\WindowsPowerShell\Modules$AlyaPathSep"+$env:PSModulePath
    }
}
if ((Test-Path "$($AlyaTools)\WindowsPowerShell\Scripts") -and `
     -Not $env:PATH.Contains("$($AlyaTools)\WindowsPowerShell\Scripts"))
{
    Write-Host "Adding tools\WindowsPowerShell\Scripts to Path"
    if (-Not $env:PATH.StartsWith("$($AlyaTools)\WindowsPowerShell\Scripts"))
    {
        $env:PATH = "$($AlyaTools)\WindowsPowerShell\Scripts$AlyaPathSep"+$env:PATH
    }
}

# Loading local custom configuration
$AlyaPnpConnectionsDefined = Get-Variable -Name "AlyaPnpConnections" -Scope Global -ErrorAction SilentlyContinue
if (-Not $AlyaPnpConnectionsDefined) { $Global:AlyaPnpConnections = @() }
if ((Test-Path $AlyaLocal\ConfigureEnv.ps1))
{
    Write-Host "Loading local configuration" -ForegroundColor $CommandInfo
    . $AlyaLocal\ConfigureEnv.ps1
}
if ($AlyaModulePath -ne $AlyaDefaultModulePath -and $AlyaModulePath -ne $AlyaDefaultModulePathCore)
{
    $modDIrs = $null
    if ((Test-Path $AlyaDefaultModulePath) -and -not $Global:AlyaDefaultModulePathWarningDone)
    {
        $modDIrs = Get-ChildItem -Path $AlyaDefaultModulePath -Directory
    }
    if ((Test-Path $AlyaDefaultModulePathCore) -and -not $Global:AlyaDefaultModulePathWarningDone)
    {
        $modDIrs = Get-ChildItem -Path $AlyaDefaultModulePathCore -Directory
    }
    if ($modDIrs -and $modDIrs.Count -gt 0)
    {
        $Global:AlyaDefaultModulePathWarningDone = $true
        Write-Host "You have specified the variable AlyaModulePath and modules are present in the default module path:"  -ForegroundColor Red
        Write-Host "$AlyaDefaultModulePath"  -ForegroundColor Red
        Write-Host "$AlyaDefaultModulePathCore"  -ForegroundColor Red
        Write-Host "This can lead to unexpected behaviour!"  -ForegroundColor Red
        Write-Host "We suggest you rename default module path to prevent from issues and rerun this powershell session."  -ForegroundColor Red
    }
    if (-Not (Test-Path $AlyaModulePath))
    {
        New-Item -Path $AlyaModulePath -ItemType Directory -Force
    }
    if (-Not $env:PSModulePath.Contains("$($AlyaModulePath)"))
    {
        $env:PSModulePath = "$($AlyaModulePath)$AlyaPathSep"+$env:PSModulePath
    }
}
if ($AlyaScriptPath -ne $AlyaDefaultScriptPath -and $AlyaScriptPath -ne $AlyaDefaultScriptPathCore)
{
    if (-Not (Test-Path $AlyaScriptPath))
    {
        New-Item -Path $AlyaScriptPath -ItemType Directory -Force
    }
}
if ($AlyaIsPsCore)
{
    if (-Not $env:PATH.Contains("$($AlyaDefaultScriptPathCore)"))
    {
        $env:PATH = "$($AlyaDefaultScriptPathCore)$AlyaPathSep$($env:PATH)"
    }
}
if (-Not $env:PATH.Contains("$($AlyaScriptPath)"))
{
    $env:PATH = "$($AlyaScriptPath)$AlyaPathSep$($env:PATH)"
}

if ($AlyaIsPsUnix) { 
    $vsCodeProfileDir = Join-Path ([Environment]::GetFolderPath("UserProfile")) ".local/share/powershell"
} else {
    $vsCodeProfileDir = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "PowerShell"
}
$vsCodeProfileFile = Join-Path $vsCodeProfileDir "Microsoft.VSCode_profile.ps1"
try
{
    if (-Not (Test-Path $vsCodeProfileDir))
    {
        New-Item -Path $vsCodeProfileDir -ItemType Directory -Force
    }
    @"
`$Env:PSModulePath = "$($AlyaModulePath);`$(`$Env:PSModulePath)"
`$Env:Path = "$($AlyaScriptPath);`$(`$Env:Path)"
"@ | Set-Content -Path $vsCodeProfileFile -Force
}
catch
{
    Write-Warning $_.Exception.Message
}

<# CLIENT SETTINGS #>
$AlyaOfficeToolsOnTaskbar = @("OUTLOOK.EXE", "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE") #WINPROJ.EXE, VISIO.EXE, ONENOTE.EXE, MSPUB.EXE, MSACCESS.EXE

<# URLS #>
$AlyaGitDownload = "https://git-scm.com/install/windows"
$AlyaDeployToolDownload = "https://www.microsoft.com/en-us/download/details.aspx?id=49117"
$AlyaAipClientDownload = "https://www.microsoft.com/en-us/download/details.aspx?id=53018"
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
    $Global:AlyaLocalConfig = Get-Content -Path "$AlyaLocal\LocalConfig.json" -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json
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
    $Global:AlyaGlobalConfig = Get-Content -Path "$AlyaData\GlobalConfig.json" -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json
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
$AlyaTimeString = (Get-Date).ToString("yyyyMMddHHmmssfff")

<# MISC HELPER FUNCTIONS #>

function MakeFsCompatiblePath()
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [string]$path,
        [bool]$IsOneDriveDir = $true
    )
    $npath = $path
    $hadDisk = $false
    if ($npath.Substring(1,1) -eq ":") { $hadDisk = $true }
    $npath = $npath.Replace("<", "_"). `
       Replace(">", "_"). `
       Replace(":", "_"). `
       Replace("`"", "_"). `
       Replace("'", "_"). `
       Replace("|", "_"). `
       Replace("?", "_"). `
       Replace("*", "_")

    if ($AlyaIsPsUnix)
    {
        $npath = $npath.Replace("\", "_")
    }
    else
    {
        $npath = $npath.Replace("/", "_")
    }

    if ($hadDisk) { $npath = $npath.Remove(1,1).Insert(1,":") }

    $parent = Split-Path -Path $npath -Parent
    $leaf = Split-Path -Path $npath -Leaf

    $maxDirLen = 248
    $maxFileLen = 260
    if ($IsOneDriveDir)
    { 
        $maxDirLen = 236
        $maxFileLen = 248
    }

    if ($parent.Length -gt $maxDirLen)
    {
        throw "Directory too long. Max $maxDirLen charcters allowed if OneDrive=$IsOneDriveDir"
    }
    if ($npath.Length -gt $maxFileLen)
    {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
        $ext = [System.IO.Path]::GetExtension($leaf)
        $maxLength = $maxFileLen - $parent.Length - $ext.Length - 1
        $npath = Join-Path $parent ($name.Substring(0,$maxLength)+$ext)
    }

    if ($npath.Length -ne $path.Length)
    {
        Write-Warning "Path shortened (OneDrive=$IsOneDriveDir)"
        Write-Warning "  from $path"
        Write-Warning "  to   $npath"
    }

    return $npath
}

function IIf($If, $Then, $Else) {
    If ($If -IsNot "Boolean") {$_ = $If}
    If ($If) {If ($Then -is "ScriptBlock") {&$Then} Else {$Then}}
    Else {If ($Else -is "ScriptBlock") {&$Else} Else {$Else}}
}

function Get-ActualLoadedLibraries ()
{
    [System.AppDomain]::CurrentDomain.GetAssemblies() | Select-Object -Property FullName,Location | Sort-Object -Property FullName | Format-List
    [System.AppDomain]::CurrentDomain.GetAssemblies() | Select-Object -Property FullName,Location | Sort-Object -Property FullName | Format-Table
}

function Set-AllCallsToVerbose
{
    $PSDefaultParameterValues = @{"*:Verbose"=$True}
}

function Get-PowerShellDefaultEncoding
{
    [psobject].Assembly.GetTypes() | Where-Object { $_.Name -eq 'ClrFacade'} |
    ForEach-Object {
      $_.GetMethod('GetDefaultEncoding', [System.Reflection.BindingFlags]'nonpublic,static').Invoke($null, @())
    }
}

function Get-PowerShellEncodingIfNoBom
{
    $badBytes = [byte[]]@(0xC3, 0x80)
    $utf8Str = [System.Text.Encoding]::UTF8.GetString($badBytes)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes('Write-Output "') + [byte[]]@(0xC3, 0x80) + [byte[]]@(0x22)
    $path = Join-Path ([System.IO.Path]::GetTempPath()) 'encodingtest.ps1'
    try
    {
        [System.IO.File]::WriteAllBytes($path, $bytes)
        switch (& $path)
        {
            $utf8Str
            {
                return 'UTF-8'
                break
            }
            default
            {
                return 'Windows-1252'
                break
            }
        }
    }
    finally
    {
        Remove-Item $path
    }
}

function Invoke-WebRequestIndep ()
{
    Param(
        [Switch]$UseBasicParsing,
        [System.Uri]$Uri,
        [System.Version]$HttpVersion,
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [System.String]$SessionVariable,
        [Switch]$AllowUnencryptedAuthentication,
        [Object]$Authentication,
        [System.Management.Automation.PSCredential]$Credential,
        [Switch]$UseDefaultCredentials,
        [System.String]$CertificateThumbprint,
        [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,
        [Switch]$SkipCertificateCheck,
        [Switch]$SkipHeaderValidation,
        [Object]$SslProtocol,
        [System.Security.SecureString]$Token,
        [System.String]$UserAgent,
        [Switch]$DisableKeepAlive,
        [System.Int32]$TimeoutSec,
        [System.Collections.IDictionary]$Headers,
        [System.Int32]$MaximumRedirection,
        [System.Int32]$MaximumRetryCount,
        [System.Int32]$RetryIntervalSec,
        [Object]$Method,
        [System.String]$CustomMethod,
        [Switch]$NoProxy,
        [System.Uri]$Proxy,
        [System.Management.Automation.PSCredential]$ProxyCredential,
        [Switch]$ProxyUseDefaultCredentials,
        [System.Object]$Body,
        [System.Collections.IDictionary]$Form,
        [System.String]$ContentType,
        [System.String]$TransferEncoding,
        [System.String]$InFile,
        [System.String]$OutFile,
        [Switch]$AllowInsecureRedirect,
        [Switch]$PassThru,
        [Switch]$Resume,
        [Switch]$SkipHttpErrorCheck,
        [Object]$Verbose,
        [Object]$Debug,
        [Object]$ErrorAction,
        [Object]$WarningAction,
        [Object]$InformationAction,
        [Object]$ErrorVariable,
        [Object]$WarningVariable,
        [Object]$InformationVariable,
        [Object]$OutVariable,
        [Object]$OutBuffer,
        [Object]$PipelineVariable
    )
    $parms = @{}
    $pkeys = $PSBoundParameters.Keys
    if ($AlyaIsPsCore) {
        if ($pkeys -contains "SkipHttpErrorCheck") { $parms["SkipHttpErrorCheck"] = $null }
        if ($pkeys -contains "HttpVersion") { $parms["HttpVersion"] = $HttpVersion }
        if ($pkeys -contains "AllowUnencryptedAuthentication") { $parms["AllowUnencryptedAuthentication"] = $null }
        if ($pkeys -contains "Authentication") { $parms["Authentication"] = $Authentication }
        if ($pkeys -contains "SkipCertificateCheck") { $parms["SkipCertificateCheck"] = $null }
        if ($pkeys -contains "SslProtocol") { $parms["SslProtocol"] = $SslProtocol }
        if ($pkeys -contains "Token") { $parms["Token"] = $Token }
        if ($pkeys -contains "MaximumRetryCount") { $parms["MaximumRetryCount"] = $MaximumRetryCount }
        if ($pkeys -contains "RetryIntervalSec") { $parms["RetryIntervalSec"] = $RetryIntervalSec }
        if ($pkeys -contains "CustomMethod") { $parms["CustomMethod"] = $CustomMethod }
        if ($pkeys -contains "NoProxy") { $parms["NoProxy"] = $null }
        if ($pkeys -contains "Form") { $parms["Form"] = $Form }
        if ($pkeys -contains "Resume") { $parms["Resume"] = $null }
        if ($pkeys -contains "SkipHeaderValidation") { $parms["SkipHeaderValidation"] = $null }
        if ($pkeys -contains "PreserveAuthorizationOnRedirect") { $parms["PreserveAuthorizationOnRedirect"] = $null }
        if ($pkeys -contains "AllowInsecureRedirect") { $parms["AllowInsecureRedirect"] = $null }
    }
    else
    {
        if ($pkeys -notcontains "UseBasicParsing") { $parms["UseBasicParsing"] = $null }
    }
    if ($pkeys -contains "UseBasicParsing") { $parms["UseBasicParsing"] = $null }
    if ($pkeys -contains "Uri") { $parms["Uri"] = $Uri }
    if ($pkeys -contains "WebSession") { $parms["WebSession"] = $WebSession }
    if ($pkeys -contains "SessionVariable") { $parms["SessionVariable"] = $SessionVariable }
    if ($pkeys -contains "Credential") { $parms["Credential"] = $Credential }
    if ($pkeys -contains "UseDefaultCredentials") { $parms["UseDefaultCredentials"] = $null }
    if ($pkeys -contains "CertificateThumbprint") { $parms["CertificateThumbprint"] = $CertificateThumbprint }
    if ($pkeys -contains "Certificate") { $parms["Certificate"] = $Certificate }
    if ($pkeys -contains "UserAgent") { $parms["UserAgent"] = $UserAgent }
    if ($pkeys -contains "DisableKeepAlive") { $parms["DisableKeepAlive"] = $null }
    if ($pkeys -contains "TimeoutSec") { $parms["TimeoutSec"] = $TimeoutSec }
    if ($pkeys -contains "Headers") { $parms["Headers"] = $Headers }
    if ($pkeys -contains "MaximumRedirection") { $parms["MaximumRedirection"] = $MaximumRedirection }
    if ($pkeys -contains "Method") { $parms["Method"] = $Method }
    if ($pkeys -contains "Proxy") { $parms["Proxy"] = $Proxy }
    if ($pkeys -contains "ProxyCredential") { $parms["ProxyCredential"] = $ProxyCredential }
    if ($pkeys -contains "ProxyUseDefaultCredentials") { $parms["ProxyUseDefaultCredentials"] = $null }
    if ($pkeys -contains "Body") { $parms["Body"] = $Body }
    if ($pkeys -contains "ContentType") { $parms["ContentType"] = $ContentType }
    if ($pkeys -contains "TransferEncoding") { $parms["TransferEncoding"] = $TransferEncoding }
    if ($pkeys -contains "InFile") { $parms["InFile"] = $InFile }
    if ($pkeys -contains "OutFile") { $parms["OutFile"] = $OutFile }
    if ($pkeys -contains "PassThru") { $parms["PassThru"] = $null }
    if ($pkeys -contains "Verbose") { $parms["Verbose"] = $null }
    if ($pkeys -contains "Debug") { $parms["Debug"] = $null }
    if ($pkeys -contains "ErrorAction") { $parms["ErrorAction"] = $ErrorAction }
    if ($pkeys -contains "WarningAction") { $parms["WarningAction"] = $WarningAction }
    if ($pkeys -contains "InformationAction") { $parms["InformationAction"] = $InformationAction }
    if ($pkeys -contains "ErrorVariable") { $parms["ErrorVariable"] = $ErrorVariable }
    if ($pkeys -contains "WarningVariable") { $parms["WarningVariable"] = $WarningVariable }
    if ($pkeys -contains "InformationVariable") { $parms["InformationVariable"] = $InformationVariable }
    if ($pkeys -contains "OutVariable") { $parms["OutVariable"] = $OutVariable }
    if ($pkeys -contains "OutBuffer") { $parms["OutBuffer"] = $OutBuffer }
    if ($pkeys -contains "PipelineVariable") { $parms["PipelineVariable"] = $PipelineVariable }
    return Invoke-WebRequest @parms
}

function Get-MimeType()
{
    [CmdletBinding()]
    Param(
        [string]$Extension = $null
    )
    $mimeType = $null
    if ( $null -ne $extension )
    {
        $drive = Get-PSDrive "HKCR" -ErrorAction SilentlyContinue
        if ( $null -eq $drive )
        {
            $drive = New-PSDrive -Name "HKCR" -PSProvider Registry -Root HKEY_CLASSES_ROOT
        }
        $mimeType = (Get-ItemProperty "HKCR:$extension")."Content Type"
    }
    return $mimeType
}

$AlyaMimeTypeMap = @{
    '.323'                          = 'text/h323'
    '.3g2'                          = 'video/3gpp2'
    '.3gp'                          = 'video/3gpp'
    '.3gp2'                         = 'video/3gpp2'
    '.3gpp'                         = 'video/3gpp'
    '.7z'                           = 'application/x-7z-compressed'
    '.aa'                           = 'audio/audible'
    '.AAC'                          = 'audio/aac'
    '.aaf'                          = 'application/octet-stream'
    '.aax'                          = 'audio/vnd.audible.aax'
    '.ac3'                          = 'audio/ac3'
    '.aca'                          = 'application/octet-stream'
    '.accda'                        = 'application/msaccess.addin'
    '.accdb'                        = 'application/msaccess'
    '.accdc'                        = 'application/msaccess.cab'
    '.accde'                        = 'application/msaccess'
    '.accdr'                        = 'application/msaccess.runtime'
    '.accdt'                        = 'application/msaccess'
    '.accdw'                        = 'application/msaccess.webapplication'
    '.accft'                        = 'application/msaccess.ftemplate'
    '.acx'                          = 'application/internet-property-stream'
    '.AddIn'                        = 'text/xml'
    '.ade'                          = 'application/msaccess'
    '.adobebridge'                  = 'application/x-bridge-url'
    '.adp'                          = 'application/msaccess'
    '.ADT'                          = 'audio/vnd.dlna.adts'
    '.ADTS'                         = 'audio/aac'
    '.afm'                          = 'application/octet-stream'
    '.ai'                           = 'application/postscript'
    '.aif'                          = 'audio/aiff'
    '.aifc'                         = 'audio/aiff'
    '.aiff'                         = 'audio/aiff'
    '.air'                          = 'application/vnd.adobe.air-application-installer-package+zip'
    '.amc'                          = 'application/mpeg'
    '.anx'                          = 'application/annodex'
    '.apk'                          = 'application/vnd.android.package-archive'
    '.apng'                         = 'image/apng'
    '.application'                  = 'application/x-ms-application'
    '.art'                          = 'image/x-jg'
    '.asa'                          = 'application/xml'
    '.asax'                         = 'application/xml'
    '.ascx'                         = 'application/xml'
    '.asd'                          = 'application/octet-stream'
    '.asf'                          = 'video/x-ms-asf'
    '.ashx'                         = 'application/xml'
    '.asi'                          = 'application/octet-stream'
    '.asm'                          = 'text/plain'
    '.asmx'                         = 'application/xml'
    '.aspx'                         = 'application/xml'
    '.asr'                          = 'video/x-ms-asf'
    '.asx'                          = 'video/x-ms-asf'
    '.atom'                         = 'application/atom+xml'
    '.au'                           = 'audio/basic'
    '.avci'                         = 'image/avci'
    '.avcs'                         = 'image/avcs'
    '.avi'                          = 'video/x-msvideo'
    '.avif'                         = 'image/avif'
    '.avifs'                        = 'image/avif-sequence'
    '.axa'                          = 'audio/annodex'
    '.axs'                          = 'application/olescript'
    '.axv'                          = 'video/annodex'
    '.bas'                          = 'text/plain'
    '.bcpio'                        = 'application/x-bcpio'
    '.bin'                          = 'application/octet-stream'
    '.bmp'                          = 'image/bmp'
    '.c'                            = 'text/plain'
    '.cab'                          = 'application/octet-stream'
    '.caf'                          = 'audio/x-caf'
    '.calx'                         = 'application/vnd.ms-office.calx'
    '.cat'                          = 'application/vnd.ms-pki.seccat'
    '.cc'                           = 'text/plain'
    '.cd'                           = 'text/plain'
    '.cdda'                         = 'audio/aiff'
    '.cdf'                          = 'application/x-cdf'
    '.cer'                          = 'application/x-x509-ca-cert'
    '.cfg'                          = 'text/plain'
    '.chm'                          = 'application/octet-stream'
    '.class'                        = 'application/x-java-applet'
    '.clp'                          = 'application/x-msclip'
    '.cmd'                          = 'text/plain'
    '.cmx'                          = 'image/x-cmx'
    '.cnf'                          = 'text/plain'
    '.cod'                          = 'image/cis-cod'
    '.config'                       = 'application/xml'
    '.contact'                      = 'text/x-ms-contact'
    '.coverage'                     = 'application/xml'
    '.cpio'                         = 'application/x-cpio'
    '.cpp'                          = 'text/plain'
    '.crd'                          = 'application/x-mscardfile'
    '.crl'                          = 'application/pkix-crl'
    '.crt'                          = 'application/x-x509-ca-cert'
    '.cs'                           = 'text/plain'
    '.csdproj'                      = 'text/plain'
    '.csh'                          = 'application/x-csh'
    '.csproj'                       = 'text/plain'
    '.css'                          = 'text/css'
    '.csv'                          = 'text/csv'
    '.cur'                          = 'application/octet-stream'
    '.cxx'                          = 'text/plain'
    '.czx'                          = 'application/x-czx'
    '.dat'                          = 'application/octet-stream'
    '.datasource'                   = 'application/xml'
    '.dbproj'                       = 'text/plain'
    '.dcr'                          = 'application/x-director'
    '.def'                          = 'text/plain'
    '.deploy'                       = 'application/octet-stream'
    '.der'                          = 'application/x-x509-ca-cert'
    '.dgml'                         = 'application/xml'
    '.dib'                          = 'image/bmp'
    '.dif'                          = 'video/x-dv'
    '.dir'                          = 'application/x-director'
    '.disco'                        = 'text/xml'
    '.divx'                         = 'video/divx'
    '.dll.config'                   = 'text/xml'
    '.dll'                          = 'application/x-msdownload'
    '.dlm'                          = 'text/dlm'
    '.doc'                          = 'application/msword'
    '.docm'                         = 'application/vnd.ms-word.document.macroEnabled.12'
    '.docx'                         = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    '.dot'                          = 'application/msword'
    '.dotm'                         = 'application/vnd.ms-word.template.macroEnabled.12'
    '.dotx'                         = 'application/vnd.openxmlformats-officedocument.wordprocessingml.template'
    '.dsp'                          = 'application/octet-stream'
    '.dsw'                          = 'text/plain'
    '.dtd'                          = 'text/xml'
    '.dtsConfig'                    = 'text/xml'
    '.dv'                           = 'video/x-dv'
    '.dvi'                          = 'application/x-dvi'
    '.dwf'                          = 'drawing/x-dwf'
    '.dwg'                          = 'application/acad'
    '.dwp'                          = 'application/octet-stream'
    '.dxf'                          = 'application/x-dxf'
    '.dxr'                          = 'application/x-director'
    '.emf'                          = 'image/emf'
    '.eml'                          = 'message/rfc822'
    '.emz'                          = 'application/octet-stream'
    '.eot'                          = 'application/vnd.ms-fontobject'
    '.eps'                          = 'application/postscript'
    '.es'                           = 'application/ecmascript'
    '.etl'                          = 'application/etl'
    '.etx'                          = 'text/x-setext'
    '.evy'                          = 'application/envoy'
    '.exe.config'                   = 'text/xml'
    '.exe'                          = 'application/vnd.microsoft.portable-executable'
    '.f4v'                          = 'video/mp4'
    '.fdf'                          = 'application/vnd.fdf'
    '.fif'                          = 'application/fractals'
    '.filters'                      = 'application/xml'
    '.fla'                          = 'application/octet-stream'
    '.flac'                         = 'audio/flac'
    '.flr'                          = 'x-world/x-vrml'
    '.flv'                          = 'video/x-flv'
    '.fsscript'                     = 'application/fsharp-script'
    '.fsx'                          = 'application/fsharp-script'
    '.generictest'                  = 'application/xml'
    '.geojson'                      = 'application/geo+json'
    '.gif'                          = 'image/gif'
    '.gpx'                          = 'application/gpx+xml'
    '.group'                        = 'text/x-ms-group'
    '.gsm'                          = 'audio/x-gsm'
    '.gtar'                         = 'application/x-gtar'
    '.gz'                           = 'application/x-gzip'
    '.h'                            = 'text/plain'
    '.hdf'                          = 'application/x-hdf'
    '.hdml'                         = 'text/x-hdml'
    '.heic'                         = 'image/heic'
    '.heics'                        = 'image/heic-sequence'
    '.heif'                         = 'image/heif'
    '.heifs'                        = 'image/heif-sequence'
    '.hhc'                          = 'application/x-oleobject'
    '.hhk'                          = 'application/octet-stream'
    '.hhp'                          = 'application/octet-stream'
    '.hlp'                          = 'application/winhlp'
    '.hpp'                          = 'text/plain'
    '.hqx'                          = 'application/mac-binhex40'
    '.hta'                          = 'application/hta'
    '.htc'                          = 'text/x-component'
    '.htm'                          = 'text/html'
    '.html'                         = 'text/html'
    '.htt'                          = 'text/webviewhtml'
    '.hxa'                          = 'application/xml'
    '.hxc'                          = 'application/xml'
    '.hxd'                          = 'application/octet-stream'
    '.hxe'                          = 'application/xml'
    '.hxf'                          = 'application/xml'
    '.hxh'                          = 'application/octet-stream'
    '.hxi'                          = 'application/octet-stream'
    '.hxk'                          = 'application/xml'
    '.hxq'                          = 'application/octet-stream'
    '.hxr'                          = 'application/octet-stream'
    '.hxs'                          = 'application/octet-stream'
    '.hxt'                          = 'text/html'
    '.hxv'                          = 'application/xml'
    '.hxw'                          = 'application/octet-stream'
    '.hxx'                          = 'text/plain'
    '.i'                            = 'text/plain'
    '.ical'                         = 'text/calendar'
    '.icalendar'                    = 'text/calendar'
    '.ico'                          = 'image/x-icon'
    '.ics'                          = 'text/calendar'
    '.idl'                          = 'text/plain'
    '.ief'                          = 'image/ief'
    '.ifb'                          = 'text/calendar'
    '.iii'                          = 'application/x-iphone'
    '.inc'                          = 'text/plain'
    '.inf'                          = 'application/octet-stream'
    '.ini'                          = 'text/plain'
    '.inl'                          = 'text/plain'
    '.ins'                          = 'application/x-internet-signup'
    '.ipa'                          = 'application/x-itunes-ipa'
    '.ipg'                          = 'application/x-itunes-ipg'
    '.ipproj'                       = 'text/plain'
    '.ipsw'                         = 'application/x-itunes-ipsw'
    '.iqy'                          = 'text/x-ms-iqy'
    '.isma'                         = 'application/octet-stream'
    '.ismv'                         = 'application/octet-stream'
    '.isp'                          = 'application/x-internet-signup'
    '.ite'                          = 'application/x-itunes-ite'
    '.itlp'                         = 'application/x-itunes-itlp'
    '.itms'                         = 'application/x-itunes-itms'
    '.itpc'                         = 'application/x-itunes-itpc'
    '.IVF'                          = 'video/x-ivf'
    '.jar'                          = 'application/java-archive'
    '.java'                         = 'application/octet-stream'
    '.jck'                          = 'application/liquidmotion'
    '.jcz'                          = 'application/liquidmotion'
    '.jfif'                         = 'image/pjpeg'
    '.jnlp'                         = 'application/x-java-jnlp-file'
    '.jpb'                          = 'application/octet-stream'
    '.jpe'                          = 'image/jpeg'
    '.jpeg'                         = 'image/jpeg'
    '.jpg'                          = 'image/jpeg'
    '.js'                           = 'application/javascript'
    '.json'                         = 'application/json'
    '.jsx'                          = 'text/jscript'
    '.jsxbin'                       = 'text/plain'
    '.latex'                        = 'application/x-latex'
    '.library-ms'                   = 'application/windows-library+xml'
    '.lit'                          = 'application/x-ms-reader'
    '.loadtest'                     = 'application/xml'
    '.lpk'                          = 'application/octet-stream'
    '.lsf'                          = 'video/x-la-asf'
    '.lst'                          = 'text/plain'
    '.lsx'                          = 'video/x-la-asf'
    '.lzh'                          = 'application/octet-stream'
    '.m13'                          = 'application/x-msmediaview'
    '.m14'                          = 'application/x-msmediaview'
    '.m1v'                          = 'video/mpeg'
    '.m2t'                          = 'video/vnd.dlna.mpeg-tts'
    '.m2ts'                         = 'video/vnd.dlna.mpeg-tts'
    '.m2v'                          = 'video/mpeg'
    '.m3u'                          = 'audio/x-mpegurl'
    '.m3u8'                         = 'audio/x-mpegurl'
    '.m4a'                          = 'audio/m4a'
    '.m4b'                          = 'audio/m4b'
    '.m4p'                          = 'audio/m4p'
    '.m4r'                          = 'audio/x-m4r'
    '.m4v'                          = 'video/x-m4v'
    '.mac'                          = 'image/x-macpaint'
    '.mak'                          = 'text/plain'
    '.man'                          = 'application/x-troff-man'
    '.manifest'                     = 'application/x-ms-manifest'
    '.map'                          = 'text/plain'
    '.master'                       = 'application/xml'
    '.mbox'                         = 'application/mbox'
    '.mda'                          = 'application/msaccess'
    '.mdb'                          = 'application/x-msaccess'
    '.mde'                          = 'application/msaccess'
    '.mdp'                          = 'application/octet-stream'
    '.me'                           = 'application/x-troff-me'
    '.mfp'                          = 'application/x-shockwave-flash'
    '.mht'                          = 'message/rfc822'
    '.mhtml'                        = 'message/rfc822'
    '.mid'                          = 'audio/mid'
    '.midi'                         = 'audio/mid'
    '.mix'                          = 'application/octet-stream'
    '.mk'                           = 'text/plain'
    '.mk3d'                         = 'video/x-matroska-3d'
    '.mka'                          = 'audio/x-matroska'
    '.mkv'                          = 'video/x-matroska'
    '.mmf'                          = 'application/x-smaf'
    '.mno'                          = 'text/xml'
    '.mny'                          = 'application/x-msmoney'
    '.mod'                          = 'video/mpeg'
    '.mov'                          = 'video/quicktime'
    '.movie'                        = 'video/x-sgi-movie'
    '.mp2'                          = 'video/mpeg'
    '.mp2v'                         = 'video/mpeg'
    '.mp3'                          = 'audio/mpeg'
    '.mp4'                          = 'video/mp4'
    '.mp4v'                         = 'video/mp4'
    '.mpa'                          = 'video/mpeg'
    '.mpe'                          = 'video/mpeg'
    '.mpeg'                         = 'video/mpeg'
    '.mpf'                          = 'application/vnd.ms-mediapackage'
    '.mpg'                          = 'video/mpeg'
    '.mpp'                          = 'application/vnd.ms-project'
    '.mpv2'                         = 'video/mpeg'
    '.mqv'                          = 'video/quicktime'
    '.ms'                           = 'application/x-troff-ms'
    '.msg'                          = 'application/vnd.ms-outlook'
    '.msi'                          = 'application/octet-stream'
    '.mso'                          = 'application/octet-stream'
    '.mts'                          = 'video/vnd.dlna.mpeg-tts'
    '.mtx'                          = 'application/xml'
    '.mvb'                          = 'application/x-msmediaview'
    '.mvc'                          = 'application/x-miva-compiled'
    '.mxf'                          = 'application/mxf'
    '.mxp'                          = 'application/x-mmxp'
    '.nc'                           = 'application/x-netcdf'
    '.nsc'                          = 'video/x-ms-asf'
    '.nws'                          = 'message/rfc822'
    '.ocx'                          = 'application/octet-stream'
    '.oda'                          = 'application/oda'
    '.odb'                          = 'application/vnd.oasis.opendocument.database'
    '.odc'                          = 'application/vnd.oasis.opendocument.chart'
    '.odf'                          = 'application/vnd.oasis.opendocument.formula'
    '.odg'                          = 'application/vnd.oasis.opendocument.graphics'
    '.odh'                          = 'text/plain'
    '.odi'                          = 'application/vnd.oasis.opendocument.image'
    '.odl'                          = 'text/plain'
    '.odm'                          = 'application/vnd.oasis.opendocument.text-master'
    '.odp'                          = 'application/vnd.oasis.opendocument.presentation'
    '.ods'                          = 'application/vnd.oasis.opendocument.spreadsheet'
    '.odt'                          = 'application/vnd.oasis.opendocument.text'
    '.oga'                          = 'audio/ogg'
    '.ogg'                          = 'audio/ogg'
    '.ogv'                          = 'video/ogg'
    '.ogx'                          = 'application/ogg'
    '.one'                          = 'application/onenote'
    '.onea'                         = 'application/onenote'
    '.onepkg'                       = 'application/onenote'
    '.onetmp'                       = 'application/onenote'
    '.onetoc'                       = 'application/onenote'
    '.onetoc2'                      = 'application/onenote'
    '.opus'                         = 'audio/ogg'
    '.orderedtest'                  = 'application/xml'
    '.osdx'                         = 'application/opensearchdescription+xml'
    '.otf'                          = 'application/font-sfnt'
    '.otg'                          = 'application/vnd.oasis.opendocument.graphics-template'
    '.oth'                          = 'application/vnd.oasis.opendocument.text-web'
    '.otp'                          = 'application/vnd.oasis.opendocument.presentation-template'
    '.ots'                          = 'application/vnd.oasis.opendocument.spreadsheet-template'
    '.ott'                          = 'application/vnd.oasis.opendocument.text-template'
    '.oxps'                         = 'application/oxps'
    '.oxt'                          = 'application/vnd.openofficeorg.extension'
    '.p10'                          = 'application/pkcs10'
    '.p12'                          = 'application/x-pkcs12'
    '.p7b'                          = 'application/x-pkcs7-certificates'
    '.p7c'                          = 'application/pkcs7-mime'
    '.p7m'                          = 'application/pkcs7-mime'
    '.p7r'                          = 'application/x-pkcs7-certreqresp'
    '.p7s'                          = 'application/pkcs7-signature'
    '.pbm'                          = 'image/x-portable-bitmap'
    '.pcast'                        = 'application/x-podcast'
    '.pct'                          = 'image/pict'
    '.pcx'                          = 'application/octet-stream'
    '.pcz'                          = 'application/octet-stream'
    '.pdf'                          = 'application/pdf'
    '.pfb'                          = 'application/octet-stream'
    '.pfm'                          = 'application/octet-stream'
    '.pfx'                          = 'application/x-pkcs12'
    '.pgm'                          = 'image/x-portable-graymap'
    '.pic'                          = 'image/pict'
    '.pict'                         = 'image/pict'
    '.pkgdef'                       = 'text/plain'
    '.pkgundef'                     = 'text/plain'
    '.pko'                          = 'application/vnd.ms-pki.pko'
    '.pls'                          = 'audio/scpls'
    '.pma'                          = 'application/x-perfmon'
    '.pmc'                          = 'application/x-perfmon'
    '.pml'                          = 'application/x-perfmon'
    '.pmr'                          = 'application/x-perfmon'
    '.pmw'                          = 'application/x-perfmon'
    '.png'                          = 'image/png'
    '.pnm'                          = 'image/x-portable-anymap'
    '.pnt'                          = 'image/x-macpaint'
    '.pntg'                         = 'image/x-macpaint'
    '.pnz'                          = 'image/png'
    '.pot'                          = 'application/vnd.ms-powerpoint'
    '.potm'                         = 'application/vnd.ms-powerpoint.template.macroEnabled.12'
    '.potx'                         = 'application/vnd.openxmlformats-officedocument.presentationml.template'
    '.ppa'                          = 'application/vnd.ms-powerpoint'
    '.ppam'                         = 'application/vnd.ms-powerpoint.addin.macroEnabled.12'
    '.ppm'                          = 'image/x-portable-pixmap'
    '.pps'                          = 'application/vnd.ms-powerpoint'
    '.ppsm'                         = 'application/vnd.ms-powerpoint.slideshow.macroEnabled.12'
    '.ppsx'                         = 'application/vnd.openxmlformats-officedocument.presentationml.slideshow'
    '.ppt'                          = 'application/vnd.ms-powerpoint'
    '.pptm'                         = 'application/vnd.ms-powerpoint.presentation.macroEnabled.12'
    '.pptx'                         = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    '.prf'                          = 'application/pics-rules'
    '.prm'                          = 'application/octet-stream'
    '.prx'                          = 'application/octet-stream'
    '.ps'                           = 'application/postscript'
    '.psc1'                         = 'application/PowerShell'
    '.psd'                          = 'application/octet-stream'
    '.psess'                        = 'application/xml'
    '.psm'                          = 'application/octet-stream'
    '.psp'                          = 'application/octet-stream'
    '.pst'                          = 'application/vnd.ms-outlook'
    '.pub'                          = 'application/x-mspublisher'
    '.pwz'                          = 'application/vnd.ms-powerpoint'
    '.qht'                          = 'text/x-html-insertion'
    '.qhtm'                         = 'text/x-html-insertion'
    '.qt'                           = 'video/quicktime'
    '.qti'                          = 'image/x-quicktime'
    '.qtif'                         = 'image/x-quicktime'
    '.qtl'                          = 'application/x-quicktimeplayer'
    '.qxd'                          = 'application/octet-stream'
    '.ra'                           = 'audio/x-pn-realaudio'
    '.ram'                          = 'audio/x-pn-realaudio'
    '.rar'                          = 'application/x-rar-compressed'
    '.ras'                          = 'image/x-cmu-raster'
    '.rat'                          = 'application/rat-file'
    '.rc'                           = 'text/plain'
    '.rc2'                          = 'text/plain'
    '.rct'                          = 'text/plain'
    '.rdlc'                         = 'application/xml'
    '.reg'                          = 'text/plain'
    '.resx'                         = 'application/xml'
    '.rf'                           = 'image/vnd.rn-realflash'
    '.rgb'                          = 'image/x-rgb'
    '.rgs'                          = 'text/plain'
    '.rm'                           = 'application/vnd.rn-realmedia'
    '.rmi'                          = 'audio/mid'
    '.rmp'                          = 'application/vnd.rn-rn_music_package'
    '.rmvb'                         = 'application/vnd.rn-realmedia-vbr'
    '.roff'                         = 'application/x-troff'
    '.rpm'                          = 'audio/x-pn-realaudio-plugin'
    '.rqy'                          = 'text/x-ms-rqy'
    '.rtf'                          = 'application/rtf'
    '.rtx'                          = 'text/richtext'
    '.ruleset'                      = 'application/xml'
    '.rvt'                          = 'application/octet-stream'
    '.s'                            = 'text/plain'
    '.safariextz'                   = 'application/x-safari-safariextz'
    '.scd'                          = 'application/x-msschedule'
    '.scr'                          = 'text/plain'
    '.sct'                          = 'text/scriptlet'
    '.sd2'                          = 'audio/x-sd2'
    '.sdp'                          = 'application/sdp'
    '.sea'                          = 'application/octet-stream'
    '.searchConnector-ms'           = 'application/windows-search-connector+xml'
    '.setpay'                       = 'application/set-payment-initiation'
    '.setreg'                       = 'application/set-registration-initiation'
    '.settings'                     = 'application/xml'
    '.sgimb'                        = 'application/x-sgimb'
    '.sgml'                         = 'text/sgml'
    '.sh'                           = 'application/x-sh'
    '.shar'                         = 'application/x-shar'
    '.shtml'                        = 'text/html'
    '.sit'                          = 'application/x-stuffit'
    '.sitemap'                      = 'application/xml'
    '.skin'                         = 'application/xml'
    '.skp'                          = 'application/x-koan'
    '.sldm'                         = 'application/vnd.ms-powerpoint.slide.macroEnabled.12'
    '.sldx'                         = 'application/vnd.openxmlformats-officedocument.presentationml.slide'
    '.slk'                          = 'application/vnd.ms-excel'
    '.sln'                          = 'text/plain'
    '.slupkg-ms'                    = 'application/x-ms-license'
    '.smd'                          = 'audio/x-smd'
    '.smi'                          = 'application/octet-stream'
    '.smx'                          = 'audio/x-smd'
    '.smz'                          = 'audio/x-smd'
    '.snd'                          = 'audio/basic'
    '.snippet'                      = 'application/xml'
    '.snp'                          = 'application/octet-stream'
    '.sol'                          = 'text/plain'
    '.sor'                          = 'text/plain'
    '.spc'                          = 'application/x-pkcs7-certificates'
    '.spl'                          = 'application/futuresplash'
    '.spx'                          = 'audio/ogg'
    '.sql'                          = 'application/sql'
    '.src'                          = 'application/x-wais-source'
    '.srf'                          = 'text/plain'
    '.SSISDeploymentManifest'       = 'text/xml'
    '.ssm'                          = 'application/streamingmedia'
    '.sst'                          = 'application/vnd.ms-pki.certstore'
    '.step'                         = 'application/step'
    '.stl'                          = 'application/vnd.ms-pki.stl'
    '.stp'                          = 'application/step'
    '.sv4cpio'                      = 'application/x-sv4cpio'
    '.sv4crc'                       = 'application/x-sv4crc'
    '.svc'                          = 'application/xml'
    '.svg'                          = 'image/svg+xml'
    '.swf'                          = 'application/x-shockwave-flash'
    '.t'                            = 'application/x-troff'
    '.tar'                          = 'application/x-tar'
    '.tcl'                          = 'application/x-tcl'
    '.testrunconfig'                = 'application/xml'
    '.testsettings'                 = 'application/xml'
    '.tex'                          = 'application/x-tex'
    '.texi'                         = 'application/x-texinfo'
    '.texinfo'                      = 'application/x-texinfo'
    '.tgz'                          = 'application/x-compressed'
    '.thmx'                         = 'application/vnd.ms-officetheme'
    '.thn'                          = 'application/octet-stream'
    '.tif'                          = 'image/tiff'
    '.tiff'                         = 'image/tiff'
    '.tlh'                          = 'text/plain'
    '.tli'                          = 'text/plain'
    '.toc'                          = 'application/octet-stream'
    '.tr'                           = 'application/x-troff'
    '.trm'                          = 'application/x-msterminal'
    '.trx'                          = 'application/xml'
    '.ts'                           = 'video/vnd.dlna.mpeg-tts'
    '.tsv'                          = 'text/tab-separated-values'
    '.ttf'                          = 'application/font-sfnt'
    '.tts'                          = 'video/vnd.dlna.mpeg-tts'
    '.txt'                          = 'text/plain'
    '.u32'                          = 'application/octet-stream'
    '.uls'                          = 'text/iuls'
    '.user'                         = 'text/plain'
    '.ustar'                        = 'application/x-ustar'
    '.vb'                           = 'text/plain'
    '.vbdproj'                      = 'text/plain'
    '.vbk'                          = 'video/mpeg'
    '.vbproj'                       = 'text/plain'
    '.vbs'                          = 'text/vbscript'
    '.vcf'                          = 'text/x-vcard'
    '.vcproj'                       = 'application/xml'
    '.vcs'                          = 'text/plain'
    '.vcxproj'                      = 'application/xml'
    '.vddproj'                      = 'text/plain'
    '.vdp'                          = 'text/plain'
    '.vdproj'                       = 'text/plain'
    '.vdx'                          = 'application/vnd.ms-visio.viewer'
    '.vml'                          = 'text/xml'
    '.vscontent'                    = 'application/xml'
    '.vsct'                         = 'text/xml'
    '.vsd'                          = 'application/vnd.visio'
    '.vsi'                          = 'application/ms-vsi'
    '.vsix'                         = 'application/vsix'
    '.vsixlangpack'                 = 'text/xml'
    '.vsixmanifest'                 = 'text/xml'
    '.vsmdi'                        = 'application/xml'
    '.vspscc'                       = 'text/plain'
    '.vss'                          = 'application/vnd.visio'
    '.vsscc'                        = 'text/plain'
    '.vssettings'                   = 'text/xml'
    '.vssscc'                       = 'text/plain'
    '.vst'                          = 'application/vnd.visio'
    '.vstemplate'                   = 'text/xml'
    '.vsto'                         = 'application/x-ms-vsto'
    '.vsw'                          = 'application/vnd.visio'
    '.vsx'                          = 'application/vnd.visio'
    '.vtt'                          = 'text/vtt'
    '.vtx'                          = 'application/vnd.visio'
    '.wasm'                         = 'application/wasm'
    '.wav'                          = 'audio/wav'
    '.wave'                         = 'audio/wav'
    '.wax'                          = 'audio/x-ms-wax'
    '.wbk'                          = 'application/msword'
    '.wbmp'                         = 'image/vnd.wap.wbmp'
    '.wcm'                          = 'application/vnd.ms-works'
    '.wdb'                          = 'application/vnd.ms-works'
    '.wdp'                          = 'image/vnd.ms-photo'
    '.webarchive'                   = 'application/x-safari-webarchive'
    '.webm'                         = 'video/webm'
    '.webp'                         = 'image/webp' # https://en.wikipedia.org/wiki/WebP
    '.webtest'                      = 'application/xml'
    '.wiq'                          = 'application/xml'
    '.wiz'                          = 'application/msword'
    '.wks'                          = 'application/vnd.ms-works'
    '.WLMP'                         = 'application/wlmoviemaker'
    '.wlpginstall'                  = 'application/x-wlpg-detect'
    '.wlpginstall3'                 = 'application/x-wlpg3-detect'
    '.wm'                           = 'video/x-ms-wm'
    '.wma'                          = 'audio/x-ms-wma'
    '.wmd'                          = 'application/x-ms-wmd'
    '.wmf'                          = 'application/x-msmetafile'
    '.wml'                          = 'text/vnd.wap.wml'
    '.wmlc'                         = 'application/vnd.wap.wmlc'
    '.wmls'                         = 'text/vnd.wap.wmlscript'
    '.wmlsc'                        = 'application/vnd.wap.wmlscriptc'
    '.wmp'                          = 'video/x-ms-wmp'
    '.wmv'                          = 'video/x-ms-wmv'
    '.wmx'                          = 'video/x-ms-wmx'
    '.wmz'                          = 'application/x-ms-wmz'
    '.woff'                         = 'application/font-woff'
    '.woff2'                        = 'application/font-woff2'
    '.wpl'                          = 'application/vnd.ms-wpl'
    '.wps'                          = 'application/vnd.ms-works'
    '.wri'                          = 'application/x-mswrite'
    '.wrl'                          = 'x-world/x-vrml'
    '.wrz'                          = 'x-world/x-vrml'
    '.wsc'                          = 'text/scriptlet'
    '.wsdl'                         = 'text/xml'
    '.wvx'                          = 'video/x-ms-wvx'
    '.x'                            = 'application/directx'
    '.xaf'                          = 'x-world/x-vrml'
    '.xaml'                         = 'application/xaml+xml'
    '.xap'                          = 'application/x-silverlight-app'
    '.xbap'                         = 'application/x-ms-xbap'
    '.xbm'                          = 'image/x-xbitmap'
    '.xdr'                          = 'text/plain'
    '.xht'                          = 'application/xhtml+xml'
    '.xhtml'                        = 'application/xhtml+xml'
    '.xla'                          = 'application/vnd.ms-excel'
    '.xlam'                         = 'application/vnd.ms-excel.addin.macroEnabled.12'
    '.xlc'                          = 'application/vnd.ms-excel'
    '.xld'                          = 'application/vnd.ms-excel'
    '.xlk'                          = 'application/vnd.ms-excel'
    '.xll'                          = 'application/vnd.ms-excel'
    '.xlm'                          = 'application/vnd.ms-excel'
    '.xls'                          = 'application/vnd.ms-excel'
    '.xlsb'                         = 'application/vnd.ms-excel.sheet.binary.macroEnabled.12'
    '.xlsm'                         = 'application/vnd.ms-excel.sheet.macroEnabled.12'
    '.xlsx'                         = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    '.xlt'                          = 'application/vnd.ms-excel'
    '.xltm'                         = 'application/vnd.ms-excel.template.macroEnabled.12'
    '.xltx'                         = 'application/vnd.openxmlformats-officedocument.spreadsheetml.template'
    '.xlw'                          = 'application/vnd.ms-excel'
    '.xml'                          = 'text/xml'
    '.xmp'                          = 'application/octet-stream'
    '.xmta'                         = 'application/xml'
    '.xof'                          = 'x-world/x-vrml'
    '.XOML'                         = 'text/plain'
    '.xpm'                          = 'image/x-xpixmap'
    '.xps'                          = 'application/vnd.ms-xpsdocument'
    '.xrm-ms'                       = 'text/xml'
    '.xsc'                          = 'application/xml'
    '.xsd'                          = 'text/xml'
    '.xsf'                          = 'text/xml'
    '.xsl'                          = 'text/xml'
    '.xslt'                         = 'text/xml'
    '.xsn'                          = 'application/octet-stream'
    '.xspf'                         = 'application/xspf+xml'
    '.xss'                          = 'application/xml'
    '.xtp'                          = 'application/octet-stream'
    '.xwd'                          = 'image/x-xwindowdump'
    '.z'                            = 'application/x-compress'
    '.zip'                          = 'application/zip'
}
function Get-MimeTypeIndependent()
{
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Extension
    )
    process {
        if (-not $Extension.StartsWith('.')) {
            $Extension = ".$Extension"
        }

        if ($AlyaMimeTypeMap.ContainsKey($Extension)) {
            return $AlyaMimeTypeMap[$Extension]
        } else {
            return "application/octet-stream"
        }
    }
}

function Remove-OneDriveItemRecursive
{
    [cmdletbinding()]
    param(
        [string] $Path
    )
    if ($Path -and (Test-Path -LiteralPath $Path))
    {
        $Items = Get-ChildItem -LiteralPath $Path -File -Recurse
        $Items += Get-ChildItem -LiteralPath $Path -File -Recurse -Attributes "Hidden"
        foreach ($Item in $Items)
        {
            try
            {
                $Item.Delete()
            } catch
            {
                Write-Warning "Remove-OneDriveItemRecursive - Couldn't delete $($Item.FullName), error: $($_.Exception.Message). Trying Remove-Item instead."
                try
                {
                    $null = Remove-Item -Path $Item.FullName -Force -ErrorAction Stop
                } catch
                {
                    throw "Remove-OneDriveItemRecursive - Couldn't delete $($Item.FullName), error: $($_.Exception.Message)"
                }
            }
        }
        $Items = Get-ChildItem -LiteralPath $Path -Directory -Recurse
        $Items += Get-ChildItem -LiteralPath $Path -Directory -Recurse -Attributes "Hidden"
        $Items = $Items| Sort-object -Property { $_.FullName.Length } -Descending
        foreach ($Item in $Items)
        {
            try
            {
                $Item.Delete()
            } catch
            {
                Write-Warning "Remove-OneDriveItemRecursive - Couldn't delete $($Item.FullName), error: $($_.Exception.Message). Trying Remove-Item instead."
                try
                {
                    $null = Remove-Item -Path $Item.FullName -Recurse -Force -ErrorAction Stop
                } catch
                {
                    throw "Remove-OneDriveItemRecursive - Couldn't delete $($Item.FullName), error: $($_.Exception.Message)"
                }
            }
        }
        try
        {
            $Item = Get-Item -Path $Path
            $Item.Delete()
        } catch
        {
            Write-Warning "Remove-OneDriveItemRecursive - Couldn't delete $($Path), error: $($_.Exception.Message). Trying Remove-Item instead."
            try
            {
                $null = Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            } catch
            {
                throw "Remove-OneDriveItemRecursive - Couldn't delete $($Path), error: $($_.Exception.Message)"
            }
        }
    } else
    {
        Write-Warning "Remove-OneDriveItemRecursive - Path $Path doesn't exists. Skipping. "
    }
}

# From https://stackoverflow.com/questions/33283848/determining-internet-connection-using-powershell
function Test-IPv4InternetConnectivity
{
    if (-Not (Get-Module -Name "NetConnection"))
    {
        Import-Module -Name "NetConnection"
    }
    $strOSVersion = (Get-WmiObject -Query "Select Version from Win32_OperatingSystem").Version
    $arrStrOSVersion = $strOSVersion.Split(".")
    $intOSMajorVersion = [UInt16]$arrStrOSVersion[0]
    if ($arrStrOSVersion.Length -ge 2)
    {
        $intOSMinorVersion = [UInt16]$arrStrOSVersion[1]
    }
    else
    {
        $intOSMinorVersion = [UInt16]0
    }
    if (($intOSMajorVersion -gt 6) -or (($intOSMajorVersion -eq 6) -and ($intOSMinorVersion -gt 1)))
    {
        $IPV4ConnectivityInternet = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetConnectionProfile.IPv4Connectivity]::Internet
        $internetNetworks = Get-NetConnectionProfile | Where-Object {$_.IPv4Connectivity -eq $IPV4ConnectivityInternet}
    }
    else
    {
        $internetNetworks = ([Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))).GetNetworkConnections() | `
            ForEach-Object {$_.GetNetwork().GetConnectivity()} | Where-Object {($_ -band 64) -eq 64}
    }
    return ($internetNetworks -ne $null)
}

function Test-IPv6InternetConnectivity
{
    if (-Not (Get-Module -Name "NetConnection"))
    {
        Import-Module -Name "NetConnection"
    }
    $strOSVersion = (Get-WmiObject -Query "Select Version from Win32_OperatingSystem").Version
    $arrStrOSVersion = $strOSVersion.Split(".")
    $intOSMajorVersion = [UInt16]$arrStrOSVersion[0]
    if ($arrStrOSVersion.Length -ge 2)
    {
        $intOSMinorVersion = [UInt16]$arrStrOSVersion[1]
    }
    else
    {
        $intOSMinorVersion = [UInt16]0
    }
    if (($intOSMajorVersion -gt 6) -or (($intOSMajorVersion -eq 6) -and ($intOSMinorVersion -gt 1)))
    {
        $IPV6ConnectivityInternet = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetConnectionProfile.IPv6Connectivity]::Internet
        $internetNetworks = Get-NetConnectionProfile | Where-Object {$_.IPv6Connectivity -eq $IPV6ConnectivityInternet}
    }
    else
    {
        $internetNetworks = ([Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))).GetNetworkConnections() | `
            ForEach-Object {$_.GetNetwork().GetConnectivity()} | Where-Object {($_ -band 64) -eq 1024}
    }
    return ($internetNetworks -ne $null)
}

function Is-InternetConnected()
{
    $var = Get-Variable -Name "AlyaIsInternetConnected" -Scope "Global" -ErrorAction SilentlyContinue

    if ($AlyaIsPsUnix)
    {
        if (-Not $var)
        {
            $Global:AlyaIsInternetConnected = $false
        }
    }
    else
    {
        $Global:AlyaIsInternetConnected = Test-IPv4InternetConnectivity
    }    

    if (-Not $Global:AlyaIsInternetConnected)
    {
        try {
            $req = Invoke-WebRequestIndep -Uri "https://www.google.ch" -UseBasicParsing
            $Global:AlyaIsInternetConnected = $true
        }
        catch {
            $hasTestNetCon = Get-Command -Name "Test-NetConnection" -ErrorAction SilentlyContinue
            if (-Not $var)
            {
                if ($hasTestNetCon)
                {
                    $ret = Test-NetConnection -ComputerName 8.8.8.8 -Port 443 -ErrorAction SilentlyContinue -InformationLevel Quiet
                }
                else
                {
                    $ret = Test-Connection -TargetName 8.8.8.8 -TcpPort 443 -Quiet -ErrorAction SilentlyContinue
                }
                if (-Not $ret)
                {
                    if ($hasTestNetCon)
                    {
                        $ret = Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -ErrorAction SilentlyContinue -InformationLevel Quiet
                    }
                    else
                    {
                        $ret = Test-Connection -TargetName 1.1.1.1 -TcpPort 443 -Quiet -ErrorAction SilentlyContinue
                    }
                }
                if ($ret)
                {
                    $Global:AlyaIsInternetConnected = $ret
                }
                else
                {
                    $Global:AlyaIsInternetConnected = $false
                }
            }
        }
    }
    return $Global:AlyaIsInternetConnected
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

function Get-Password(
    [int] [Parameter(Mandatory = $true)] $length)
{
    $allPwdChars = @(
        "QWERTYUIOPASDFGHJKLZXCVBNM",
        "qwertyuiopasdfghjklzxcvbnm",
        "0123456789",
        "!@#$%()-_=+"
    )
    $rnd = [System.Random]::new()
    $pwd = ""
    for ($n=0; $n -lt $length; $n++)
    {
        $row = ($n % 4)
        $chars = $allPwdChars[$row].ToCharArray()
        $pwd += $chars[$rnd.Next(0, $chars.Length - 1)]
    }
    return $pwd
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

<# PACKAGE AND MODULE MANGEMENT FUNCTIONS #>

function Get-PublishedModuleVersion(
    [string] [Parameter(Mandatory = $true)] $moduleName,
    [Version] $exactVersion = "0.0.0.0",
    [bool] $allowPrerelease = $false
)
{
    $url = "https://www.powershellgallery.com/packages/$moduleName/?dummy=$(Get-Random)"
    $request = [System.Net.WebRequest]::Create($url)
    $request.AllowAutoRedirect=$false
    [Version]$version = "0.0.0.0"
    [string]$fullVersion = "0.0.0.0"
    try
    {
        $response = $request.GetResponse()
        $version = $response.GetResponseHeader("Location").Split("/")[-1].Trim()
        $fullVersion = $version
        $response.Close()
        $response.Dispose()
    }
    catch
    {
        Write-Warning $_.Exception.Message
        return $null
    }
    if ($allowPrerelease -or $exactVersion -ne "0.0.0.0")
    {
        if ($exactVersion -ne "0.0.0.0") { $version = $exactVersion }
        $url = "https://www.powershellgallery.com/packages/$moduleName/$version/?dummy=$(Get-Random)"
        try
        {
            $response = Invoke-WebRequestIndep -Method "Get" -Uri $url -UseBasicParsing
            if ($exactVersion -ne "0.0.0.0")
            {
                $versionUrl = $response.Links | where { $_.href -like "/packages/$moduleName/$exactVersion*" } | Select-Object -Property href -Last 1 | Out-String
            }
            else
            {
                $versionUrl = $response.Links | where { $_.href -like "/packages/$moduleName/*-nightly" } | Select-Object -Property href -Last 1 | Out-String
            }
            if ($versionUrl)
            {
                $version = $versionUrl.Split("/")[-1].Replace("-nightly", "").Trim()
                $fullVersion = $versionUrl.Split("/")[-1].Trim()
            }
            else
            {
                $version = $version
                $fullVersion = $fullVersion
            }
        }
        catch
        {
            Write-Warning $_.Exception.Message
        }
    }
    return @($version, $fullVersion)
}

function Check-Module (
    [string] [Parameter(Mandatory = $true)] $moduleName,
    [Version] $minimalVersion = "0.0.0.0",
    [Version] $exactVersion = "0.0.0.0"
)
{
    if ($exactVersion -ne "0.0.0.0")
    {
        $module = Get-Module -Name $moduleName -ListAvailable | Where-Object { $_.Version -eq $exactVersion }
        if (-Not $module)
        {
            try
            {
                try
                {
                    $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | Where-Object { $_.Version -eq $exactVersion }
                }
                catch
                {
                    Import-Module -Name PowerShellGet
                    $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | Where-Object { $_.Version -eq $exactVersion }
                }
            }
            catch { }
        }
    }
    else
    {
        $module = Get-Module -Name $moduleName -ListAvailable | `
            Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            try
            {
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | `
                    Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            catch
            {
                Import-Module -Name PowerShellGet
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | `
                    Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
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
	Invoke-WebRequestIndep -Uri $nusrc.href -OutFile $fileName
	if (-not (Test-Path $fileName))
	{
		Write-Error "    Was not able to download $packageName which is a prerequisite for this script" -ErrorAction Continue
		break
	}
    #Add-Type -AssemblyName System.IO.Compression.FileSystem
    #[System.IO.Compression.ZipFile]::ExtractToDirectory($fileName, "$($AlyaTools)\Packages\$packageName")
    #New version for mac:
	if (-not (Test-Path "$($AlyaTools)\Packages\$packageName"))
	{
		New-Item -Path "$($AlyaTools)\Packages\$packageName" -ItemType Directory -Force
	}
    $cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
    if ($cmdTst)
    {
        Expand-Archive -Path $fileName -DestinationPath "$($AlyaTools)\Packages\$packageName" -Force
    }
    else
    {
        Expand-Archive -Path $fileName -OutputPath "$($AlyaTools)\Packages\$packageName" -Force
    }
    Remove-Item $fileName
}

function Install-PackageIfNotInstalled (
    [string] [Parameter(Mandatory = $true)] $packageName,
    [bool] $autoUpdate = $true,
    [string] $exactVersion = $null
)
{
    if ($AlyaPackageVersionOverwrite.Name -contains $packageName)
    {
        $exactVersion = ($AlyaPackageVersionOverwrite | Where-Object { $_.name -eq $packageName}).Version
    }
    if (-Not (Is-InternetConnected))
    {
        Write-Warning "No internet connection. Not able to check any package!"
        return
    }
    if (-Not (Test-Path "$($AlyaTools)\Packages"))
    {
        $tmp = New-Item -Path "$($AlyaTools)\Packages" -ItemType Directory -Force
    }
    if ($exactVersion) {
        $resp = Invoke-WebRequestIndep -Uri "https://www.nuget.org/packages/$packageName/$exactVersion" -UseBasicParsing
    } else {
        $resp = Invoke-WebRequestIndep -Uri "https://www.nuget.org/packages/$packageName" -UseBasicParsing
    }
    $nusrc = ($resp).Links | Where-Object { $_.href -like "*/package/*" -and $_.outerText -eq "Download package" -or $_.outerText -eq "Manual download" -or $_."data-track" -eq "outbound-manual-download"} | Select-Object -First 1
    $nuvrs = $nusrc.href.Substring($nusrc.href.LastIndexOf("/") + 1, $nusrc.href.Length - $nusrc.href.LastIndexOf("/") - 1)
    if (-not (Test-Path "$($AlyaTools)\Packages\$packageName\$packageName.nuspec"))
    {
        Write-Host ('Package {0} is not installed. Installing v{1}' -f $packageName, $nuvrs)
        DownloadAndInstall-Package -packageName $packageName -nuvrs $nuvrs -nusrc $nusrc
    }
    else
    {
        # Checking package version, updating if required
        $nuspec = [xml](Get-Content "$($AlyaTools)\Packages\$packageName\$packageName.nuspec")
        $nuvrsInstalled = $nuspec.package.metadata.version
        if ($autoUpdate)
        {
            if ($nuvrsInstalled -ne $nuvrs)
            {
                $nuvrsInstalled = $nuvrs
                Remove-Item -Recurse -Force "$($AlyaTools)\Packages\$packageName"
                DownloadAndInstall-Package -packageName $packageName -nuvrs $nuvrs -nusrc $nusrc
            }
        }
        Write-Host ('Package {0} is installed. Used:v{1} Requested:v{2}' -f $packageName, $nuvrsInstalled, $nuvrs)
    }
    if (-Not $AlyaIsPsUnix)
    {
        foreach($file in (Get-ChildItem -Path "$($AlyaTools)\Packages\$packageName" -Recurse))
        {
            Unblock-File -Path $file.FullName
        }
    }
}
#Install-PackageIfNotInstalled "Selenium.WebDriver"
#Install-PackageIfNotInstalled "Microsoft.SharePointOnline.CSOM"

function Uninstall-ModuleIfInstalled (
    [string] [Parameter(Mandatory = $true)] $moduleName,
    [Version] $exactVersion = "0.0.0.0"
)
{
    if ($exactVersion -ne "0.0.0.0")
    {
        $module = Get-Module -Name $moduleName -ListAvailable | Where-Object { $_.Version -eq $exactVersion }
        if (-Not $module)
        {
            try
            {
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | Where-Object { $_.Version -eq $exactVersion }
            }
            catch
            {
                Import-Module -Name PowerShellGet
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | Where-Object { $_.Version -eq $exactVersion }
            }
        }
    }
    else
    {
        $module = Get-Module -Name $moduleName -ListAvailable | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            try
            {
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | Sort-Object -Property Version | Select-Object -Last 1
            }
            catch
            {
                Import-Module -Name PowerShellGet
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | Sort-Object -Property Version | Select-Object -Last 1
            }
        }
    }
    if ($module)
    {
        Remove-Module -Name $moduleName -Force -ErrorAction SilentlyContinue
        if ($exactVersion -ne "0.0.0.0")
        {
            Write-Host ('Uninstalling requested version v{1} from module {0}.' -f $moduleName, $exactVersion)
            try {
                Uninstall-Module -Name $moduleName -RequiredVersion $exactVersion -Force
            }
            catch {
                $path = Split-Path (Split-Path $module.Path -Parent) -Parent
                Remove-Item -Path $path -Recurse -Force
            }
        }
        else
        {
            Write-Host ('Uninstalling all versions from module {0}.' -f $moduleName)
            try {
                Uninstall-Module -Name $moduleName -AllVersions -Force
            }
            catch {
                $path = Split-Path (Split-Path $module.Path -Parent) -Parent
                Remove-Item -Path $path -Recurse -Force
            }
        }
    }
}

function Install-ModuleIfNotInstalled (
    [string] [Parameter(Mandatory = $true)] $moduleName,
    [Version] $minimalVersion = "0.0.0.0",
    [Version] $exactVersion = "0.0.0.0",
    [bool] $autoUpdate = $true,
    [bool]$allowPrerelease = $false,
    [bool]$doNotLoadModules = $false
)
{
    if ($AlyaModuleVersionOverwrite.Name -contains $moduleName)
    {
        $exactVersion = ($AlyaModuleVersionOverwrite | Where-Object { $_.name -eq $moduleName}).Version
    }
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
			try {
			    $req = Invoke-WebRequestIndep -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore
			}
			catch {
			    $req = $_.Exception.Response
			}
            if ($req.Headers.Location -eq $null)
            {
                throw "No redirection found."
            }
			$ModuleContentUrl = $req.Headers.Location.AbsoluteUri
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
        if (-Not $doNotLoadModules)
        {
            Import-Module "$ModuleContentDir\PackageManagement.psd1" -Force -Verbose
        }
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
    $psg = Get-Module -Name PowerShellGet -ListAvailable | Sort-Object -Property Version | Select-Object -Last 1
    if ($moduleName -ne "PackageManagement" -and $moduleName -ne "PowerShellGet" -and (-Not $psg -or $psg.Version -lt [Version]"2.0.0.0"))
    {
        Install-ModuleIfNotInstalled "PowerShellGet"
        throw "PowerShellGet updated! Please restart your powershell session"
    }
    if ((Get-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue).Version -lt '2.8.5.201')
    {
        Write-Warning "Installing nuget"
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
    }
    [Version]$requestedVersion = $null
    [string]$requestedVersionFullname = $null
    [bool]$moduleNotOnline = $false
    $module = $null
    if ($exactVersion -ne "0.0.0.0")
    {
        $module = Get-Module -Name $moduleName -ListAvailable | Where-Object { $_.Version -eq $exactVersion }
        if (-Not $module)
        {
            try
            {
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | Where-Object { $_.Version -eq $exactVersion }
            }
            catch
            {
                if (-Not $doNotLoadModules)
                {
                    Import-Module -Name PowerShellGet
                }
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | Where-Object { $_.Version -eq $exactVersion }
            }
            if (-Not $module)
            {
                $module = Get-Module -FullyQualifiedName "$AlyaModulePath\$moduleName" -ListAvailable -ErrorAction SilentlyContinue | Where-Object { $_.Version -eq $exactVersion }
            }
        }
        if ($null -ne $module)
        {
            $autoUpdate = $false
            $requestedVersion = $exactVersion
            $requestedVersionFullname = $exactVersion
        }
        else
        {
            $versionCheck = Get-PublishedModuleVersion $moduleName -AllowPrerelease $allowPrerelease -exactVersion $exactVersion
            if (-Not $versionCheck) {
                Write-Warning "Module '$moduleName' does not looks like a module from Powershell Gallery"
                $requestedVersion = $exactVersion
                $requestedVersionFullname = $exactVersion
                $moduleNotOnline = $true
            }
            else {
                $requestedVersion = $versionCheck[0]
                $requestedVersionFullname = $versionCheck[1]
            }
        }
    }
    if ($minimalVersion -ne "0.0.0.0")
    {
        $module = Get-Module -Name $moduleName -ListAvailable | `
            Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            try
            {
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | `
                    Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            catch
            {
                if (-Not $doNotLoadModules)
                {
                    Import-Module -Name PowerShellGet
                }
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | `
                    Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            if (-Not $module)
            {
                $module = Get-Module -FullyQualifiedName "$AlyaModulePath\$moduleName" -ListAvailable -ErrorAction SilentlyContinue | `
                    Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
        }
        if ($null -ne $module)
        {
            $autoUpdate = $false
            $requestedVersion = $module.Version
            $requestedVersionFullname = $module.Version
        }
    }
    if ($null -eq $requestedVersion)
    {
        $versionCheck = Get-PublishedModuleVersion $moduleName -AllowPrerelease $allowPrerelease
        if (-Not $versionCheck) {
            Write-Warning "Module '$moduleName' does not looks like a module from Powershell Gallery"
            $module = Get-Module -Name $moduleName -ListAvailable | Sort-Object -Property Version | Select-Object -Last 1
            $requestedVersion = $module.Version
            $requestedVersionFullname = $module.Version
            $moduleNotOnline = $true
        }
        else {
            $requestedVersion = $versionCheck[0]
            $requestedVersionFullname = $versionCheck[1]
        }
    }
    if ($null -eq $module -and $exactVersion -eq "0.0.0.0" -and $minimalVersion -eq "0.0.0.0")
    {
        $module = Get-Module -Name $moduleName -ListAvailable | `
            Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            try
            {
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | `
                    Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            catch
            {
                if (-Not $doNotLoadModules)
                {
                    Import-Module -Name PowerShellGet
                }
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | `
                    Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            if (-Not $module)
            {
                $module = Get-Module -FullyQualifiedName "$AlyaModulePath\$moduleName" -ListAvailable -ErrorAction SilentlyContinue | `
                    Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
        }
    }
    if ($module)
    {
        Write-Host ('Module {0} is installed. Used:v{1} Requested:v{2}' -f $moduleName, $module.Version, $requestedVersion)
        if ((-Not $autoUpdate) -and ($requestedVersion -gt $module.Version))
        {
            Write-Warning ("A newer version (v{0}) is available. Consider upgrading!" -f $newestVersion)
        }
        if ($requestedVersion -eq $module.Version)
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
        $installModuleHasPrerelease = $null -ne ((Get-Command Install-Module).Parameters.GetEnumerator() | Where-Object { $_.Key -eq "AllowPrerelease" })
        if (-Not $installModuleHasPrerelease)
        {
            $installModuleHasPrerelease = (Get-Command Install-Module).ParameterSets | Select-Object -ExpandProperty Parameters | Where-Object { $_.Name -eq "AllowPrerelease" }
        }
        $installModuleHasAcceptLicense = $null -ne ((Get-Command Install-Module).Parameters.GetEnumerator() | Where-Object { $_.Key -eq "AcceptLicense" })
        if (-Not $installModuleHasAcceptLicense)
        {
            $installModuleHasAcceptLicense = (Get-Command Install-Module).ParameterSets | Select-Object -ExpandProperty Parameters | Where-Object { $_.Name -eq "AcceptLicense" }
        }
        $saveModuleHasPrerelease = $null -ne ((Get-Command Save-Module).Parameters.GetEnumerator() | Where-Object { $_.Key -eq "AllowPrerelease" })
        if (-Not $saveModuleHasPrerelease)
        {
            $saveModuleHasPrerelease = (Get-Command Save-Module).ParameterSets | Select-Object -ExpandProperty Parameters | Where-Object { $_.Name -eq "AllowPrerelease" }
        }
        $saveModuleHasAcceptLicense = $null -ne ((Get-Command Save-Module).Parameters.GetEnumerator() | Where-Object { $_.Key -eq "AcceptLicense" })
        if (-Not $saveModuleHasAcceptLicense)
        {
            $saveModuleHasAcceptLicense = (Get-Command Save-Module).ParameterSets | Select-Object -ExpandProperty Parameters | Where-Object { $_.Name -eq "AcceptLicense" }
        }
        if (-Not $moduleNotOnline)
        {
            $optionalArgs = New-Object -TypeName Hashtable
            $optionalArgs['RequiredVersion'] = $requestedVersionFullname
            Write-Warning ('Installing/Updating module {0} to version [{1}] within scope of the current user.' -f $moduleName, $requestedVersion)
            #TODO Unload module
            if ($installModuleHasAcceptLicense)
            {
                if ($AlyaModulePath -eq $AlyaDefaultModulePath)
                {
                    if ($installModuleHasPrerelease)
                    {
                        Install-Module -Name $moduleName @optionalArgs -Scope CurrentUser -AllowClobber -AllowPrerelease:$allowPrerelease -Force -Verbose -AcceptLicense
                    }
                    else
                    {
                        Install-Module -Name $moduleName @optionalArgs -Scope CurrentUser -AllowClobber -Force -Verbose -AcceptLicense
                    }
                }
                else
                {
                    if ($saveModuleHasPrerelease)
                    {
                        Save-Module -Name $moduleName -RequiredVersion $requestedVersionFullname -Path $AlyaModulePath -AllowPrerelease:$allowPrerelease -Force -Verbose -AcceptLicense
                    }
                    else
                    {
                        Save-Module -Name $moduleName -RequiredVersion $requestedVersionFullname -Path $AlyaModulePath -Force -Verbose -AcceptLicense
                    }
                }
            }
            else
            {
                if ($AlyaModulePath -eq $AlyaDefaultModulePath)
                {
                    if ($installModuleHasPrerelease)
                    {
                        Install-Module -Name $moduleName @optionalArgs -Scope CurrentUser -AllowClobber -AllowPrerelease:$allowPrerelease -Force -Verbose
                    }
                    else
                    {
                        Install-Module -Name $moduleName @optionalArgs -Scope CurrentUser -AllowClobber -Force -Verbose
                    }
                }
                else
                {
                    if ($saveModuleHasPrerelease)
                    {
                        Save-Module -Name $moduleName -RequiredVersion $requestedVersionFullname -Path $AlyaModulePath -AllowPrerelease:$allowPrerelease -Force -Verbose
                    }
                    else
                    {
                        Save-Module -Name $moduleName -RequiredVersion $requestedVersionFullname -Path $AlyaModulePath -Force -Verbose
                    }
                }
            }
        }
        $module = Get-Module -Name $moduleName -ListAvailable | `
            Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            try
            {
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | `
                    Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            catch
            {
                Import-Module -Name PowerShellGet
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue | `
                    Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            if (-Not $module)
            {
                $module = Get-Module -FullyQualifiedName "$AlyaModulePath\$moduleName" -ListAvailable -ErrorAction SilentlyContinue | `
                    Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
                if (-Not $module)
	            {
	                Write-Warning "Not able to install the module $moduleName!" -ErrorAction Continue
	            }
	        }
	    }
    }
    if ($exactVersion -ne "0.0.0.0" -or $allowPrerelease)
    {
        $tmodule = Get-Module -Name $moduleName
        if ($tmodule -and $tmodule.Version -ne $requestedVersion)
        {
            Remove-Module -Name $moduleName
        }
        if (-Not $doNotLoadModules)
        {
            Import-Module -Name $moduleName -MinimumVersion $requestedVersion -MaximumVersion $requestedVersion
        }
    }
    if ($AlyaIsPsCore -and $moduleName -in @(
        "Microsoft.Online.Sharepoint.PowerShell", "MSOnline", "AzureADPreview", "AIPService", "AppX",
        "Microsoft.PowerApps.Administration.PowerShell", "Microsoft.PowerApps.PowerShell"))
    {
        if (-Not $doNotLoadModules)
        {
            Import-Module -Name $moduleName -UseWindowsPowershell
        }
    }
}
#Install-ModuleIfNotInstalled "AppX"
#Install-ModuleIfNotInstalled "ImportExcel"
#Install-ModuleIfNotInstalled "PowerShellGet"
#Install-ModuleIfNotInstalled "Az.Accounts"
#Install-ModuleIfNotInstalled "Az.Resources"
#Get-Module -Name Az
#Get-InstalledModule -Name Az
#Install-ModuleIfNotInstalled "Az.Compute" -exactVersion "6.3.0"

function Install-ScriptIfNotInstalled (
    [string] [Parameter(Mandatory = $true)] $scriptName,
    [Version] $minimalVersion = "0.0.0.0",
    [Version] $exactVersion = "0.0.0.0",
    [bool] $autoUpdate = $true,
    [bool] $allowPrerelease = $false
)
{
    if (-Not (Is-InternetConnected))
    {
        Write-Warning "No internet connection. Not able to check any script!"
        return
    }
    [Version]$requestedVersion = $null
    [string]$requestedVersionFullname = $null
    if ($exactVersion -ne "0.0.0.0")
    {
        $script = Get-InstalledScript -Name $scriptName -ErrorAction SilentlyContinue | Where-Object { $_.Version -eq $exactVersion }
        if ($AlyaIsPsUnix -and $null -eq $script)
        {
            $script = Get-Command -CommandType ExternalScript -ErrorAction SilentlyContinue | Where-Object { $_.Name.Replace(".ps1","").Replace(".PS1","") -eq $scriptName <#-and $_.Version -eq $exactVersion#> }
        }
        if ($null -ne $script)
        {
            $autoUpdate = $false
            $requestedVersion = $exactVersion
            $requestedVersionFullname = $exactVersion
        }
        else
        {
            $versionCheck = Get-PublishedModuleVersion $scriptName -AllowPrerelease $allowPrerelease -exactVersion $exactVersion
            if (-Not $versionCheck)
            {
                Write-Warning "Script '$scriptName' does not looks like a script from Powershell Gallery"
                return
            }
            $requestedVersion = $versionCheck[0]
            $requestedVersionFullname = $versionCheck[1]
        }
    }
    if ($minimalVersion -ne "0.0.0.0")
    {
        $script = Get-InstalledScript -Name $scriptName -ErrorAction SilentlyContinue | `
            Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if ($AlyaIsPsUnix -and $null -eq $script)
        {
            $script = Get-Command -CommandType ExternalScript -ErrorAction SilentlyContinue| `
                Where-Object { $_.Name.Replace(".ps1","").Replace(".PS1","") -eq $scriptName <#-and $_.Version -ge $minimalVersion#> } | Sort-Object -Property Version | Select-Object -Last 1
        }
        if ($null -ne $script)
        {
            $autoUpdate = $false
            $requestedVersion = $script.Version
            $requestedVersionFullname = $script.Version
        }
    }
    if ($null -eq $requestedVersion)
    {
        $versionCheck = Get-PublishedModuleVersion $scriptName -AllowPrerelease $allowPrerelease
        if (-Not $versionCheck)
        {
            Write-Warning "Script '$scriptName' does not looks like a script from Powershell Gallery"
            return
        }
        $requestedVersion = $versionCheck[0]
        $requestedVersionFullname = $versionCheck[1]
    }
    if ($null -eq $script -and $exactVersion -eq "0.0.0.0" -and $minimalVersion -eq "0.0.0.0")
    {
        $script = Get-InstalledScript -Name $scriptName -ErrorAction SilentlyContinue | `
            Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if ($AlyaIsPsUnix -and $null -eq $script)
        {
            $script = Get-Command -CommandType ExternalScript -ErrorAction SilentlyContinue | `
                Where-Object { $_.Name.Replace(".ps1","").Replace(".PS1","") -eq $scriptName <#-and $_.Version -ge $minimalVersion#> } | Sort-Object -Property Version | Select-Object -Last 1
        }
    }
    if ($script)
    {
        Write-Host ('Script {0} is installed. Used:v{1} Requested:v{2}' -f $scriptName, $script.Version, $requestedVersion)
        if ((-Not $autoUpdate) -and ($requestedVersion -gt $script.Version))
        {
            Write-Warning ("A newer version (v{0}) is available. Consider upgrading!" -f $script.Version)
        }
        if ($requestedVersion -eq $script.Version)
        {
            $autoUpdate = $false
        }
    }
    else
    {
        Write-Host ('Script {0} not found with requested version v{1}. Installing now...' -f $scriptName, $requestedVersion)
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
        $paramAL = (Get-Command Install-Script).ParameterSets | Select-Object -ExpandProperty Parameters | Where-Object { $_.Name -eq "AcceptLicense" }
        if ($paramAL)
        {
            Install-Script -Name $scriptName @optionalArgs -Scope CurrentUser -AcceptLicense -Force -Verbose
        }
        else
        {
            Install-Script -Name $scriptName @optionalArgs -Scope CurrentUser -Force -Verbose
        }
        $script = Get-InstalledScript -Name $scriptName -ErrorAction SilentlyContinue | `
            Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if ($AlyaIsPsUnix -and $null -eq $script)
        {
            $script = Get-Command -CommandType ExternalScript -ErrorAction SilentlyContinue | `
                Where-Object { $_.Name.Replace(".ps1","").Replace(".PS1","") -eq $scriptName <#-and $_.Version -ge $minimalVersion#> } | Sort-Object -Property Version | Select-Object -Last 1
        }
        if (-Not $script)
        {
            Write-Error "Not able to install the script!" -ErrorAction Continue
            exit
        }

        if ($AlyaScriptPath -ne $AlyaDefaultScriptPath -and $AlyaScriptPath -ne $AlyaDefaultScriptPathCore)
        {
            #TODO move to $AlyaScriptPath

        }
    }
}
#Install-ScriptIfNotInstalled "Get-WindowsAutoPilotInfo"

<# DEVOPS FUNCTIONS #>

function Get-JwtExpiration {
    param ([string]$jwt)
    $parts = $jwt.Split('.')
    if ($parts.Length -ne 3) { return $null }
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }
    $bytes = [System.Convert]::FromBase64String($payload)
    $json = [System.Text.Encoding]::UTF8.GetString($bytes)
    return ($json | ConvertFrom-Json).exp
}

function Refresh-DevOpsOidcToken {
    Param(
        [Parameter()]
        [string]
        $AccessToken = $env:AlyaDevOpsAccessToken,
        [Parameter()]
        [string]
        $OidcRequestUri = $env:AlyaDevOpsOidcRequestUri
    )

    if ([string]::IsNullOrEmpty($AccessToken))
    {
        throw "No access token specified!"
    }
    try {
        $exp = Get-JwtExpiration -jwt $AccessToken
        $now = [int][double]::Parse((Get-Date -UFormat %s))
        $expInMinutes = [Math]::Round(($exp - $now) / 60, 2)
    }
    catch {
        Write-Host "Exception: $($_.Exception)"
    }
    if ($expInMinutes -lt 0)
    {
        throw "Access token already expired since $expInMinutes minutes! Not able to refresh OpenID Connect token."
    }

    Write-Host "Checking existing OpenID Connect token"
    try {
        $oidcToken = $env:idToken
        if ([string]::IsNullOrEmpty($oidcToken))
        {
            if ([string]::IsNullOrEmpty($env:AlyaDevOpsIdToken))
            {
                throw "Unable to determine oidcToken."
            }
            $env:idToken = $env:AlyaDevOpsIdToken
        }
        $exp = Get-JwtExpiration -jwt $env:idToken
        $now = [int][double]::Parse((Get-Date -UFormat %s))
        $expInMinutes = [Math]::Round(($exp - $now) / 60, 2)
    }
    catch {
            Write-Error "Exception: $($_.Exception)" -ErrorAction Continue
            throw
    }

    if ($expInMinutes -ge 2)
    {
        Write-Host "OpenID Connect token expires in $expInMinutes minutes. Refresh not required."
    }
    else
    {

        Write-Host "Refreshing OpenID Connect token"
        if ([string]::IsNullOrEmpty($OidcRequestUri))
        {
            throw "OidcRequestUri is not configured"
        }
        else
        {
            if ($OidcRequestUri -notlike "*serviceConnectionId=*")
            {
                throw "Missing serviceConnectionId in OidcRequestUri: $OidcRequestUri"
            }
            $IdTokenUri = $OidcRequestUri
        }
        try {
            $Response = Invoke-RestMethod -Headers @{
                    Authorization  = "Bearer $AccessToken"
                    'Content-Type' = 'application/json'
                } `
                -Uri $IdTokenUri `
                -Method Post
        }
        catch {
            Write-Host $_.Exception
            Write-Host "$($response | ConvertTo-Json -Depth 5)"
            throw
        }
        $env:idToken = $Response.oidctoken

        try {
            $exp = Get-JwtExpiration -jwt $env:idToken
            $now = [int][double]::Parse((Get-Date -UFormat %s))
            $expInMinutes = [Math]::Round(($exp - $now) / 60, 2)
            Write-Host "  expires in $expInMinutes minutes"
        }
        catch {
            Write-Error "Exception: $($_.Exception)" -ErrorAction Continue
            throw
        }
        if ($expInMinutes -le 9)
        {
            throw "OpenID Connect token refresh failed."
        }

    }

}

<# LOGIN FUNCTIONS #>
function LogoutAllFrom-Az()
{
    Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue
    Clear-AzContext -Scope CurrentUser -Force -ErrorAction SilentlyContinue
    [Environment]::SetEnvironmentVariable("AlyaManagementApp", "", "Process")
    [Environment]::SetEnvironmentVariable("AlyaManagementCrt", "", "Process")
    [Environment]::SetEnvironmentVariable("AlyaManagementPwd", "", "Process")
    Get-ChildItem -Path $env:TEMP -Filter "$AlyaTenantId-*.xpy" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-Item -Path "$($env:TEMP)\$AlyaTenantId-Actual.env" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}
function Get-CustomersContext(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName = $null,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId = $null,
    [string] [Parameter(Mandatory = $false)] $TenantId = $null)
{
    $context = $null
    if (-Not $TenantId) { $TenantId = $AlyaTenantId }
    if ($SubscriptionId)
    {
        try {
            $context = Get-AzContext -ListAvailable | Where-Object { $_.Name -like "*$SubscriptionId*$TenantId*" }
        } catch {
            $context = Get-AzContext | Where-Object { $_.Name -like "*$SubscriptionId*$TenantId*" }
        }
    }
    elseif ($SubscriptionName)
    {
        try {
            $context = Get-AzContext -ListAvailable | Where-Object { $_.Name -like "*$SubscriptionName*$TenantId*" }
        } catch {
            $context = Get-AzContext | Where-Object { $_.Name -like "*$SubscriptionName*$TenantId*" }
        }
    }
    else
    {
        try {
            $context = Get-AzContext -ListAvailable | Where-Object { $_.Name -like "*$TenantId*" }
        } catch {
            $context = Get-AzContext | Where-Object { $_.Name -like "*$TenantId*" }
        }
    }
    if ($context -and $context.Count -gt 1) { $context = $context[0] }
    return $context
}
function LogoutFrom-Az(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName = $null,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId = $null,
    [string] [Parameter(Mandatory = $false)] $TenantId = $null)
{
    $AlyaContext = Get-CustomersContext -TenantId $TenantId -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    if ($AlyaContext)
    {
        Logout-AzAccount -ContextName $AlyaContext.Name -ErrorAction SilentlyContinue | Out-Null
        Remove-AzAccount -ContextName $AlyaContext.Name -ErrorAction SilentlyContinue | Out-Null
        Remove-AzContext -InputObject $AlyaContext -ErrorAction SilentlyContinue | Out-Null
        $AlyaContext = $null
    }
    [Environment]::SetEnvironmentVariable("AlyaManagementApp", "", "Process")
    [Environment]::SetEnvironmentVariable("AlyaManagementCrt", "", "Process")
    [Environment]::SetEnvironmentVariable("AlyaManagementPwd", "", "Process")
    Get-ChildItem -Path $env:TEMP -Filter "$AlyaTenantId-*.xpy" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-Item -Path "$($env:TEMP)\$AlyaTenantId-Actual.env" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}
function LoginTo-Az(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName = $null,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId = $null,
    [string] [Parameter(Mandatory = $false)] $AuthScope = $null,
    [string] [Parameter(Mandatory = $false)] $TenantId = $null)
{
    Write-Host "Login to Az" -ForegroundColor $CommandInfo
    if (-Not $TenantId) { $TenantId = $AlyaTenantId }

    try { Update-AzConfig -Scope Process -EnableLoginByWam $AlyaWamEnabled -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Update-AzConfig -Scope Process -DisplaySurveyMessage $false -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Update-AzConfig -Scope Process -EnableDataCollection $false -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Update-AzConfig -Scope Process -DefaultSubscriptionForLogin $AlyaSubscriptionName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}

    if (Test-Path "$($env:TEMP)\$AlyaTenantId-Actual.env")
    {
        $envVars = Get-Content "$($env:TEMP)\$AlyaTenantId-Actual.env" | ConvertFrom-Json -AsHashtable
        foreach ($key in $envVars.Keys)
        {
            [Environment]::SetEnvironmentVariable($key, $envVars[$key], "Process")
        }
    }

    if ($AlyaIsDevOpsPipeline)
    {
        Write-Host "  within DevOps"
        Refresh-DevOpsOidcToken
        $AlyaContext = Get-CustomersContext
        if (-Not $AlyaContext)
        {
            throw "Not able to get DevOps az context. Please select a connection in the pipeline task."
        }
    }
    else 
    {
        if ($env:AlyaManagementCrt)
        {
            $AlyaContext = $null
        }
        else
        {
            $AlyaContext = Get-CustomersContext -TenantId $TenantId -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
            if ($AlyaContext)
            {
                Write-Host "  checking existing az context"
                if ($AlyaContext.Count -gt 1)
                {
                    $AlyaContext = Select-Item -message "Please select an existing context" -list $AlyaContext
                }
                if ($AlyaContext.Tenant.Id -ne $TenantId)
                {
                    Logout-AzAccount -ContextName $AlyaContext.Name -ErrorAction SilentlyContinue | Out-Null
                    Remove-AzAccount -ContextName $AlyaContext.Name -ErrorAction SilentlyContinue | Out-Null
                    Remove-AzContext -InputObject $AlyaContext -ErrorAction SilentlyContinue | Out-Null
                    $AlyaContext = $null
                }
                else
                {
                    $actContext = Get-AzContext
                    if ($actContext.Name -ne $AlyaContext.Name)
                    {
                        Set-AzContext -Context $AlyaContext -Force | Out-Null
                    }
                    $user = Get-AzAdUser -UserPrincipalName $actContext.Account.Id -ErrorAction SilentlyContinue
                    if (-Not $user)
                    {
                        $user = Get-AzAdUser -Mail $actContext.Account.Id -ErrorAction SilentlyContinue
                    }
                    if (-Not $user)
                    {
                        Write-Host "  existing context not working"
                        Logout-AzAccount -ContextName $AlyaContext.Name -ErrorAction SilentlyContinue | Out-Null
                        Remove-AzAccount -ContextName $AlyaContext.Name -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                        Remove-AzContext -InputObject $AlyaContext -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                        $AlyaContext = $null
                    }
                }
            }
        }
        if (-Not $AlyaContext)
        {
            $params = @{
                Environment = $AlyaAzureEnvironment
                Tenant      = $TenantId
            }
            if ($AuthScope)
            {
                $params["AuthScope"] = $AuthScope
            }
            if ($SubscriptionId)
            {
                $params["Subscription"] = $SubscriptionId
            }
            elseif ($SubscriptionName)
            {
                $params["Subscription"] = $SubscriptionName
            }
            if ($env:AlyaManagementCrt)
            {
                Write-Host "Login to Az with management app" -ForegroundColor $CommandInfo
                $params["CertificatePath"] = $env:AlyaManagementCrt
                $params["CertificatePassword"] = (ConvertTo-SecureString -String $env:AlyaManagementPwd -AsPlainText -Force)
                $params["ApplicationId"] = $env:AlyaManagementApp
            }
            Connect-AzAccount @params | Out-Null
            $AlyaContext = Get-CustomersContext -TenantId $TenantId -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
        else
        {
            Set-AzContext -Context $AlyaContext | Out-Null
        }
    }
    if (-Not $AlyaContext)
    {
        Write-Error "Not logged in to Az!" -ErrorAction Continue
        Exit 1
    }
    $sameSub = $false
    if (-Not [string]::IsNullOrEmpty($SubscriptionId))
    {
        $sameSub = ($AlyaContext.Subscription.Id -eq $SubscriptionId)
    }
    else
    {
        if (-Not [string]::IsNullOrEmpty($SubscriptionName))
        {
            $sameSub = ($AlyaContext.Subscription.Name -eq $SubscriptionName)
        }
        else
        {
            $sameSub = $true #Doesn't matter
        }
    }
    if (-Not $sameSub)
    {
        Write-Host "Selecting subscription" -ForegroundColor $CommandInfo
        $sub = $null
        if (-Not [string]::IsNullOrEmpty($SubscriptionId))
        {
            $sub = Get-AzSubscription | Where-Object { $_.Id -eq $SubscriptionId }
        }
        else
        {
            if (-Not [string]::IsNullOrEmpty($SubscriptionName))
            {
                $sub = Get-AzSubscription | Where-Object { $_.Name -eq $SubscriptionName }
            }
            else
            {
                $sub = $AlyaContext.Subscription
            }
        }
        if ($sub)
        {
            Set-AzContext -SubscriptionObject $sub  | Out-Null
        }
        else
        {
            Get-AzSubscription -ErrorAction SilentlyContinue
            throw "Subscription $($SubscriptionId)$($SubscriptionName) not found"
        }
    }
}
#LoginTo-Az -SubscriptionName $AlyaSubscriptionName

function LogoutAllFrom-MgGraph()
{
    Disconnect-MgGraph
    [Environment]::SetEnvironmentVariable("AlyaManagementApp", "", "Process")
    [Environment]::SetEnvironmentVariable("AlyaManagementCrt", "", "Process")
    [Environment]::SetEnvironmentVariable("AlyaManagementPwd", "", "Process")
    Get-ChildItem -Path $env:TEMP -Filter "$AlyaTenantId-*.xpy" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-Item -Path "$($env:TEMP)\$AlyaTenantId-Actual.env" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}
function LoginTo-MgGraph(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName = $null,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId = $null,
    [string[]] [Parameter(Mandatory = $false)] $Scopes = $null,
    [string] [Parameter(Mandatory = $false)] $ClientId = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateThumbprint = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateFile = $null,
    [SecureString] [Parameter(Mandatory = $false)] $ClientCertificatePassword = $null
)
{
    if (Test-Path "$($env:TEMP)\$AlyaTenantId-Actual.env")
    {
        $envVars = Get-Content "$($env:TEMP)\$AlyaTenantId-Actual.env" | ConvertFrom-Json -AsHashtable
        foreach ($key in $envVars.Keys)
        {
            [Environment]::SetEnvironmentVariable($key, $envVars[$key], "Process")
        }
    }
    
    if ($env:AlyaManagementCrt)
    {
        Write-Host "Login to Graph with management app" -ForegroundColor $CommandInfo
        $ClientCertificateFile = $env:AlyaManagementCrt
        $ClientCertificatePassword = (ConvertTo-SecureString -String $env:AlyaManagementPwd -AsPlainText -Force)
        $ClientId = $env:AlyaManagementApp
    }
    elseif (-Not [string]::IsNullOrEmpty($ClientId) -and $ClientCertificateThumbprint)
    {
        Write-Host "Login to Graph with app '$($ClientId)'" -ForegroundColor $CommandInfo
        $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        if (-Not $cert)
        {
            $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        }
        if (-Not $cert)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' not found"
        }
        if (-Not $cert.HasPrivateKey)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' does not has a private key"
        }
    }
    else
    {
        Write-Host "Login to Graph" -ForegroundColor $CommandInfo
    }

    try { Set-MgGraphOption -EnableLoginByWAM $AlyaWamEnabled -ErrorAction SilentlyContinue | Out-Null } catch {}

    if ($AlyaIsDevOpsPipeline)
    {
        Write-Host "  within DevOps"
        Refresh-DevOpsOidcToken
        try {

            $mgContext = Get-MgContext | Where-Object { $_.TenantId -eq $AlyaTenantId } -ErrorAction SilentlyContinue
            if ($mgContext)
            {
                Write-Host "  checking existing graph context"
                foreach($Scope in $Scopes)
                {
                    if ($mgContext.Scopes -notcontains $Scope)
                    {
                        $mgContext = $null
                        break
                    }
                }
            }

            if (-Not $mgContext)
            {
                $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -TenantId $AlyaTenantId -AsSecureString
                Connect-MGGraph -AccessToken $token.Token -Environment $AlyaGraphEnvironment -NoWelcome

                $mgContext = Get-MgContext | Where-Object { $_.TenantId -eq $AlyaTenantId } -ErrorAction SilentlyContinue
                if (-Not $mgContext)
                {
                    throw "Not able to get DevOps graph context without login."
                }
            }

        }
        catch
        {

            Write-Error $_.Exception -ErrorAction Continue
            Write-Warning "Getting token failed. Trying LoginTo-Az"

            try {
                LoginTo-Az -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
                $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -TenantId $AlyaTenantId -AsSecureString
                Connect-MGGraph -AccessToken $token.Token -Environment $AlyaGraphEnvironment -NoWelcome
                
                $mgContext = Get-MgContext | Where-Object { $_.TenantId -eq $AlyaTenantId } -ErrorAction SilentlyContinue
                if (-Not $mgContext)
                {
                    throw "Not able to get DevOps graph context. Please select a connection in the pipeline task."
                }
            }
            catch {
                Write-Error $_.Exception -ErrorAction Continue
                Write-Warning "LoginTo-Az failed"
            }
            
        }
        
    }
    else 
    {
        $mgContext = Get-MgContext | Where-Object { $_.TenantId -eq $AlyaTenantId } -ErrorAction SilentlyContinue
        if ($mgContext)
        {
            Write-Host "  checking existing graph context"
            foreach($Scope in $Scopes)
            {
                if ($mgContext.Scopes -notcontains $Scope)
                {
                    $mgContext = $null
                    break
                }
            }
        }

        if (-Not $mgContext)
        {
            if (-Not [string]::IsNullOrEmpty($ClientId)) {
                if (-Not [string]::IsNullOrEmpty($ClientCertificateThumbprint)) {
                    Connect-MGGraph -Environment $AlyaGraphEnvironment -ClientId $ClientId -CertificateThumbprint $ClientCertificateThumbprint -TenantId $AlyaTenantId -NoWelcome
                } elseif (-Not [string]::IsNullOrEmpty($ClientCertificateFile) -and $ClientCertificatePassword) {
                    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($ClientCertificateFile, $ClientCertificatePassword)
                    Connect-MGGraph -Environment $AlyaGraphEnvironment -ClientId $ClientId -Certificate $cert -TenantId $AlyaTenantId -NoWelcome
                } else {
                    throw "For client authentication, either ClientCertificateThumbprint or ClientCertificateFile with ClientCertificatePassword must be provided."
                }
            } else {
                if ($null -ne $AlyaGraphAppId) {
                    Connect-MGGraph -Environment $AlyaGraphEnvironment -ClientId $AlyaGraphAppId -Scopes $Scopes -TenantId $AlyaTenantId -NoWelcome
                } else {
                    Connect-MGGraph -Environment $AlyaGraphEnvironment -Scopes $Scopes -TenantId $AlyaTenantId -NoWelcome
                }
            }

            $mgContext = Get-MgContext | Where-Object { $_.TenantId -eq $AlyaTenantId } -ErrorAction SilentlyContinue
            if (-Not $Global:AlyaMgContext)
            {
                #Required after a consent, otherwise you run into a login mess
                # TODO check bug still there, way to check if consent happended
                $mgContext = Disconnect-MgGraph
                if (-Not [string]::IsNullOrEmpty($ClientId)) {
                    if (-Not [string]::IsNullOrEmpty($ClientCertificateThumbprint)) {
                        Connect-MGGraph -Environment $AlyaGraphEnvironment -ClientId $ClientId -CertificateThumbprint $ClientCertificateThumbprint -TenantId $AlyaTenantId -NoWelcome
                    } elseif (-Not [string]::IsNullOrEmpty($ClientCertificateFile) -and $ClientCertificatePassword) {
                        $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($ClientCertificateFile, $ClientCertificatePassword)
                        Connect-MGGraph -Environment $AlyaGraphEnvironment -ClientId $ClientId -Certificate $cert -TenantId $AlyaTenantId -NoWelcome
                    } else {
                        throw "For client authentication, either ClientCertificateThumbprint or ClientCertificateFile with ClientCertificatePassword must be provided."
                    }
                } else {
                    if ($null -ne $AlyaGraphAppId) {
                        Connect-MGGraph -Environment $AlyaGraphEnvironment -ClientId $AlyaGraphAppId -Scopes $Scopes -TenantId $AlyaTenantId -NoWelcome
                    } else {
                        Connect-MGGraph -Environment $AlyaGraphEnvironment -Scopes $Scopes -TenantId $AlyaTenantId -NoWelcome
                    }
                }
                $mgContext = Get-MgContext | Where-Object { $_.TenantId -eq $AlyaTenantId } -ErrorAction SilentlyContinue
                $Global:AlyaMgContext = $mgContext
            }

            if ($null -eq $ClientId) {
                foreach($Scope in $Scopes)
                {
                    if ($mgContext.Scopes -notcontains $Scope)
                    {
                        Write-Error "Was not able to get required scope $Scope" -ErrorAction Continue
                        $mgContext = $null
                        break
                    }
                }
            }
        }

        if (-Not $mgContext)
        {
            Write-Error "Not logged in to Graph!" -ErrorAction Continue
            Exit 1
        }
    }
}
#LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"
#Get-MgUser -UserId "any@alyaconsulting.ch"

function LogoutAllFrom-Entra()
{
    Disconnect-Entra
    [Environment]::SetEnvironmentVariable("AlyaManagementApp", "", "Process")
    [Environment]::SetEnvironmentVariable("AlyaManagementCrt", "", "Process")
    [Environment]::SetEnvironmentVariable("AlyaManagementPwd", "", "Process")
    Get-ChildItem -Path $env:TEMP -Filter "$AlyaTenantId-*.xpy" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-Item -Path "$($env:TEMP)\$AlyaTenantId-Actual.env" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}
function LoginTo-Entra(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName = $null,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId = $null,
    [string[]] [Parameter(Mandatory = $false)] $Scopes = $null,
    [string] [Parameter(Mandatory = $false)] $ClientId = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateThumbprint = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateFile = $null,
    [SecureString] [Parameter(Mandatory = $false)] $ClientCertificatePassword = $null
)
{
    if (Test-Path "$($env:TEMP)\$AlyaTenantId-Actual.env")
    {
        $envVars = Get-Content "$($env:TEMP)\$AlyaTenantId-Actual.env" | ConvertFrom-Json -AsHashtable
        foreach ($key in $envVars.Keys)
        {
            [Environment]::SetEnvironmentVariable($key, $envVars[$key], "Process")
        }
    }
    
    if ($env:AlyaManagementCrt)
    {
        Write-Host "Login to Entra with management app" -ForegroundColor $CommandInfo
        $ClientCertificateFile = $env:AlyaManagementCrt
        $ClientCertificatePassword = (ConvertTo-SecureString -String $env:AlyaManagementPwd -AsPlainText -Force)
        $ClientId = $env:AlyaManagementApp
    }
    elseif (-Not [string]::IsNullOrEmpty($ClientId) -and $ClientCertificateThumbprint)
    {
        Write-Host "Login to Entra with app '$($ClientId)'" -ForegroundColor $CommandInfo
        $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        if (-Not $cert)
        {
            $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        }
        if (-Not $cert)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' not found"
        }
        if (-Not $cert.HasPrivateKey)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' does not has a private key"
        }
    }
    else
    {
        Write-Host "Login to Entra" -ForegroundColor $CommandInfo
    }

    if ($AlyaIsDevOpsPipeline)
    {
        Write-Host "  within DevOps"
        throw "Not yet implemented"
    }
    else 
    {
        $mgContext = Get-EntraContext | Where-Object { $_.TenantId -eq $AlyaTenantId } -ErrorAction SilentlyContinue
        if ($mgContext)
        {
            Write-Host "  checking existing entra context"
            foreach($Scope in $Scopes)
            {
                if ($mgContext.Scopes -notcontains $Scope)
                {
                    $mgContext = $null
                    break
                }
            }
        }

        if (-Not $mgContext)
        {
            if (-Not [string]::IsNullOrEmpty($ClientId)) {
                if (-Not [string]::IsNullOrEmpty($ClientCertificateThumbprint)) {
                    Connect-Entra -Environment $AlyaGraphEnvironment -ClientId $ClientId -CertificateThumbprint $ClientCertificateThumbprint -TenantId $AlyaTenantId -NoWelcome
                } elseif (-Not [string]::IsNullOrEmpty($ClientCertificateFile) -and $ClientCertificatePassword) {
                    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($ClientCertificateFile, $ClientCertificatePassword)
                    Connect-Entra -Environment $AlyaGraphEnvironment -ClientId $ClientId -Certificate $cert -TenantId $AlyaTenantId -NoWelcome
                } else {
                    throw "For client authentication, either ClientCertificateThumbprint or ClientCertificateFile with ClientCertificatePassword must be provided."
                }
            } else {
                if ($null -ne $AlyaGraphAppId) {
                    Connect-Entra -Environment $AlyaGraphEnvironment -ClientId $AlyaGraphAppId -Scopes $Scopes -TenantId $AlyaTenantId -NoWelcome
                } else {
                    Connect-Entra -Environment $AlyaGraphEnvironment -Scopes $Scopes -TenantId $AlyaTenantId -NoWelcome
                }
            }

            $mgContext = Get-EntraContext | Where-Object { $_.TenantId -eq $AlyaTenantId } -ErrorAction SilentlyContinue
            if (-Not $Global:AlyaMgContext)
            {
                #Required after a consent, otherwise you run into a login mess
                # TODO check bug still there, way to check if consent happended
                $mgContext = Disconnect-Entra
                if (-Not [string]::IsNullOrEmpty($ClientId)) {
                    if (-Not [string]::IsNullOrEmpty($ClientCertificateThumbprint)) {
                        Connect-Entra -Environment $AlyaGraphEnvironment -ClientId $ClientId -CertificateThumbprint $ClientCertificateThumbprint -TenantId $AlyaTenantId -NoWelcome
                    } elseif (-Not [string]::IsNullOrEmpty($ClientCertificateFile) -and $ClientCertificatePassword) {
                        $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($ClientCertificateFile, $ClientCertificatePassword)
                        Connect-Entra -Environment $AlyaGraphEnvironment -ClientId $ClientId -Certificate $cert -TenantId $AlyaTenantId -NoWelcome
                    } else {
                        throw "For client authentication, either ClientCertificateThumbprint or ClientCertificateFile with ClientCertificatePassword must be provided."
                    }
                } else {
                    if ($null -ne $AlyaGraphAppId) {
                        Connect-Entra -Environment $AlyaGraphEnvironment -ClientId $AlyaGraphAppId -Scopes $Scopes -TenantId $AlyaTenantId -NoWelcome
                    } else {
                        Connect-Entra -Environment $AlyaGraphEnvironment -Scopes $Scopes -TenantId $AlyaTenantId -NoWelcome
                    }
                }
                $mgContext = Get-EntraContext | Where-Object { $_.TenantId -eq $AlyaTenantId } -ErrorAction SilentlyContinue
                $Global:AlyaMgContext = $mgContext
            }

            if ($null -eq $ClientId) {
                foreach($Scope in $Scopes)
                {
                    if ($mgContext.Scopes -notcontains $Scope)
                    {
                        Write-Error "Was not able to get required scope $Scope" -ErrorAction Continue
                        $mgContext = $null
                        break
                    }
                }
            }
        }

        if (-Not $mgContext)
        {
            Write-Error "Not logged in to Entra!" -ErrorAction Continue
            Exit 1
        }
    }
}

function LoginTo-DataGateway()
{
    Write-Host "Login to DataGateway" -ForegroundColor $CommandInfo

    if ([string]::IsNullOrEmpty($AlyaDataGatewayAppId) -or $AlyaDataGatewayAppId -eq "PleaseSpecify")
    {
        Write-Warning "We need to register the Data Gateway app"
        & "$AlyaScripts\powerplattform\Register-DataGatewayApp.ps1"
        throw "Please restart this script"
    }
    if ([string]::IsNullOrEmpty($AlyaDataGatewayAppKeyVault) -or $AlyaDataGatewayAppKeyVault -eq "PleaseSpecify")
    {
        throw "AlyaDataGatewayAppKeyVault has to be configured in ConfigureEnv.ps1"
    }
    if (([string]::IsNullOrEmpty($AlyaDataGatewayAppKeySecretName) -or $AlyaDataGatewayAppKeySecretName -eq "PleaseSpecify") -and ([string]::IsNullOrEmpty($AlyaDataGatewayAppCertificateSecretName) -or $AlyaDataGatewayAppCertificateSecretName -eq "PleaseSpecify"))
    {
        throw "AlyaDataGatewayAppKeySecretName or AlyaDataGatewayAppCertificateSecretName has to be configured in ConfigureEnv.ps1"
    }

    $isLoggedIn = $false
    try
    {
        Get-DataGatewayAccessToken
        $isLoggedIn = $true
    }
    catch { }
    if (-Not $isLoggedIn)
    {
        LoginTo-Az -SubscriptionName $AlyaSubscriptionName
        if ([string]::IsNullOrEmpty($AlyaDataGatewayAppKeySecretName) -or $AlyaDataGatewayAppKeySecretName -eq "PleaseSpecify")
        {
            throw "Not yet implemented"
        }
        else
        {
            $AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $AlyaDataGatewayAppKeyVault -Name $AlyaDataGatewayAppKeySecretName
            if (-Not $AzureKeyVaultSecret) {
                throw "Not able to find keyvault secret"
            }
            return Connect-DataGatewayServiceAccount -ApplicationId $AlyaDataGatewayAppId -ClientSecret $AzureKeyVaultSecret.SecretValue -Tenant $AlyaTenantId
        }
    }
    return $null
}

function Get-AdalAccessToken(
    [String] [Parameter(Mandatory = $false)] $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",
    [String] [Parameter(Mandatory = $false)] $redirectUri = "urn:ietf:wg:oauth:2.0:oob",
    [string] [Parameter(Mandatory = $false)] $SubscriptionName = $null,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId = $null,
    [string] [Parameter(Mandatory = $false)] $TenantId = $null)
{
	#TODO check first if type exists
    if (-Not $TenantId) { $TenantId = $AlyaTenantId }
    $module = Get-Module "AzureAdPreview" -ListAvailable
    if (-Not $module)
    {
        throw "This function requires the AzureAdPreview module loaded"
    }
    $dll = $module.FileList | Where-Object { $_ -like "*Microsoft.IdentityModel.Clients.ActiveDirectory.dll" }
    Add-Type -Path $dll
    $resourceAppIdURI = $AlyaGraphEndpoint
    $authority = "$AlyaLoginEndpoint/$AlyaTenantName"
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    $AlyaContext = Get-CustomersContext -TenantId $TenantId -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    $userUpn = $AlyaContext.Account.Id
    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($userUpn, "OptionalDisplayableId")
    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result
    return $authResult.AccessToken
}

function LoginTo-Ad(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName = $null,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId = $null,
    [string] [Parameter(Mandatory = $false)] $TenantId = $null)
{
    Write-Host "Login to AzureAd" -ForegroundColor $CommandInfo
    if (-Not $TenantId) { $TenantId = $AlyaTenantId }
    try { Disconnect-AzureAD -ErrorAction SilentlyContinue } catch {}
    $AlyaContext = Get-CustomersContext -TenantId $TenantId -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    if (-Not $AlyaContext)
    {
        throw "Please login first to Az to minimize number of logins"
    }
    $graphToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($AlyaContext.Account, $AlyaContext.Environment, $TenantId, $null, "Never", $null, $AlyaGraphEndpoint).AccessToken
    $aadToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($AlyaContext.Account, $AlyaContext.Environment, $TenantId, $null, "Never", $null, $AlyaADGraphEndpoint).AccessToken
    Connect-AzureAD -AadAccessToken $aadToken -MsAccessToken $graphToken -AccountId $AlyaContext.Account.Id -TenantId $TenantId -AzureEnvironmentName $AlyaContext.Environment.Name
    try { $TenantDetail = Get-AzureADTenantDetail -ErrorAction SilentlyContinue } catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {}
    if (-Not $TenantDetail)
    {
        Write-Error "Not logged in to AzureAd!" -ErrorAction Continue
        Exit 1
    }
}

function ReloginTo-Wvd(
    [String] [Parameter(Mandatory = $false)] $AppId = $null,
    [SecureString] [Parameter(Mandatory = $false)] $SecPwd = $null)
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
    [String] [Parameter(Mandatory = $false)] $AppId = $null,
    [SecureString] [Parameter(Mandatory = $false)] $SecPwd = $null)
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

function LoginTo-MSStore()
{
    Write-Host "Login to MSStore" -ForegroundColor $CommandInfo
    try
    {
        $apps = Get-MSStoreInventory -IncludeOffline -MaxResults 1
    }
    catch
    {
        try
        {
            if (-Not $Global:AlyaStroreCreds)
            {
                $Global:AlyaStroreCreds = Get-Credential -Message "Please provide MS Store admin credentials"
            }
            Connect-MSStore -Credentials $Global:AlyaStroreCreds
            $apps = Get-MSStoreInventory -IncludeOffline -MaxResults 1
        }
        catch
        {
            Write-Warning "Please grant access to the store app"
            Grant-MSStoreClientAppAccess
            Connect-MSStore -Credentials $Global:AlyaStroreCreds
            $apps = Get-MSStoreInventory -IncludeOffline -MaxResults 1
        }
    }
}

function LoginTo-Teams(
    [string] [Parameter(Mandatory = $false)] $ClientId = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateThumbprint = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateFile = $null,
    [SecureString] [Parameter(Mandatory = $false)] $ClientCertificatePassword = $null
)
{
    if (Test-Path "$($env:TEMP)\$AlyaTenantId-Actual.env")
    {
        $envVars = Get-Content "$($env:TEMP)\$AlyaTenantId-Actual.env" | ConvertFrom-Json -AsHashtable
        foreach ($key in $envVars.Keys)
        {
            [Environment]::SetEnvironmentVariable($key, $envVars[$key], "Process")
        }
    }
    
    if ($env:AlyaManagementCrt)
    {
        Write-Host "Login to Teams with management app" -ForegroundColor $CommandInfo
        $ClientCertificateFile = $env:AlyaManagementCrt
        $ClientCertificatePassword = (ConvertTo-SecureString -String $env:AlyaManagementPwd -AsPlainText -Force)
        $ClientId = $env:AlyaManagementApp
    }
    elseif (-Not [string]::IsNullOrEmpty($ClientId) -and $ClientCertificateThumbprint)
    {
        Write-Host "Login to Teams with app '$($ClientId)'" -ForegroundColor $CommandInfo
        $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        if (-Not $cert)
        {
            $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        }
        if (-Not $cert)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' not found"
        }
        if (-Not $cert.HasPrivateKey)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' does not has a private key"
        }
    }
    else
    {
        Write-Host "Login to Teams" -ForegroundColor $CommandInfo
    }

    $mod = Get-Module -Name MicrosoftTeams
    if (-Not $mod) { Write-Host "  loading module MicrosoftTeams..." } # import of teams module requires long time!
    try { $TenantDetail = Get-CsTenant -ErrorAction SilentlyContinue } catch {}
    if ($TenantDetail -and $TenantDetail.TenantId -ne $AlyaTenantId)
    {
        Write-Warning "Logged in to wrong teams tenant! Logging out now"
        Disconnect-MicrosoftTeams
        $TenantDetail = $null
    }

    if ($TenantDetail)
    {
        Write-Host "Already logged in"
    }
    else
    {
        if (-Not [string]::IsNullOrEmpty($ClientId)) {
            if ([string]::IsNullOrEmpty($AlyaTeamsEnvironment)) {
                if (-Not [string]::IsNullOrEmpty($ClientCertificateThumbprint)) {
                    Connect-MicrosoftTeams -ClientId $ClientId -CertificateThumbprint $ClientCertificateThumbprint -TenantId $AlyaTenantId -NoWelcome
                } elseif (-Not [string]::IsNullOrEmpty($ClientCertificateFile) -and $ClientCertificatePassword) {
                    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($ClientCertificateFile, $ClientCertificatePassword)
                    Connect-MicrosoftTeams -ClientId $ClientId -Certificate $cert -TenantId $AlyaTenantId -NoWelcome
                } else {
                    throw "For client authentication, either ClientCertificateThumbprint or ClientCertificateFile with ClientCertificatePassword must be provided."
                }
            } else {
                if (-Not [string]::IsNullOrEmpty($ClientCertificateThumbprint)) {
                    Connect-MicrosoftTeams -Environment $AlyaTeamsEnvironment -ClientId $ClientId -CertificateThumbprint $ClientCertificateThumbprint -TenantId $AlyaTenantId -NoWelcome
                } elseif (-Not [string]::IsNullOrEmpty($ClientCertificateFile) -and $ClientCertificatePassword) {
                    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($ClientCertificateFile, $ClientCertificatePassword)
                    Connect-MicrosoftTeams -Environment $AlyaTeamsEnvironment -ClientId $ClientId -Certificate $cert -TenantId $AlyaTenantId -NoWelcome
                } else {
                    throw "For client authentication, either ClientCertificateThumbprint or ClientCertificateFile with ClientCertificatePassword must be provided."
                }
            }
        } else {
            if ([string]::IsNullOrEmpty($AlyaTeamsEnvironment)) {
                Connect-MicrosoftTeams -DisableWAM:(!$AlyaWamEnabled)
            } else {
                Connect-MicrosoftTeams -DisableWAM:(!$AlyaWamEnabled) -TeamsEnvironmentName $AlyaTeamsEnvironment
            }
        }
    }

    $TenantDetail = Get-CsTenant -ErrorAction SilentlyContinue
    if (-Not $TenantDetail)
    {
        Write-Error "Not logged in to Teams!" -ErrorAction Continue
        Exit 1
    }
}

function LoginTo-EXO(
    [String[]]$commandsToLoad = $null,
    [string] [Parameter(Mandatory = $false)] $ClientId = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateThumbprint = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateFile = $null,
    [SecureString] [Parameter(Mandatory = $false)] $ClientCertificatePassword = $null
)
{
    if (Test-Path "$($env:TEMP)\$AlyaTenantId-Actual.env")
    {
        $envVars = Get-Content "$($env:TEMP)\$AlyaTenantId-Actual.env" | ConvertFrom-Json -AsHashtable
        foreach ($key in $envVars.Keys)
        {
            [Environment]::SetEnvironmentVariable($key, $envVars[$key], "Process")
        }
    }
    
    if ($env:AlyaManagementCrt)
    {
        Write-Host "Login to EXO with management app" -ForegroundColor $CommandInfo
        $ClientCertificateFile = $env:AlyaManagementCrt
        $ClientCertificatePassword = (ConvertTo-SecureString -String $env:AlyaManagementPwd -AsPlainText -Force)
        $ClientId = $env:AlyaManagementApp
    }
    elseif (-Not [string]::IsNullOrEmpty($ClientId) -and $ClientCertificateThumbprint)
    {
        Write-Host "Login to EXO with app '$($ClientId)'" -ForegroundColor $CommandInfo
        $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        if (-Not $cert)
        {
            $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        }
        if (-Not $cert)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' not found"
        }
        if (-Not $cert.HasPrivateKey)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' does not has a private key"
        }
    }
    else
    {
        Write-Host "Login to EXO" -ForegroundColor $CommandInfo
    }

    $actConnection = Get-ConnectionInformation | Where-Object { $_.IsEopSession -eq $false -and $_.State -eq "Connected" -and $_.TenantID -eq $AlyaTenantId -and $_.TokenExpiryTimeUTC -gt [DateTime]::UtcNow }
    if (-Not $actConnection)
    {
        if ($commandsToLoad)
        {
            if (-Not [string]::IsNullOrEmpty($ClientId)) {
                if (-Not [string]::IsNullOrEmpty($ClientCertificateThumbprint)) {
                    Connect-ExchangeOnline -ExchangeEnvironmentName $AlyaExchangeEnvironment -AppId $ClientId -Organization $AlyaTenantName -CertificateThumbprint $ClientCertificateThumbprint -ShowBanner:$false -ShowProgress $true -DisableWAM:(!$AlyaWamEnabled) -CommandName $commandsToLoad
                } elseif (-Not [string]::IsNullOrEmpty($ClientCertificateFile) -and $ClientCertificatePassword) {
                    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($ClientCertificateFile, $ClientCertificatePassword)
                    Connect-ExchangeOnline -ExchangeEnvironmentName $AlyaExchangeEnvironment -AppId $ClientId -Organization $AlyaTenantName -Certificate $cert -ShowBanner:$false -ShowProgress $true -DisableWAM:(!$AlyaWamEnabled) -CommandName $commandsToLoad
                } else {
                    throw "For client authentication, either ClientCertificateThumbprint or ClientCertificateFile with ClientCertificatePassword must be provided."
                }
            } else {
                Connect-ExchangeOnline -ExchangeEnvironmentName $AlyaExchangeEnvironment -ShowBanner:$false -ShowProgress $true -DisableWAM:(!$AlyaWamEnabled) -CommandName $commandsToLoad
            }
        }
        else
        {
            if (-Not [string]::IsNullOrEmpty($ClientId)) {
                if (-Not [string]::IsNullOrEmpty($ClientCertificateThumbprint)) {
                    Connect-ExchangeOnline -ExchangeEnvironmentName $AlyaExchangeEnvironment -AppId $ClientId -Organization $AlyaTenantName -CertificateThumbprint $ClientCertificateThumbprint -ShowBanner:$false -ShowProgress $true -DisableWAM:(!$AlyaWamEnabled) 
                } elseif (-Not [string]::IsNullOrEmpty($ClientCertificateFile) -and $ClientCertificatePassword) {
                    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($ClientCertificateFile, $ClientCertificatePassword)
                    Connect-ExchangeOnline -ExchangeEnvironmentName $AlyaExchangeEnvironment -AppId $ClientId -Organization $AlyaTenantName -Certificate $cert -ShowBanner:$false -ShowProgress $true -DisableWAM:(!$AlyaWamEnabled) 
                } else {
                    throw "For client authentication, either ClientCertificateThumbprint or ClientCertificateFile with ClientCertificatePassword must be provided."
                }
            } else {
                Connect-ExchangeOnline -ExchangeEnvironmentName $AlyaExchangeEnvironment -ShowBanner:$false -ShowProgress $true -DisableWAM:(!$AlyaWamEnabled)
            }
        }
    }
}

function LoginTo-IPPS(
    [string] [Parameter(Mandatory = $false)] $ClientId = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateThumbprint = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateFile = $null,
    [SecureString] [Parameter(Mandatory = $false)] $ClientCertificatePassword = $null
)
{
    if (Test-Path "$($env:TEMP)\$AlyaTenantId-Actual.env")
    {
        $envVars = Get-Content "$($env:TEMP)\$AlyaTenantId-Actual.env" | ConvertFrom-Json -AsHashtable
        foreach ($key in $envVars.Keys)
        {
            [Environment]::SetEnvironmentVariable($key, $envVars[$key], "Process")
        }
    }
    
    if ($env:AlyaManagementCrt)
    {
        Write-Host "Login to IPPS with management app" -ForegroundColor $CommandInfo
        $ClientCertificateFile = $env:AlyaManagementCrt
        $ClientCertificatePassword = (ConvertTo-SecureString -String $env:AlyaManagementPwd -AsPlainText -Force)
        $ClientId = $env:AlyaManagementApp
    }
    elseif (-Not [string]::IsNullOrEmpty($ClientId) -and $ClientCertificateThumbprint)
    {
        Write-Host "Login to IPPS with app '$($ClientId)'" -ForegroundColor $CommandInfo
        $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        if (-Not $cert)
        {
            $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        }
        if (-Not $cert)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' not found"
        }
        if (-Not $cert.HasPrivateKey)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' does not has a private key"
        }
    }
    else
    {
        Write-Host "Login to IPPS" -ForegroundColor $CommandInfo
    }

    $actConnection = Get-ConnectionInformation | Where-Object { $_.IsEopSession -eq $true -and $_.State -eq "Connected" -and $_.TenantID -eq $AlyaTenantId -and $_.TokenExpiryTimeUTC -gt [DateTime]::UtcNow }
    if (-Not $actConnection)
    {
        if ($AlyaLoginEndpoint -eq "https://login.microsoftonline.com")
        {
            if (-Not [string]::IsNullOrEmpty($ClientId)) {
                if (-Not [string]::IsNullOrEmpty($ClientCertificateThumbprint)) {
                    Connect-IPPSSession -AppId $ClientId -CertificateThumbprint $ClientCertificateThumbprint -ShowBanner:$false -DisableWAM:(!$AlyaWamEnabled) 
                } elseif (-Not [string]::IsNullOrEmpty($ClientCertificateFile) -and $ClientCertificatePassword) {
                    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($ClientCertificateFile, $ClientCertificatePassword)
                    Connect-IPPSSession -AppId $ClientId -Certificate $cert -ShowBanner:$false -DisableWAM:(!$AlyaWamEnabled)
                } else {
                    throw "For client authentication, either ClientCertificateThumbprint or ClientCertificateFile with ClientCertificatePassword must be provided."
                }
            } else {
                Connect-IPPSSession -ShowBanner:$false -DisableWAM:(!$AlyaWamEnabled)
            }
        }
        else
        {
            if (-Not [string]::IsNullOrEmpty($ClientId)) {
                if (-Not [string]::IsNullOrEmpty($ClientCertificateThumbprint)) {
                    Connect-IPPSSession -AppId $ClientId -CertificateThumbprint $ClientCertificateThumbprint -ShowBanner:$false -DisableWAM:(!$AlyaWamEnabled) -AzureADAuthorizationEndpointUri $AlyaLoginEndpoint
                } elseif (-Not [string]::IsNullOrEmpty($ClientCertificateFile) -and $ClientCertificatePassword) {
                    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($ClientCertificateFile, $ClientCertificatePassword)
                    Connect-IPPSSession -AppId $ClientId -Certificate $cert -ShowBanner:$false -DisableWAM:(!$AlyaWamEnabled) -AzureADAuthorizationEndpointUri $AlyaLoginEndpoint
                } else {
                    throw "For client authentication, either ClientCertificateThumbprint or ClientCertificateFile with ClientCertificatePassword must be provided."
                }
            } else {
                Connect-IPPSSession -ShowBanner:$false -DisableWAM:(!$AlyaWamEnabled) -AzureADAuthorizationEndpointUri $AlyaLoginEndpoint
            }
        }
    }
}

function LogoutFrom-EXOandIPPS()
{
    Write-Host "Disconnecting from EXO and IPPS" -ForegroundColor $CommandInfo
    Disconnect-ExchangeOnline -Confirm:$false
}

function LogoutFrom-Msol()
{
    [Microsoft.Online.Administration.Automation.ConnectMsolService]::ClearUserSessionState()
}

function LoginTo-Msol(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName = $null,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId = $null,
    [string] [Parameter(Mandatory = $false)] $TenantId = $null)
{
    Write-Host "Login to MSOnline" -ForegroundColor $CommandInfo
    if (-Not $TenantId) { $TenantId = $AlyaTenantId }
    $AlyaContext = Get-CustomersContext -TenantId $TenantId -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    if (-Not $AlyaContext)
    {
        Write-Warning "Please login first to Az to minimize number of logins"
		Connect-MsolService -AzureEnvironment $AlyaAzureEnvironment
    }
	else
	{
        try {
            $graphToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($AlyaContext.Account, $AlyaContext.Environment, $TenantId, $null, "Never", $null, $AlyaGraphEndpoint).AccessToken
            $aadToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($AlyaContext.Account, $AlyaContext.Environment, $TenantId, $null, "Never", $null, $AlyaADGraphEndpoint).AccessToken
            Connect-MsolService -AdGraphAccessToken $aadToken -MsGraphAccessToken $graphToken -AzureEnvironment $AlyaContext.Environment.Name
        }
        catch {
            Connect-MsolService -AzureEnvironment $AlyaContext.Environment.Name
        }
    }
	try { $TenantDetail = Get-MsolCompanyInformation -ErrorAction SilentlyContinue } catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {}
    if (-Not $TenantDetail)
    {
        throw "Not logged in to AzureAd!"
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
        throw "Not logged in to Msol!"
    }
}

function LogoutFrom-SPO()
{
    try { Disconnect-SPOService -ErrorAction SilentlyContinue } catch {}
    try { Disconnect-SPOService -ErrorAction SilentlyContinue } catch {}
}

function LoginTo-SPO(
    [string] [Parameter(Mandatory = $false)] $AdminUrl = $null,
    [string] [Parameter(Mandatory = $false)] $ClientId = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateThumbprint = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateFile = $null,
    [SecureString] [Parameter(Mandatory = $false)] $ClientCertificatePassword = $null
)
{
    if (Test-Path "$($env:TEMP)\$AlyaTenantId-Actual.env")
    {
        $envVars = Get-Content "$($env:TEMP)\$AlyaTenantId-Actual.env" | ConvertFrom-Json -AsHashtable
        foreach ($key in $envVars.Keys)
        {
            [Environment]::SetEnvironmentVariable($key, $envVars[$key], "Process")
        }
    }
    
    if ($env:AlyaManagementCrt)
    {
        Write-Host "Login to SPO with management app" -ForegroundColor $CommandInfo
        $ClientCertificateFile = $env:AlyaManagementCrt
        $ClientCertificatePassword = (ConvertTo-SecureString -String $env:AlyaManagementPwd -AsPlainText -Force)
        $ClientId = $env:AlyaManagementApp
    }
    elseif (-Not [string]::IsNullOrEmpty($ClientId) -and $ClientCertificateThumbprint)
    {
        Write-Host "Login to SPO with app '$($ClientId)'" -ForegroundColor $CommandInfo
        $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        if (-Not $cert)
        {
            $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        }
        if (-Not $cert)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' not found"
        }
        if (-Not $cert.HasPrivateKey)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' does not has a private key"
        }
    }
    else
    {
        Write-Host "Login to SPO" -ForegroundColor $CommandInfo
    }

    if ([string]::IsNullOrEmpty($AdminUrl))
    {
        $AdminUrl = $AlyaSharePointAdminUrl
    }
    $Site = $null
    try { $Site = Get-SPOSite -Identity $AdminUrl -ErrorAction SilentlyContinue } catch {}
    if (-Not $Site)
    {
        if (-Not [string]::IsNullOrEmpty($ClientId)) {
            if (-Not [string]::IsNullOrEmpty($ClientCertificateThumbprint)) {
                Connect-SPOService -Region $AlyaSharePointEnvironment -Url $AdminUrl -ClientId $ClientId -CertificateThumbprint $ClientCertificateThumbprint
            } elseif (-Not [string]::IsNullOrEmpty($ClientCertificateFile) -and $ClientCertificatePassword) {
                $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($ClientCertificateFile, $ClientCertificatePassword)
                Connect-SPOService -Region $AlyaSharePointEnvironment -Url $AdminUrl -ClientId $ClientId -Certificate $cert
            } else {
                throw "For client authentication, either ClientCertificateThumbprint or ClientCertificateFile with ClientCertificatePassword must be provided."
            }
        } else {
            Connect-SPOService -Region $AlyaSharePointEnvironment -Url $AdminUrl -ModernAuth $true -UseSystemBrowser $true
        }
    }
    try { $Site = Get-SPOSite -Identity $AdminUrl -ErrorAction SilentlyContinue } catch {}
    if (-Not $Site)
    {
        throw "Not logged in to SPO!"
    }
}

function ReloginTo-PnP(
    [string] [Parameter(Mandatory = $true)] $Url,
    [string] [Parameter(Mandatory = $false)] $ClientId = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateThumbprint = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateFile = $null,
    [SecureString] [Parameter(Mandatory = $false)] $ClientCertificatePassword = $null
    )
{
    return LoginTo-PnP -Url $Url -ClientId $ClientId -Thumbprint $ClientCertificateThumbprint -ClientCertificateFile $ClientCertificateFile -ClientCertificatePassword $ClientCertificatePassword -Relogin $true
}

function LogoutAllFrom-PnP()
{
    foreach($Connection in $Global:AlyaPnpConnections)
    {
        if ($Connection -ne $null)
        {
            LogoutFrom-PnP -Connection $Connection
        }
    }
    $Global:AlyaPnpAdminConnection = $null
    $Global:AlyaPnpConnections = @()
    [Environment]::SetEnvironmentVariable("AlyaManagementApp", "", "Process")
    [Environment]::SetEnvironmentVariable("AlyaManagementCrt", "", "Process")
    [Environment]::SetEnvironmentVariable("AlyaManagementPwd", "", "Process")
    Get-ChildItem -Path $env:TEMP -Filter "$AlyaTenantId-*.xpy" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-Item -Path "$($env:TEMP)\$AlyaTenantId-Actual.env" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

function LogoutFrom-PnP(
    [object] [Parameter(Mandatory = $true)] $Connection
)
{
    if ($null -ne $Connection -and $null -ne $Connection.Url)
    {
        if ($Connection.ClientId -and $Connection.Thumbprint)
        {
            $Global:AlyaPnpConnections = $Global:AlyaPnpConnections | Where-Object { $_.Url.TrimEnd("/") -ne $Connection.Url.TrimEnd("/") -and $_.ClientId -ne $Connection.ClientId }
        }
        else
        {
            $Global:AlyaPnpConnections = $Global:AlyaPnpConnections | Where-Object { $_.Url.TrimEnd("/") -ne $Connection.Url.TrimEnd("/") }
        }
    }
    $Connection = $null
}

function LoginTo-PnP(
    [string] [Parameter(Mandatory = $true)] $Url,
    [string] [Parameter(Mandatory = $false)] $TenantAdminUrl = $null,
    [object] [Parameter(Mandatory = $false)] $AdminConnection = $null,
    [string] [Parameter(Mandatory = $false)] $ClientId = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateThumbprint = $null,
    [string] [Parameter(Mandatory = $false)] $ClientCertificateFile = $null,
    [SecureString] [Parameter(Mandatory = $false)] $ClientCertificatePassword = $null,
    [bool] [Parameter(Mandatory = $false)] $Relogin = $false,
    [bool] [Parameter(Mandatory = $false)] $DeviceLogin = $false
    )
{
    if (Test-Path "$($env:TEMP)\$AlyaTenantId-Actual.env")
    {
        $envVars = Get-Content "$($env:TEMP)\$AlyaTenantId-Actual.env" | ConvertFrom-Json -AsHashtable
        foreach ($key in $envVars.Keys)
        {
            [Environment]::SetEnvironmentVariable($key, $envVars[$key], "Process")
        }
    }
    
    if ($env:AlyaManagementCrt)
    {
        Write-Host "Login to SharePointPnPPowerShellOnline '$($Url)' with management app" -ForegroundColor $CommandInfo
        $ClientCertificateFile = $env:AlyaManagementCrt
        $ClientCertificatePassword = (ConvertTo-SecureString -String $env:AlyaManagementPwd -AsPlainText -Force)
        $ClientId = $env:AlyaManagementApp
    }
    elseif (-Not [string]::IsNullOrEmpty($ClientId) -and $ClientCertificateThumbprint)
    {
        Write-Host "Login to SharePointPnPPowerShellOnline '$($Url)' with app '$($ClientId)'" -ForegroundColor $CommandInfo
        $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        if (-Not $cert)
        {
            $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $ClientCertificateThumbprint }
        }
        if (-Not $cert)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' not found"
        }
        if (-Not $cert.HasPrivateKey)
        {
            throw "Certificate with thumbprint '$ClientCertificateThumbprint' does not has a private key"
        }
    }
    else
    {
        Write-Host "Login to SharePointPnPPowerShellOnline '$($Url)'" -ForegroundColor $CommandInfo
        if ([string]::IsNullOrEmpty($AlyaPnPAppId) -or $AlyaPnPAppId -eq "PleaseSpecify")
        {
            Write-Warning "We need to register the PnP app"
            & "$AlyaScripts\sharepoint\Register-PnPApp.ps1"
            throw "Please restart this script"
        }
    }

    if ($AlyaIsDevOpsPipeline)
    {
        Write-Host "  within DevOps"
        $ClientCertificatePasswordPlain = "!#$($AlyaTenantId)=%"
        $ClientCertificatePassword = ConvertTo-SecureString -String $ClientCertificatePasswordPlain -AsPlainText -Force
        $ClientCertificateFile = "$($env:TEMP)\$AlyaTenantId.xpy"
        if (-Not (Test-Path $ClientCertificateFile))
        {
            if ([string]::IsNullOrEmpty($AlyaSharePointRunAsCertificateKeyVault))
            {
                throw "AlyaSharePointRunAsCertificateKeyVault has to be configured in ConfigureEnv.ps1"
            }
            if ([string]::IsNullOrEmpty($AlyaSharePointRunAsCertificateSecretName))
            {
                throw "AlyaSharePointRunAsCertificateSecretName has to be configured in ConfigureEnv.ps1"
            }
            if ([string]::IsNullOrEmpty($AlyaSharePointRunAsClientId))
            {
                throw "AlyaSharePointRunAsClientId has to be configured in ConfigureEnv.ps1"
            }
            $ClientId = $AlyaSharePointRunAsClientId
            LoginTo-Az -SubscriptionName $AlyaSubscriptionName
            $AzureKeyVaultCert = Get-AzKeyVaultCertificate -VaultName $AlyaSharePointRunAsCertificateKeyVault -Name $AlyaSharePointRunAsCertificateSecretName
            if (-Not $AzureKeyVaultCert) {
                throw "Not able to find keyvault secret"
            }
            $CertificateRetrieved = Get-AzKeyVaultSecret -VaultName $AlyaSharePointRunAsCertificateKeyVault -Name $AlyaSharePointRunAsCertificateSecretName
            $CertificateBytes = [System.Convert]::FromBase64String(($CertificateRetrieved.SecretValue | Foreach-Object { [System.Net.NetworkCredential]::new("", $_).Password }))
            $CertCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $CertCollection.Import($CertificateBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            $ProtectedCertificateBytes = $CertCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $ClientCertificatePasswordPlain)
            [System.IO.File]::WriteAllBytes($ClientCertificateFile, $ProtectedCertificateBytes)
            Clear-Variable -Name "CertPasswordPlain" -Force -ErrorAction SilentlyContinue
            Clear-Variable -Name "CertificateBytes" -Force -ErrorAction SilentlyContinue
            Clear-Variable -Name "ProtectedCertificateBytes" -Force -ErrorAction SilentlyContinue
        }
    }
    
    if ([string]::IsNullOrEmpty($TenantAdminUrl))
    {
        $TenantAdminUrl = $AlyaSharePointAdminUrl
    }
    if ($null -eq $AdminConnection -and $null -ne $Global:AlyaPnpAdminConnection -and  $null -ne $TenantAdminUrl -and $Global:AlyaPnpAdminConnection.Url.TrimEnd("/") -eq $TenantAdminUrl.TrimEnd("/"))
    {
        $AdminConnection = $Global:AlyaPnpAdminConnection
    }
    $env:PNPPOWERSHELL_DISABLETELEMETRY = "true"

    $AlyaConnection = $null
    if ($ClientId)
    {
        $AlyaConnection = $Global:AlyaPnpConnections | Where-Object { $null -ne $_.Url -and $_.Url.TrimEnd("/") -eq $Url.TrimEnd("/") -and $_.ClientId -eq $ClientId }
    }
    else
    {
        $AlyaConnection = $Global:AlyaPnpConnections | Where-Object { $null -ne $_.Url -and $_.Url.TrimEnd("/") -eq $Url.TrimEnd("/") }
    }

    if ($null -ne $AlyaConnection -and $Relogin)
    {
        if ($ClientId)
        {
            $Global:AlyaPnpConnections = $Global:AlyaPnpConnections | Where-Object { -Not ($null -ne $_.Url -and $_.Url.TrimEnd("/") -eq $Url.TrimEnd("/") -and $_.ClientId -eq $ClientId) }
        }
        else
        {
            $Global:AlyaPnpConnections = $Global:AlyaPnpConnections | Where-Object { -Not ($null -ne $_.Url -and $_.Url.TrimEnd("/") -eq $Url.TrimEnd("/")) }
        }
        $AlyaConnection = $null
    }

    if ($null -eq $AlyaConnection)
    {
        if ($ClientId)
        {
            if ($ClientCertificateThumbprint)
            {
                try {
                    $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -Url $Url -TenantAdminUrl $TenantAdminUrl -ReturnConnection -ClientId $ClientId -Thumbprint $ClientCertificateThumbprint -ValidateConnection
                }
                catch {
                    $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -Url $Url -TenantAdminUrl $TenantAdminUrl -ReturnConnection -ClientId $ClientId -Thumbprint $ClientCertificateThumbprint
                }
            }
            elseif ($ClientCertificateFile)
            {
                try {
                    $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -Url $Url -TenantAdminUrl $TenantAdminUrl -ReturnConnection -ClientId $ClientId -CertificatePath $ClientCertificateFile -CertificatePassword $ClientCertificatePassword -ValidateConnection
                }
                catch {
                    $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -Url $Url -TenantAdminUrl $TenantAdminUrl -ReturnConnection -ClientId $ClientId -CertificatePath $ClientCertificateFile -CertificatePassword $ClientCertificatePassword
                }
            }
            else
            {
                throw "With ClientId at least thumprint or certFile has to be specified"
            }
        }
        else
        {
            if (-Not $AdminConnection) {
                if ($AlyaPnpEnvironment -eq "Production") {
                    if ($DeviceLogin) {
                        try {
                            $AdminConnection = Connect-PnPOnline -Tenant $AlyaTenantName -ClientId $AlyaPnPAppId -Url $TenantAdminUrl -ReturnConnection -DeviceLogin -ValidateConnection
                        }
                        catch {
                            $AdminConnection = Connect-PnPOnline -Tenant $AlyaTenantName -ClientId $AlyaPnPAppId -Url $TenantAdminUrl -ReturnConnection -DeviceLogin
                        }
                    }
                    else {
                        try {
                            $AdminConnection = Connect-PnPOnline -Tenant $AlyaTenantName -ClientId $AlyaPnPAppId -Url $TenantAdminUrl -ReturnConnection -Interactive -ValidateConnection
                        }
                        catch {
                            $AdminConnection = Connect-PnPOnline -Tenant $AlyaTenantName -ClientId $AlyaPnPAppId -Url $TenantAdminUrl -ReturnConnection -Interactive
                        }
                    }
                } else {
                    if ($DeviceLogin) {
                        try {
                            $AdminConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -ClientId $AlyaPnPAppId -Url $TenantAdminUrl -ReturnConnection -DeviceLogin -ValidateConnection
                        }
                        catch {
                            $AdminConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -ClientId $AlyaPnPAppId -Url $TenantAdminUrl -ReturnConnection -DeviceLogin
                        }
                    }
                    else {
                        try {
                            $AdminConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -ClientId $AlyaPnPAppId -Url $TenantAdminUrl -ReturnConnection -Interactive -ValidateConnection
                        }
                        catch {
                            $AdminConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -ClientId $AlyaPnPAppId -Url $TenantAdminUrl -ReturnConnection -Interactive
                        }
                    }
                }
                $Global:AlyaPnpAdminConnection = $AdminConnection
            }
            if ($Url -ne $TenantAdminUrl) {
                if ($AlyaPnpEnvironment -eq "Production") {
                    if ($DeviceLogin) {
                        try {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -ClientId $AlyaPnPAppId -Url $Url -Connection $AdminConnection -ReturnConnection -DeviceLogin -ValidateConnection
                        }
                        catch {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -ClientId $AlyaPnPAppId -Url $Url -Connection $AdminConnection -ReturnConnection -DeviceLogin
                        }
                    }
                    else {
                        try {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -ClientId $AlyaPnPAppId -Url $Url -Connection $AdminConnection -ReturnConnection -Interactive -ValidateConnection
                        }
                        catch {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -ClientId $AlyaPnPAppId -Url $Url -Connection $AdminConnection -ReturnConnection -Interactive
                        }
                    }
                } else {
                    if ($DeviceLogin) {
                        try {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -ClientId $AlyaPnPAppId -Url $Url -Connection $AdminConnection -ReturnConnection -DeviceLogin -ValidateConnection
                        }
                        catch {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -ClientId $AlyaPnPAppId -Url $Url -Connection $AdminConnection -ReturnConnection -DeviceLogin
                        }
                    }
                    else {
                        try {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -ClientId $AlyaPnPAppId -Url $Url -Connection $AdminConnection -ReturnConnection -Interactive -ValidateConnection
                        }
                        catch {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -ClientId $AlyaPnPAppId -Url $Url -Connection $AdminConnection -ReturnConnection -Interactive
                        }
                    }
                }
            }
            else
            {
                $AlyaConnection = $AdminConnection
            }
        }
        [object[]]$Global:AlyaPnpConnections += $AlyaConnection
    }

    $AlyaContext = $null
    try { $AlyaContext = Get-PnPContext -Connection $AlyaConnection -ErrorAction SilentlyContinue } catch [System.InvalidOperationException] {}
    if (-Not $AlyaContext)
    {
        throw "Not logged in to SharePointPnPPowerShellOnline!"
    }

    return $AlyaConnection
}

function LoginTo-PowerApps()
{
    Write-Host "Login to PowerApps" -ForegroundColor $CommandInfo
    $AlyaPowerAppsEnv = $null
    try { $AlyaPowerAppsEnv = Get-PowerAppEnvironment -ErrorAction SilentlyContinue } catch [System.Management.Automation.MethodInvocationException] {}
    if (-Not $AlyaPowerAppsEnv)
    {
        Add-PowerAppsAccount -UseSystemBrowser $true
         #`
            # -AudienceOverride:  "https://service.powerapps.com/" `
            # -AuthBaseUriOverride: "https://login.microsoftonline.com" `
            # -BapEndpointOverride:  "api.bap.microsoft.com" `
            # -CdsOneEndpointOverride:  "api.cds.microsoft.com" `
            # -FlowEndpointOverride:  "api.flow.microsoft.com" `
            # -GraphEndpointOverride:  "graph.windows.net" `
            # -PowerAppsEndpointOverride:  "api.powerapps.com" `
            # -PvaEndpointOverride:  "powerva.microsoft.com"
    }
    $AlyaPowerAppsEnv = $null
    try { $AlyaPowerAppsEnv = Get-PowerAppEnvironment -ErrorAction SilentlyContinue } catch [System.Management.Automation.MethodInvocationException] {}
    if (-Not $AlyaPowerAppsEnv)
    {
        throw "Not logged in to PowerApps!"
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
        throw "Not logged in to AADRM!"
    }
}

function LoginTo-AIP(
    [switch] [Parameter(Mandatory = $false)]
    $AppLogin = $false,
    [switch] [Parameter(Mandatory = $false)]
    $ServiceUserLogin = $false
)
{
    Write-Host "Login to AIP" -ForegroundColor $CommandInfo
    $ServiceDetail = $null
    try { $ServiceDetail = Get-AipService -ErrorAction SilentlyContinue } catch [Microsoft.RightsManagementServices.Online.Admin.PowerShell.AdminClientException] {}
    if ($null -eq $ServiceDetail)
    {
        if ($AppLogin)
        {
            if ([string]::IsNullOrEmpty($AlyaAipAppId) -or $AlyaAipAppId -eq "PleaseSpecify")
            {
                Write-Warning "We need to register the AIP app"
                & "$AlyaScripts\aip\Register-AIPApp.ps1"
                throw "Please restart this script"
            }
            $AlyaAipAppSecret = ConvertTo-SecureString -String "Se28Q~GAFzTgXUFuYyZxoH.MD9g0ahmdbW741a.6" -AsPlainText -Force
            $AipCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AlyaAipAppId, $AlyaAipAppSecret
            Connect-AipService -ServicePrincipal -Credential $AipCredential -TenantId $AlyaTenantId -EnvironmentName $AlyaAzureEnvironment
        }
        else
        {
            if ($ServiceUserLogin)
            {
                LoginTo-Az -SubscriptionName $AlyaSubscriptionName
                $KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
                $CompName = Make-PascalCase($AlyaCompanyNameShort)
                $CredentialAssetName = "$($CompName)AipServiceUserCredential"
                $AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $CredentialAssetName
                $AipCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AzureKeyVaultSecret.ContentType, $AzureKeyVaultSecret.SecretValue
                Connect-AipService -Credential $AipCredential -TenantId $AlyaTenantId -EnvironmentName $AlyaAzureEnvironment
            }
            else
            {
                Connect-AipService -TenantId $AlyaTenantId -EnvironmentName $AlyaAzureEnvironment
            }
    	}
    }
    $ServiceDetail = $null
    try { $ServiceDetail = Get-AipService -ErrorAction SilentlyContinue } catch [Microsoft.RightsManagementServices.Online.Admin.PowerShell.AdminClientException] {}
    if ($null -eq $ServiceDetail)
    {
        throw "Not logged in to AIP!"
    }
}

function Reset-AllAuthTokens
{
    $Global:AlyaMgContext = $null
    $Global:AlyaPnpAdminConnection = $null
    $Global:AlyaPnpConnections = @()
    $Global:AlyaStroreCreds = $null
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    try { Disconnect-MicrosoftTeams -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    try { Disconnect-SPOService -ErrorAction SilentlyContinue } catch {}
    try { Disconnect-PnPOnline -ClearPersistedLogin -ErrorAction SilentlyContinue } catch {}
    try { Remove-PowerAppsAccount -ErrorAction SilentlyContinue } catch {}
    try { Disconnect-AadrmService -ErrorAction SilentlyContinue } catch {}
    try { Disconnect-AipService -ErrorAction SilentlyContinue } catch {}
    LoginTo-Az -SubscriptionName $AlyaSubscriptionName
    Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/me/revokeSignInSessions" -Method "POST"
    LogoutAllFrom-Az
    if (Test-Path "$env:USERPROFILE\.Azure")
    {
        Remove-Item "$env:USERPROFILE\.Azure" -Recurse -Force
    }
    if (Test-Path "$env:USERPROFILE\.Graph")
    {
        Remove-Item "$env:USERPROFILE\.Graph" -Recurse -Force
    }
    [Environment]::SetEnvironmentVariable("AlyaManagementApp", "", "Process")
    [Environment]::SetEnvironmentVariable("AlyaManagementCrt", "", "Process")
    [Environment]::SetEnvironmentVariable("AlyaManagementPwd", "", "Process")
    Get-ChildItem -Path $env:TEMP -Filter "$AlyaTenantId-*.xpy" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-Item -Path "$($env:TEMP)\$AlyaTenantId-Actual.env" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

<# STRING FUNCTIONS #>
function Make-PascalCase(
    [string]$string)
{
    if ([string]::IsNullOrEmpty($string)) {return $string}
    return (Get-Culture).TextInfo.ToTitleCase($string)
}

<# MODULE DEPENDENCIES CHECK #>
function Find-ModuleDependencyDuplicates()
{
    $allDlls = Get-ChildItem -Path $AlyaModulePath -Filter *.dll -Recurse | Sort-Object -Property Name
    $dllNames = $allDlls | ForEach-Object { $_.Name } | Sort-Object -Unique
    foreach($dllName in $dllNames)
    {
        $dlls = $allDlls | Where-Object { $_.Name -eq $dllName }
        if ($dlls.Count -gt 1)
        {
            $versionStrs = $dlls | ForEach-Object { $_.VersionInfo.FileVersion }
            $versions = @()
            foreach($versionStr in $versionStrs)
            {
                if (-Not [string]::IsNullOrEmpty($versionStr))
                {
                    try {
                        $versions += [Version]$versionStr
                    }
                    catch {
                        try {
                            $versions += [Version]$versionStr.Split()[0]
                        }
                        catch {
                            <#Do this if a terminating exception happens#>
                        }
                    }
                }
            }
            $versions = $versions | Sort-Object -Unique -Descending
            if ($versions.Count -gt 1)
            {
                Write-Host "Multiple DLLs found with the same name '$dllName' and different versions:"
                foreach($version in $versions)
                {
                    Write-Host "  Version $version"
                    $dllsForVersion = $dlls | Where-Object { $_.VersionInfo.FileVersion -like "$version*" }
                    $dllsForVersion | ForEach-Object { Write-Host "    $($_.FullName)" }
                }
            }
        }
    }
}

<# MICROSOFT GRAPH FUNCTIONS #>
function Connect-MsGraphAsDelegated
{
    param (
        [string]$ClientID,
        [string]$ClientSecret
    )
    $Resource = $AlyaGraphEndpoint
    $RedirectUri = "$AlyaLoginEndpoint/common/oauth2/nativeclient"
    Add-Type -AssemblyName System.Web
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
    $Url = "$AlyaLoginEndpoint/common/oauth2/authorize?response_type=code&redirect_uri=$RedirectUriEncoded&client_id=$ClientID&resource=$ResourceEncoded&prompt=admin_consent&scope=$ScopeEncoded"
    Get-AuthCode
    $Regex = '(?<=code=)(.*)(?=&)'
    $AuthCode = ($TokenUri | Select-string -pattern $Regex).Matches[0].Value
    $Body = "grant_type=authorization_code&redirect_uri=$RedirectUri&client_id=$ClientId&client_secret=$ClientSecretEncoded&code=$AuthCode&resource=$Resource"
    $TokenResponse = Invoke-RestMethod "$AlyaLoginEndpoint/common/oauth2/token" -Method Post -ContentType "application/x-www-form-urlencoded" -Body $Body -ErrorAction "Stop"
    $TokenResponse.access_token
}

function Get-MsGraphToken
{
    return Get-AzAccessToken("$AlyaGraphEndpoint/")
}

function Get-MsGraph
{
    param (
        [parameter(Mandatory = $false)]
        $AccessToken = $null,
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
    $NextLink = $Uri
    $QueryResults = [System.Collections.ArrayList]@()
    do {
        $LastLink = $NextLink
        $Results = $null
        $StatusCode = 200
        do {
            try {
                if ($AccessToken) {
                    $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $NextLink -UseBasicParsing -Method "GET" -ContentType "application/json"
                    $StatusCode = $Results.StatusCode
                }
                else{
                    $Results = Invoke-MgGraphRequest -Method "Get" -Uri $NextLink
                }
            } catch {
                $StatusCode = $_.Exception.Response.StatusCode.value__
                if ($StatusCode -eq 429 -or $StatusCode -eq 503) {
                    Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                    Start-Sleep -Seconds 45
                }
                else {
                    if (-Not $DontThrowIfStatusEquals -or $StatusCode -ne $DontThrowIfStatusEquals)
                    {
                        if (-Not [string]::IsNullOrEmpty($_.Exception.Response.RequestMessage.Headers.Authorization))
                        {
                            $_.Exception.Response.RequestMessage.Headers.Authorization = "Bearer ****"
                        }
                        try { Write-Host ($_ | ConvertTo-Json -Depth 1) -ForegroundColor $CommandError } catch {}
                        throw
                    }
                }
            }
        } while ($StatusCode -eq 429 -or $StatusCode -eq 503)
        if ($Results.value) {
            $QueryResults.AddRange($Results.value)
        }
        $NextLink = $Results.'@odata.nextLink'
    } while ($null -ne $NextLink -and $LastLink -ne $NextLink)
    return $QueryResults.ToArray()
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
    do {
        $Result = ""
        $StatusCode = 200
        try {
            if ($AccessToken) {
                $Result = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "GET" -ContentType "application/json"
                $StatusCode = $Results.StatusCode
            }
            else{
                $Result = Invoke-MgGraphRequest -Method "Get" -Uri $Uri
            }
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 429 -or $StatusCode -eq 503) {
                Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                Start-Sleep -Seconds 45
            }
            else {
                if (-Not $DontThrowIfStatusEquals -or $StatusCode -ne $DontThrowIfStatusEquals)
                {
                    if (-Not [string]::IsNullOrEmpty($_.Exception.Response.RequestMessage.Headers.Authorization))
                    {
                        $_.Exception.Response.RequestMessage.Headers.Authorization = "Bearer ****"
                    }
                    try { Write-Host ($_ | ConvertTo-Json -Depth 1) -ForegroundColor $CommandError } catch {}
                    throw
                }
            }
        }
    } while ($StatusCode -eq 429 -or $StatusCode -eq 503)
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
    $Result = ""
    $StatusCode = ""
    do {
        try {
            if ($AccessToken) {
                $Result = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -Method "DELETE"
                $StatusCode = $Results.StatusCode
            }
            else{
                $Result = Invoke-MgGraphRequest -Method "Delete" -Uri $Uri
            }
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 429 -or $StatusCode -eq 503) {
                Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                Start-Sleep -Seconds 45
            }
            else {
                if (-Not [string]::IsNullOrEmpty($_.Exception.Response.RequestMessage.Headers.Authorization))
                {
                    $_.Exception.Response.RequestMessage.Headers.Authorization = "Bearer ****"
                }
                try { Write-Host ($_ | ConvertTo-Json -Depth 1) -ForegroundColor $CommandError } catch {}
                throw
            }
        }
    } while ($StatusCode -eq 429 -or $StatusCode -eq 503)
    return $Result
}

function SendBody-MsGraph
{
    param (
        [parameter(Mandatory = $true)]
        $Uri,
        [parameter(Mandatory = $true)]
        $Method,
        [parameter(Mandatory = $false)]
        $AccessToken = $null,
        [parameter(Mandatory = $false)]
        $Body = $null,
        [parameter(Mandatory = $false)]
        $OutputFile = $null
    )
    if ($AccessToken) {
        $HeaderParams = @{
            'Content-Type'  = "application/json"
            'Authorization' = "Bearer $AccessToken"
        }
    }
    $Results = ""
    $StatusCode = ""
    do {
        try {
            if ($AccessToken) {
                if ($OutputFile) {
                    if ($Body) {
                        $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method $Method -ContentType "application/json; charset=UTF-8" -Body $Body -OutFile $OutputFile
                        $StatusCode = $Results.StatusCode
                    }
                    else{
                        $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method $Method -OutFile $OutputFile
                        $StatusCode = $Results.StatusCode
                    }
                }
                else{
                    if ($Body) {
                        $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method $Method -ContentType "application/json; charset=UTF-8" -Body $Body
                        $StatusCode = $Results.StatusCode
                    }
                    else{
                        $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method $Method
                        $StatusCode = $Results.StatusCode
                    }
                }
            }
            else{
                if ($OutputFile) {
                    if ($Body) {
                        $Results = Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $Body -OutputFilePath $OutputFile
                    }
                    else{
                        $Results = Invoke-MgGraphRequest -Method $Method -Uri $Uri -OutputFilePath $OutputFile
                    }
                }
                else{
                    if ($Body) {
                        $Results = Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $Body
                    }
                    else{
                        $Results = Invoke-MgGraphRequest -Method $Method -Uri $Uri
                    }
                }
            }
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 429 -or $StatusCode -eq 503) {
                Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                Start-Sleep -Seconds 45
            }
            else {
                if (-Not [string]::IsNullOrEmpty($_.Exception.Response.RequestMessage.Headers.Authorization))
                {
                    $_.Exception.Response.RequestMessage.Headers.Authorization = "Bearer ****"
                }
                try { Write-Host ($_ | ConvertTo-Json -Depth 1) -ForegroundColor $CommandError } catch {}
                throw
            }
        }
    } while ($StatusCode -eq 429 -or $StatusCode -eq 503)
    if ($Results.value) {
        $Results.value
    }
    else {
        $Results
    }
}

function Post-MsGraph
{
    param (
        [parameter(Mandatory = $true)]
        $Uri,
        [parameter(Mandatory = $false)]
        $AccessToken = $null,
        [parameter(Mandatory = $false)]
        $Body = $null,
        [parameter(Mandatory = $false)]
        $OutputFile = $null
    )
    SendBody-MsGraph -Uri $Uri -AccessToken $AccessToken -Body $Body -Method "Post" -OutputFile $OutputFile
}

function Patch-MsGraph
{
    param (
        [parameter(Mandatory = $true)]
        $Uri,
        [parameter(Mandatory = $false)]
        $AccessToken = $null,
        [parameter(Mandatory = $true)]
        $Body,
        [parameter(Mandatory = $false)]
        $OutputFile = $null
    )
    SendBody-MsGraph -Uri $Uri -AccessToken $AccessToken -Body $Body -Method "Patch" -OutputFile $OutputFile
}

function Put-MsGraph
{
    param (
        [parameter(Mandatory = $true)]
        $Uri,
        [parameter(Mandatory = $false)]
        $AccessToken = $null,
        [parameter(Mandatory = $true)]
        $Body,
        [parameter(Mandatory = $false)]
        $OutputFile = $null
    )
    SendBody-MsGraph -Uri $Uri -AccessToken $AccessToken -Body $Body -Method "Put" -OutputFile $OutputFile
}


<# NETWORKING FUNCTIONS #>
$AlyaWOctet = 16777216
$AlyaXOctet = 65536
$AlyaYOctet = 256
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
    for ($i = $n + 1; $i -lt $g + 1; $i++) 
    { 
        $ipi = $ipi + [math]::pow(2, 32 - $i) 
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
        $NextIp = $NextIp + [math]::pow(2, 32 - $cidr)
        if ($NextIp -ge $GwIp) { break }
        if ((IP-toINT64(Get-BroadcastAddress -netw $NextIp -cidr $cidr)) -gt $GwIp)
        { 
            $NextIp = $NextIp - [math]::pow(2, 32 - ($cidr + 1))
            $cidr = $cidr + 1
            continue
        }
        $networks += (INT64-toIP -int $NextIp) + "/$cidr"
    }
    $networks += (INT64-toIP -int $GwIp) + "/$gwcidr"
    return $networks
}
function Get-FirstIpInNetwork()
{
    param ($netw, $netwandcidr)
    if ($netwandcidr)
    {
        $parts = $netwandcidr.Split("/")
        $netw = $parts[0]
    }
    $StartIp = IP-toINT64($netw)
    $StartIp++
    return (INT64-toIP -int $StartIp)
}
function Get-LastIpInNetwork()
{
    param ($netw, $nwmask, [int]$nwcidr, $netwandcidr)
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
    $EndIp = IP-toINT64($netw)
    $EndIp += [math]::pow(2, 32 - $nwcidr)
    $EndIp--
    return (INT64-toIP -int $EndIp)
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
        $NextIp = $NextIp + [math]::pow(2, 32 - $cidr)
        if ($NextIp -ge $GwIp) { break }
        if ((IP-toINT64(Get-BroadcastAddress -netw $NextIp -cidr $cidr)) -gt $GwIp)
        { 
            $NextIp = $NextIp - [math]::pow(2, 32 - ($cidr + 1))
            $cidr = $cidr + 1
            continue
        }
        $networks += (INT64-toIP -int $NextIp) + "/$cidr"
    }
    return $networks
}
function Check-NetworkToSubnet ([int64]$un2, [int64]$ma2, [int64]$un1)
{
    if($un2 -eq ($ma2 -band $un1)){
        return $True
    }else{
        return $False
    }
}
function Check-SubnetToNetwork ([int64]$un1, [int64]$ma1, [int64]$un2)
{
    if($un1 -eq ($ma1 -band $un2)){
        return $False
    }else{
        return $True
    }
}
function Check-NetworkToNetwork ([int64]$un1, [int64]$un2)
{
    if($un1 -eq $un2){
        return $True
    }else{
        return $False
    }
}

function Check-SubnetInSubnet ([string]$isAddr, [string]$withinAddr)
{
    if ($isAddr.IndexOf("/") -eq -1) { $isAddr += "/32" }
    if ($withinAddr.IndexOf("/") -eq -1) { $withinAddr += "/32" }
    $network1, [int]$subnetlen1 = $isAddr.Split('/')
    $network2, [int]$subnetlen2 = $withinAddr.Split('/')
    $network1addr = [Net.IPAddress]::Parse($network1)
    $mask1addr = [Net.IPAddress]::Parse((CIDR-toMask -cidr $subnetlen1))
    $network2addr = [Net.IPAddress]::Parse($network2)
    $mask2addr = [Net.IPAddress]::Parse((CIDR-toMask -cidr $subnetlen2))
    $bcast1 = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $mask1addr.address -bor $network1addr.address))
    $bcast2 = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $mask2addr.address -bor $network2addr.address))
    $nwk1 = new-object net.ipaddress (($mask1addr.address -band $network1addr.address))
    $nwk2 = new-object net.ipaddress (($mask2addr.address -band $network2addr.address))
    return $nwk1.Address -ge $nwk2.Address -and $bcast1.Address -le $bcast2.Address
}
#Check-SubnetInSubnet "172.16.72.0/24" "172.16.0.0/16" true
#Check-SubnetInSubnet "172.16.72.1" "172.16.0.0/16" true
#Check-SubnetInSubnet "172.16.0.0/28" "172.16.72.0/24" false
#Check-SubnetInSubnet "172.16.72.0/24" "172.16.0.0/28" false
#Check-SubnetInSubnet "172.16.72.0" "172.16.0.0/28" false TODO!!
#Check-SubnetInSubnet "10.249.14.0/23" "10.249.0.0/20" true

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
    if (-Not (Check-SubnetInSubnet $AlyaProdNetwork $AlyaAzureNetwork))
    {
        Write-Error "AlyaProdNetwork '$($AlyaProdNetwork)' is not within AlyaAzureNetwork '$($AlyaAzureNetwork)'" -ErrorAction Continue
        exit
    }
}
if ($AlyaAzureNetwork -and $AlyaTestNetwork -and $AlyaAzureNetwork -ne "PleaseSpecify" -and $AlyaTestNetwork -ne "PleaseSpecify")
{
    if (-Not (Check-SubnetInSubnet $AlyaTestNetwork $AlyaAzureNetwork))
    {
        Write-Error "AlyaTestNetwork '$($AlyaTestNetwork)' is not within AlyaAzureNetwork '$($AlyaAzureNetwork)'" -ErrorAction Continue
        exit
    }
}

function ConvertFrom-XML
{
    #https://www.red-gate.com/simple-talk/blogs/convert-from-xml/
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, ValueFromPipeline)]
		[System.Xml.XmlNode]$node, #we are working through the nodes
		[string]$Prefix='',#do we indicate an attribute with a prefix?
		$ShowDocElement=$false #Do we show the document element? 
	)
	process
	{   #if option set, we skip the Document element
		if ($node.DocumentElement -and !($ShowDocElement)) 
            { $node = $node.DocumentElement }
		$oHash = [ordered] @{ } # start with an ordered hashtable.
        #The order of elements is always significant regardless of what they are
		write-verbose "calling with $($node.LocalName)"
		if ($node.Attributes -ne $null) #if there are elements
		# record all the attributes first in the ordered hash
		{
			$node.Attributes | foreach {
				$oHash.$($Prefix+$_.FirstChild.parentNode.LocalName) = $_.FirstChild.value
			}
		}
		# check to see if there is a pseudo-array. (more than one
		# child-node with the same name that must be handled as an array)
		$node.ChildNodes | #we just group the names and create an empty
        #array for each
		Group-Object -Property LocalName | where { $_.count -gt 1 } | select Name |
		foreach{
			write-verbose "pseudo-Array $($_.Name)"
			$oHash.($_.Name) = @() <# create an empty array for each one#>
		}
		foreach ($child in $node.ChildNodes)
		{#now we look at each node in turn.
			write-verbose "processing the '$($child.LocalName)'"
			$childName = $child.LocalName
			if ($child -is [system.xml.xmltext])
			# if it is simple XML text 
			{
				write-verbose "simple xml $childname"
				$oHash.$childname += $child.InnerText
			}
			# if it has a #text child we may need to cope with attributes
			elseif ($child.FirstChild.Name -eq '#text' -and $child.ChildNodes.Count -eq 1)
			{
				write-verbose "text"
				if ($child.Attributes -ne $null) #hah, an attribute
				{
					<#we need to record the text with the #text label and preserve all
					the attributes #>
					$aHash = [ordered]@{ }
					$child.Attributes | foreach {
						$aHash.$($_.FirstChild.parentNode.LocalName) = $_.FirstChild.value
					}
                    #now we add the text with an explicit name
					$aHash.'#text' += $child.'#text'
					$oHash.$childname += $aHash
				}
				else
				{ #phew, just a simple text attribute. 
					$oHash.$childname += $child.FirstChild.InnerText
				}
			}
			elseif ($child.'#cdata-section' -ne $null)
			# if it is a data section, a block of text that isnt parsed by the parser,
			# but is otherwise recognized as markup
			{
				write-verbose "cdata section"
				$oHash.$childname = $child.'#cdata-section'
			}
			elseif ($child.ChildNodes.Count -gt 1 -and 
                        ($child | gm -MemberType Property).Count -eq 1)
			{
				$oHash.$childname = @()
				foreach ($grandchild in $child.ChildNodes)
				{
					$oHash.$childname += (ConvertFrom-XML $grandchild)
				}
			}
			else
			{
				# create an array as a value  to the hashtable element
				$oHash.$childname += (ConvertFrom-XML $child)
			}
		}
		$oHash
	}
} 

function Select-Item()
{
    Param(
        $list,
        $message = "Please select an item",
        [ValidateSet("Single","Multiple","None")]
        $outputMode = "Single"
    )
    $sel = $list | Out-GridView -Title $message -OutputMode $outputMode
    return $sel
}

<# SELENIUM BROWSER #>
function Get-SeleniumBrowser()
{
    Param(
        [bool]$HideCommandPrompt = $true,
        [bool]$Headless = $false,
        [bool]$PrivateBrowsing = $true,
        $OptionSettings =  @{ },
        $seleniumVersion = $null,
        $driverVersion = $null
    )
    return Get-SeleniumEdgeBrowser -HideCommandPrompt = $HideCommandPrompt `
        -Headless = $Headless `
        -PrivateBrowsing = $PrivateBrowsing `
        -OptionSettings $OptionSettings `
        -seleniumVersion $seleniumVersion `
        -driverVersion $driverVersion
}

<# SELENIUM BROWSER #>
function Get-SeleniumEdgeBrowser()
{
    Param(
        [bool]$HideCommandPrompt = $true,
        [bool]$Headless = $false,
        [bool]$PrivateBrowsing = $true,
        $OptionSettings =  @{ },
        $seleniumVersion = $null,
        $edgeDriverVersion = $null
    )
    $Global:AlyaSeleniumBrowser = $null
    Install-PackageIfNotInstalled "Selenium.WebDriver" -exactVersion $seleniumVersion
    Install-PackageIfNotInstalled "Selenium.WebDriver.MSEdgeDriver" -exactVersion $edgeDriverVersion
    if($AlyaIsPsCore) {
        if (Test-Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.1\Selenium.WebDriver.dll") {
            Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.1\Selenium.WebDriver.dll"
        } else {
            if (Test-Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.0\Selenium.WebDriver.dll") {
                Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.0\Selenium.WebDriver.dll"
            } else {
                if (Test-Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.1\WebDriver.dll") {
                    Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.1\WebDriver.dll"
                } else {
                    if (Test-Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.0\WebDriver.dll") {
                        Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.0\WebDriver.dll"
                    } else {
                        throw "Could not find Selenium.WebDriver.dll or WebDriver.dll for .NET Standard in $($AlyaTools)\Packages\Selenium.WebDriver\lib"
                    }
                }
            }
        }
    } else {
        if (Test-Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\net48\Selenium.WebDriver.dll") {
            Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\net48\Selenium.WebDriver.dll"
        } else {
            if (Test-Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\net48\WebDriver.dll") {
                Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\net48\WebDriver.dll"
            } else {
                throw "Could not find Selenium.WebDriver.dll or WebDriver.dll for .NET Framework in $($AlyaTools)\Packages\Selenium.WebDriver\lib"
            }
        }
    }
    if ($env:PATH.IndexOf("$($AlyaTools)\Packages\Selenium.WebDriver.MSEdgeDriver\driver\win64") -eq -1)
    {
        $env:PATH = "$($AlyaTools)\Packages\Selenium.WebDriver.MSEdgeDriver\driver\win64$AlyaPathSep$($env:PATH)"
    }

    # Install-ModuleIfNotInstalled "AppX"
    # $edge = Get-AppXPackage | Where-Object { $_.Name -like "Microsoft.MicrosoftEdge*" }
    # if (!$edge){
    #     throw "Microsoft Edge Browser not installed."
    #     return
    # }

    $dService = [OpenQA.Selenium.Edge.EdgeDriverService]::CreateDefaultService()
    $dService.DriverServiceExecutableName = "msedgedriver.exe"
    $dService.DriverServicePath = "$($AlyaTools)\Packages\Selenium.WebDriver.MSEdgeDriver\driver\win64"
    $dService.HideCommandPromptWindow = $HideCommandPrompt
    $options = New-Object -TypeName OpenQA.Selenium.Edge.EdgeOptions -Property $OptionSettings
    if($PrivateBrowsing) {$options.AddArguments('InPrivate')}
    if($Headless) {$options.AddArguments('headless')}
    $Global:AlyaSeleniumBrowser = New-Object OpenQA.Selenium.Edge.EdgeDriver $dService, $options
    $Global:AlyaSeleniumBrowser.Manage().window.position = '0,0'
    return $Global:AlyaSeleniumBrowser
}

function Get-7ZipInstallLocation()
{
    $7zip = $null
    if ((Test-path HKLM:\SOFTWARE\7-Zip\) -eq $true)
    {
        $7zpath = Get-ItemProperty -path  HKLM:\SOFTWARE\7-Zip\ -Name Path
        $7zpath = $7zpath.Path
        $7zpathexe = $7zpath + "7z.exe"
        if ((Test-Path $7zpathexe) -eq $true)
        {
            $7zip = $7zpathexe
        }    
    }
    elseif (-Not $7zip -and (Test-Path -PathType Container "C:\Programme\7-Zip"))
    {
        $7zip = "C:\Program Files\7-Zip\7z.exe"
    }
    elseif (-Not $7zip -and (Test-Path -PathType Container "C:\Programme (x86)\7-Zip"))
    {
        $7zip = "C:\Program Files\7-Zip\7z.exe"
    }
    elseif (-Not $7zip -and (Test-Path -PathType Container "C:\Program Files\7-Zip"))
    {
        $7zip = "C:\Program Files\7-Zip\7z.exe"
    }
    elseif (-Not $7zip -and (Test-Path -PathType Container "C:\Program Files (x86)\7-Zip"))
    {
        $7zip = "C:\Program Files\7-Zip\7z.exe"
    }
    return $7zip
}
function Get-SeleniumChromeBrowser()
{
    Param(
        [bool]$HideCommandPrompt = $true,
        [bool]$Headless = $false,
        [bool]$PrivateBrowsing = $true,
        $OptionSettings =  @{ },
        $seleniumVersion = $null,
        $chromeDriverVersion = $null
    )
    $Global:AlyaSeleniumBrowser = $null
    Install-PackageIfNotInstalled "Selenium.WebDriver" -exactVersion $seleniumVersion
    Install-PackageIfNotInstalled "Selenium.WebDriver.ChromeDriver" -exactVersion $chromeDriverVersion
    if (-Not (Test-Path "$($AlyaTools)\GoogleChromePortable"))
    {
        if (-Not (Test-Path "$AlyaTools"))
        {
            $null = New-Item -Path $AlyaTools -ItemType Directory -Force
        }
        $pageUrl = "https://portableapps.com/de/apps/internet/google_chrome_portable"
        $req = Invoke-WebRequestIndep -Uri $pageUrl -UseBasicParsing -Method Get
        [regex]$regex = "[^`"]*https://downloads.sourceforge.net/portableapps[^`"]*"
        $newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
        $fileName = Split-Path -Path $newUrl -Leaf
        Invoke-WebRequestIndep -UseBasicParsing -Method Get -UserAgent "Wget" -Uri $newUrl -Outfile "$AlyaTools\$fileName"
        & "$AlyaTools\$fileName" /S /D="$AlyaTools\GoogleChromePortable"
        Wait-UntilProcessEnds -processName $fileName -ErrorAction SilentlyContinue
        Wait-UntilProcessEnds -processName $fileName.Replace(".exe","") -ErrorAction SilentlyContinue
        $null = Remove-Item -Path "$AlyaTools\$fileName" -Force
    }

    if($AlyaIsPsCore) {
        if (Test-Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.1\Selenium.WebDriver.dll") {
            Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.1\Selenium.WebDriver.dll"
        } else {
            Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.0\Selenium.WebDriver.dll"
        }
    } else {
        Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\net48\Selenium.WebDriver.dll"
    }
    if ($env:PATH.IndexOf("$($AlyaTools)\Packages\Selenium.WebDriver.ChromeDriver\driver\win32") -eq -1)
    {
        $env:PATH = "$($AlyaTools)\Packages\Selenium.WebDriver.ChromeDriver\driver\win32$AlyaPathSep$($env:PATH)"
    }

    # Install-ModuleIfNotInstalled "AppX"
    # $edge = Get-AppXPackage | Where-Object { $_.Name -like "Microsoft.MicrosoftEdge*" }
    # if (!$edge){
    #     throw "Microsoft Edge Browser not installed."
    #     return
    # }

    $dService = [OpenQA.Selenium.Chrome.ChromeDriverService]::CreateDefaultService()
    $dService.DriverServiceExecutableName = "chromedriver.exe"
    $dService.DriverServicePath = "$($AlyaTools)\Packages\Selenium.WebDriver.ChromeDriver\driver\win32"
    $dService.HideCommandPromptWindow = $HideCommandPrompt
    $options = New-Object -TypeName OpenQA.Selenium.Chrome.ChromeOptions -Property $OptionSettings
    if($PrivateBrowsing) {$options.AddArguments('InPrivate')}
    if($Headless) {$options.AddArguments('headless')}
    $options.BinaryLocation = "$($AlyaTools)\GoogleChromePortable\App\Chrome-bin\chrome.exe"
    $Global:AlyaSeleniumBrowser = New-Object OpenQA.Selenium.Chrome.ChromeDriver $dService, $options
    $Global:AlyaSeleniumBrowser.Manage().window.position = '0,0'
    return $Global:AlyaSeleniumBrowser
}

function Close-SeleniumBrowser()
{
    Param(
        $browser = $null
    )
    if (-Not $browser) { $browser = $AlyaSeleniumBrowser }
    if ($browser) {
        try { $browser.Close() } catch {}
        try { $browser.Quit() } catch {}
        try { $browser.Dispose() } catch {}
    }
    Start-Sleep -Seconds 2
    Get-Process -Name msedgedriver -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
}

function Run-ScriptInRunspace()
{
    Param(
        $scriptPath = $null
    )
    Write-Host "Run-ScriptInRunspace: $scriptPath" -ForegroundColor $CommandInfo
    $ps = $null
    try {
        $ps = [powershell]::Create()
        [void]$ps.AddCommand($scriptPath).Invoke()
        Write-Host "Results" -ForegroundColor $CommandInfo
        Write-Host "  Debug" -ForegroundColor $CommandInfo
        if ($ps.Streams.Debug)
        {
            Write-Debug $ps.Streams.Debug
        }
        Write-Host "  Verbose" -ForegroundColor $CommandInfo
        if ($ps.Streams.Verbose)
        {
            Write-Verbose $ps.Streams.Verbose
        }
        Write-Host "  Information" -ForegroundColor $CommandInfo
        if ($ps.Streams.Information)
        {
            Write-Host $ps.Streams.Information
        }
        Write-Host "  Error" -ForegroundColor $CommandInfo
        if ($ps.Streams.Error)
        {
            Write-Error $ps.Streams.Error
        }
        Write-Host "  Warning" -ForegroundColor $CommandInfo
        if ($ps.Streams.Warning)
        {
            foreach($record in $ps.Streams.Warning) {
                Write-Warning $ps.Streams.Warning
            }
        }
    }
    catch {
        if ($null -ne $ps) { $ps.Runspace.Close() }
    }
}
#Run-ScriptInRunspace "$AlyaScripts\tenant\Set-AdHocSubscriptionsDisabled.ps1"

# Alya String Functions
function Replace-AlyaString($str)
{
    $str =  $str.Replace("##AlyaDomainName##", $AlyaDomainName)
    $str =  $str.Replace("##AlyaDesktopBackgroundUrl##", $AlyaDesktopBackgroundUrl)
    $str =  $str.Replace("##AlyaLockScreenBackgroundUrl##", $AlyaLockScreenBackgroundUrl)
    $str =  $str.Replace("##AlyaWelcomeScreenBackgroundUrl##", $AlyaWelcomeScreenBackgroundUrl)
    $str =  $str.Replace("##AlyaWebPage##", $AlyaWebPage)
    $str =  $str.Replace("##AlyaPrivacyUrl##", $AlyaPrivacyUrl)
    $str =  $str.Replace("##AlyaCompanyNameShort##", $AlyaCompanyNameShort)
    $str =  $str.Replace("##AlyaCompanyName##", $AlyaCompanyName)
    $str =  $str.Replace("##AlyaTenantId##", $AlyaTenantId)
    $str =  $str.Replace("##AlyaKeyVaultName##", $KeyVaultName)
    $str =  $str.Replace("##AlyaSupportTitle##", $AlyaSupportTitle)
    $str =  $str.Replace("##AlyaSupportTel##", $AlyaSupportTel)
    $str =  $str.Replace("##AlyaSupportMail##", $AlyaSupportMail)
    $str =  $str.Replace("##AlyaSupportUrl##", $AlyaSupportUrl)
    $str =  $str.Replace("##AlyaTeamsNewTeamOwner##", $AlyaTeamsNewTeamOwner)
    $str =  $str.Replace("##AlyaSharePointNewSiteOwner##", $AlyaSharePointNewSiteOwner)
    $str =  $str.Replace("##AlyaTeamsNewTeamAdditionalOwner##", $AlyaTeamsNewTeamAdditionalOwner)
    $str =  $str.Replace("##AlyaSharePointNewSiteAdditionalOwner##", $AlyaSharePointNewSiteAdditionalOwner)
    $str =  $str.Replace("##AlyaAllInternals##", $AlyaAllInternals)
    $str =  $str.Replace("##AlyaAllExternals##", $AlyaAllExternals)
    $str =  $str.Replace("##AlyaSubscriptionId##", $AlyaSubscriptionId)
    $str =  $str.Replace("##AlyaSubscriptionIds##", $AlyaSubscriptionIds)
    $str =  $str.Replace("##AlyaTimeZone##", $AlyaTimeZone)
    $domPrts = $AlyaWebPage.Split("./")
    $AlyaLocalDomains = "https://*." + $domPrts[$domPrts.Length-2] + "." + $domPrts[$domPrts.Length-1]
    $str =  $str.Replace("##AlyaWebDomains##", $AlyaLocalDomains)
    $str =  $str.Replace("##AlyaLocalDomains##", $AlyaLocalDomains)
    if ($str.IndexOf("##Alya") -gt -1)
    {
        throw "Replace-AlyaString: Some replacement did not work or missing!"
    }
    return $str
}

function Replace-AlyaStrings($obj, $depth)
{
    if ($depth -gt 3) { return }
    foreach($prop in $obj.PSObject.Properties)
    {
        if ($prop.Value)
        {
            if ($prop.Value.GetType().Name -eq "String")
            {
                if ($prop.Value.Contains("##Alya"))
                {
                    $prop.Value = Replace-AlyaString -str $prop.Value
                }
            }
            else
            {
                if (-Not ($prop.Value.GetType().IsValueType))
                {
                    $cnt = 1
                    $cntMem = Get-Member -InputObject $prop.Value -Name Count
                    if ($cntMem)
                    {
                        $cnt = $prop.Value.Count
                    }
                    else
                    {
                        $cntMem = Get-Member -InputObject $prop.Value -Name Length
                        if ($cntMem)
                        {
                            $cnt = $prop.Value.Length
                        }
                        else
                        {
                            $cnt = ($prop.Value | Measure-Object | Select-Object Count).Count
                        }
                    }
                    if ($cnt -gt 1)
                    {
                        foreach($sobj in $prop.Value)
                        {
                            if ($sobj.GetType().Name -eq "String")
                            {
                                if ($sobj.Contains("##Alya"))
                                {
                                    #TODO will this work?
                                    $sobj = Replace-AlyaString -str $sobj
                                }
                            }
                            elseif (-Not ($sobj.GetType().IsValueType))
                            {
                                Replace-AlyaStrings -obj $sobj -depth ($depth+1)
                            }
                        }
                    }
                    else
                    {
                        $sobj = $prop.Value | Select-Object -First 1
                        if ($sobj.GetType().Name -eq "String")
                        {
                            if ($sobj.Contains("##Alya"))
                            {
                                $prop.Value[0] = Replace-AlyaString -str $sobj
                            }
                        }
                        else
                        {
                            if (-Not ($sobj.GetType().IsValueType))
                            {   
                                Replace-AlyaStrings -obj $sobj -depth ($depth+1)
                            }
                        }
                    }
                }
            }
        }
    }
}

# Deterministically normalizes exported JSON files for git:
# recursive removal of volatile attributes ($VolatileKeys), recursive canonical key sorting
# (ordinal, stable via LINQ) and stable array sorting.
# Output format (repo standard): ConvertTo-Json (-Depth 100, not compressed), UTF-8 with BOM, LF line endings.
# Idempotent: applying it twice results in the identical file.
# Special cases (by file name):
# - managedDeviceOverview.json: snapshot report, root keys "id" (random instance GUID per fetch) and
#   "lastModifiedDateTime" (report creation time) are removed as well.
# - appregistrationSummary.json: embedded sync timestamps inside the values[] arrays change with every
#   export. Decision 30.08.2026: do NOT skip the file; instead remove all DateTime typed columns
#   (currently "LastCheckInDate") from content.header[] and from every content.body[].values[] array.
# createdDateTime and lastModifiedDateTime are kept everywhere, except the special cases above.
function Make-JsonGitReady()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string[]]$Path,
        [Parameter()]
        [string[]]$VolatileKeys = @("@odata.context", "etag", "appMetadata", "microsoftPolicyGroup", "lastAppSyncDateTime", "lastSyncTriggeredDateTime", "lastSyncErrorCode")
    )

    function Get-CanonicalJson([object]$Item)
    {
        return (ConvertTo-Json -InputObject $Item -Depth 100 -Compress)
    }

    function Remove-VolatileJsonKeys([object]$Value)
    {
        if ($null -eq $Value)
        {
            return $null
        }
        if ($Value -is [System.Management.Automation.PSCustomObject])
        {
            foreach ($key in $VolatileKeys)
            {
                $prop = $Value.PSObject.Properties[$key]
                if ($null -ne $prop)
                {
                    $Value.PSObject.Properties.Remove($key)
                }
            }
            foreach ($prop in $Value.PSObject.Properties)
            {
                $prop.Value = Remove-VolatileJsonKeys -Value $prop.Value
            }
            return $Value
        }
        if ($Value -is [System.Collections.IList])
        {
            for ($i = 0; $i -lt $Value.Count; $i++)
            {
                $Value[$i] = Remove-VolatileJsonKeys -Value $Value[$i]
            }
            return $Value
        }
        return $Value
    }

    function Remove-ArrayItems([object[]]$Items, [int[]]$Indexes)
    {
        $result = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $Items.Count; $i++)
        {
            if ($Indexes -notcontains $i)
            {
                $result.Add($Items[$i])
            }
        }
        return ,([object[]]$result)
    }

    function ConvertTo-OrderedJson([object]$Value)
    {
        if ($null -eq $Value)
        {
            return $null
        }
        if ($Value -is [System.Management.Automation.PSCustomObject])
        {
            $orderedProps = [ordered]@{}
            $sortedProps = [System.Linq.Enumerable]::OrderBy(
                @($Value.PSObject.Properties),
                [Func[object,string]]{ param($prop) $prop.Name },
                [System.StringComparer]::Ordinal)
            foreach ($prop in $sortedProps)
            {
                $orderedProps[$prop.Name] = ConvertTo-OrderedJson -Value $prop.Value
            }
            return ([PSCustomObject]$orderedProps)
        }
        if ($Value -is [System.Collections.IList])
        {
            $items = New-Object System.Collections.Generic.List[object]
            foreach ($element in $Value)
            {
                $items.Add((ConvertTo-OrderedJson -Value $element))
            }
            $allHaveId = ($items.Count -gt 0)
            $allHaveDisplayName = ($items.Count -gt 0)
            $allHaveKeyId = ($items.Count -gt 0)
            foreach ($element in $items)
            {
                $names = @()
                if ($null -ne $element -and $element -is [System.Management.Automation.PSCustomObject])
                {
                    $names = @($element.PSObject.Properties.Name)
                }
                if ($names -notcontains "id")
                {
                    $allHaveId = $false
                }
                if ($names -notcontains "displayName")
                {
                    $allHaveDisplayName = $false
                }
                if ($names -notcontains "keyId")
                {
                    $allHaveKeyId = $false
                }
            }
            if ($allHaveId)
            {
                $sortedItems = [System.Linq.Enumerable]::OrderBy(
                    [object[]]$items,
                    [Func[object,string]]{ param($element) Get-CanonicalJson -Item $element.id },
                    [System.StringComparer]::Ordinal)
            }
            elseif ($allHaveKeyId)
            {
                $sortedItems = [System.Linq.Enumerable]::OrderBy(
                    [object[]]$items,
                    [Func[object,string]]{ param($element) Get-CanonicalJson -Item $element.keyId },
                    [System.StringComparer]::Ordinal)
            }
            elseif ($allHaveDisplayName)
            {
                $sortedItems = [System.Linq.Enumerable]::OrderBy(
                    [object[]]$items,
                    [Func[object,string]]{ param($element) Get-CanonicalJson -Item $element.displayName },
                    [System.StringComparer]::Ordinal)
            }
            else
            {
                $sortedItems = [System.Linq.Enumerable]::OrderBy(
                    [object[]]$items,
                    [Func[object,string]]{ param($element) Get-CanonicalJson -Item $element },
                    [System.StringComparer]::Ordinal)
            }
            return ,([object[]]@($sortedItems))
        }
        return $Value
    }

    foreach ($currentPath in $Path)
    {
        if (-Not (Test-Path -Path $currentPath))
        {
            Write-Warning "Make-JsonGitReady: file does not exist, skipping: $($currentPath)"
            continue
        }
        $resolvedPath = (Resolve-Path -Path $currentPath).Path
        $content = Get-Content -Path $resolvedPath -Raw -Encoding UTF8
        $jsonObject = ConvertFrom-Json -InputObject $content -NoEnumerate -DateKind Utc
        $jsonObject = Remove-VolatileJsonKeys -Value $jsonObject
        $fileName = [System.IO.Path]::GetFileName($resolvedPath)
        if ($jsonObject -is [System.Management.Automation.PSCustomObject] -and $fileName -eq "managedDeviceOverview.json")
        {
            # Special case: snapshot report, remove root keys "id" and "lastModifiedDateTime"
            foreach ($rootKey in @("id", "lastModifiedDateTime"))
            {
                $rootProp = $jsonObject.PSObject.Properties[$rootKey]
                if ($null -ne $rootProp)
                {
                    $jsonObject.PSObject.Properties.Remove($rootKey)
                }
            }
        }
        elseif ($jsonObject -is [System.Management.Automation.PSCustomObject] -and $fileName -eq "appregistrationSummary.json")
        {
            # Special case: remove all DateTime typed columns (currently "LastCheckInDate") from
            # content.header[] and from every content.body[].values[] array
            $dateTimeColumnIndexes = @()
            if ($null -ne $jsonObject.content -and $null -ne $jsonObject.content.header)
            {
                $headerItems = @($jsonObject.content.header)
                for ($i = 0; $i -lt $headerItems.Count; $i++)
                {
                    if ($null -ne $headerItems[$i] -and $headerItems[$i].typeName -eq "DateTime")
                    {
                        $dateTimeColumnIndexes += $i
                    }
                }
            }
            if ($dateTimeColumnIndexes.Count -gt 0)
            {
                $jsonObject.content.header = Remove-ArrayItems -Items @($jsonObject.content.header) -Indexes $dateTimeColumnIndexes
                if ($null -ne $jsonObject.content.body)
                {
                    foreach ($row in @($jsonObject.content.body))
                    {
                        if ($null -ne $row -and $null -ne $row.values)
                        {
                            $row.values = Remove-ArrayItems -Items @($row.values) -Indexes $dateTimeColumnIndexes
                        }
                    }
                }
            }
        }
        $orderedObject = ConvertTo-OrderedJson -Value $jsonObject
        $json = ConvertTo-Json -InputObject $orderedObject -Depth 100
        if ($IsLinux)
        {
            $json = $json -replace "`r`n", "`n"
        }
        $utf8WithBom = New-Object System.Text.UTF8Encoding($true)
        [System.IO.File]::WriteAllText($resolvedPath, "$($json)$($Environment.NewLine)", $utf8WithBom)
    }
}

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCXES/dtCyiLrgY
# OFOMojOkShsd5PNABaCP6xmNEczCaaCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGju
# xOV7dX3H9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQT
# AxEACqVq4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f
# 46P2IukytvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdY
# TA3E3kMHBiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhD
# o6nZ2Iwj1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL
# 1yf/30OVyct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AH
# hviDcudo30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfd
# sbCXAJvYNCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx
# /j+7m9WSaK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cid
# mgdUVveoBPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgf
# tnoAWlVn8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vC
# oTANBgkqhkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQ
# ZpE364hOTSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTso
# VYpQr3IozYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yo
# DsPU9IHP/w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQ
# X6ibUXqjXk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNp
# HbGY6Eg0RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirM
# Jk0b9UF2hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnA
# mrVkGZj2a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj
# 3+nmvWbZfNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL
# /yMvbDOHhREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtH
# dwO39ACaudnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4Qh
# trofETAxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINKdUFk8
# kwvZ1LltTWUNbRognUmgBRmPL/4U7lWqnLggMA0GCSqGSIb3DQEBAQUABIICACGk
# qtjMKuaFHVczugLION9tILf6RhVaJFrm2w8rblNJBaTFMtwLt/xdZFrGPItmiiGs
# qNlF5x6b2d04ErSvkcGd2I4ciVUrv262SMzeivNXiGCNpbQoZn6UE69HBNIPrMqg
# JB9xdJkOZBuTdD5k0T1B8qaP4EZfaE4V0D8y8YiLLRZ99Plh2HvSE4wa/tVXFcn6
# 3xnqgoxqq5oarTziz2DhhSmCb/oosYeixyJyFQORPJPqoOPx6jK/yEcNtgWuJHbt
# Gk1VLqcwHuoJsmwSEG/eASr/boehfvlcl3YYQWV+juXRut1dSKUWXfwjwUJwvbe+
# vO3tO6/NyOfrMfXZolTIV6+0HQuLO0avZ6ix1So9pWYGH2JHE2UDQxAJeW0nc6Ad
# Zc7debuLrLY4phLsfrMc1nnGOfUnPeBLgR2BO+u9sCzjINIDXOEF4yGaZQG3ba5z
# RnMHjWkAed1UhbPDnMC2iARcPBh8jPQtpcKTiz8DFF2iKd+X3dmiCYtOl8MYVsaM
# 9d2HV7DOENWlGZTImphN9UBSdgNMMFiz/kWkM6hZHFXDzFZnAhat0DN0p7W4yc8v
# aNKGaUn/Yf3kfNuVzwP15VWg/WIsKG5gJCrMj+/ASNj5KsFt4qSS3yuhZnHKR/Bc
# TSU9VOK+spC71K8Rk47cfHHcuF71UJPVynZl6h/IoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCCJ2VsNFOv2Up8PhZ4iiVIlX8p2pdtBrmXg+cMXK3E4TgIUIF0u
# UwvqQiK4HPvVI5CnHQUP9nkYDzIwMjYwODMxMTgwOTU1WjADAgEBoF2kWzBZMQsw
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
# BDEyBDBc54kdv3Zl5QaNuroF/CQnXXXKa2lqGIg0TklNvya0NWITE9PSLhxTpJQj
# D1T6o48wgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGADfldLR3IeS10nOR3B9CukZWn3+YcY80KRkOiN+xX/lq4
# P5xR7hBRNaFK9C1VrUfHY7MdEbQGmp++wuxeVda0Hh5l8Qeb4xxJ6bExLWOf9UkL
# 30GBHNUx9C/ajNZyg4ZFLo8Wfs1WunpZMXaFcyXx3KBxsBKaYVu9mXohHAH+YtoB
# K/+p9W1i6Et+NHHaMTFLTdc8Y5a19qTivKjnBnixsHWuX6lUHGUHuYK760AZ8NZA
# bl6PhYAfqXySOCxM2btIYZcKo/3jeR4IX0MTQAX8Yn3XJEeNXjl4nX2ou7cugE5h
# eGOul0KTccC4Sd/2sVEHQbXXpOvR3w7EYjJPFzeswDsiZhQgJyV1yb1tIzWGBkLC
# 9SZqfwmTZqStJa+VQ+YWttHf7ujyyTQ37ehGQN3+gbtMpMk92JS7qfwst3Yzjpgy
# NILaMyV6yd25G6zBlWQRbPnNjzzTR8bbaxjcVBEiKgxPmQ29vHDx7u6jXlTsrGKI
# xs03q6hwaFCj8nlGBasp
# SIG # End signature block
