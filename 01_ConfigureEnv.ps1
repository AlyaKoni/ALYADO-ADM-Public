#Requires -Version 2.0

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
$PSDefaultParameterValues['out-file:width'] = 2000
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
$AlyaDefaultModulePath = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "WindowsPowerShell\Modules"
$AlyaDefaultModulePathCore = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "PowerShell\Modules"
$AlyaDefaultScriptPath = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "WindowsPowerShell\Scripts"
$AlyaDefaultScriptPathCore = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "PowerShell\Scripts"
if (-Not $AlyaModulePath) { $AlyaModulePath = $AlyaDefaultModulePath }
if (-Not $AlyaScriptPath) { $AlyaScriptPath = $AlyaDefaultScriptPath }
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
    if (((Test-Path $AlyaDefaultModulePath) -or (Test-Path $AlyaDefaultModulePathCore)) -and -not $Global:AlyaDefaultModulePathWarningDone)
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

<# CLIENT SETTINGS #>
$AlyaOfficeToolsOnTaskbar = @("OUTLOOK.EXE", "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE") #WINPROJ.EXE, VISIO.EXE, ONENOTE.EXE, MSPUB.EXE, MSACCESS.EXE

<# URLS #>
$AlyaGitDownload = "https://git-scm.com/downloads/win"
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

function Remove-OneDriveItemRecursive
{
    [cmdletbinding()]
    param(
        [string] $Path
    )
    if ($Path -and (Test-Path -LiteralPath $Path))
    {
        $Items = Get-ChildItem -LiteralPath $Path -File -Recurse
        foreach ($Item in $Items)
        {
            try
            {
                $Item.Delete()
            } catch
            {
                throw "Remove-OneDriveItemRecursive - Couldn't delete $($Item.FullName), error: $($_.Exception.Message)"
            }
        }
        $Items = Get-ChildItem -LiteralPath $Path -Directory -Recurse | Sort-object -Property { $_.FullName.Length } -Descending
        foreach ($Item in $Items)
        {
            try
            {
                $Item.Delete()
            } catch
            {
                throw "Remove-OneDriveItemRecursive - Couldn't delete $($Item.FullName), error: $($_.Exception.Message)"
            }
        }
        try
        {
            (Get-Item -LiteralPath $Path).Delete()
        } catch
        {
            throw "Remove-OneDriveItemRecursive - Couldn't delete $($Path), error: $($_.Exception.Message)"
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
            $req = Invoke-WebRequest -Uri "https://www.goffogle.ch"
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
	Invoke-WebRequest -Uri $nusrc.href -OutFile $fileName
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
    foreach($file in (Get-ChildItem -Path "$($AlyaTools)\Packages\$packageName" -Recurse))
    {
        Unblock-File -Path $file.FullName
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
			    $req = Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore
			}
			catch {
			    $req = $_.Exception.Response
			}
			$ModuleContentUrl = $req.Headers.Location
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
    if ($AlyaIsPsCore -and $moduleName -in @("Microsoft.Online.Sharepoint.PowerShell", "MSOnline", "AzureADPreview", "AIPService", "AppX"))
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

<# LOGIN FUNCTIONS #>
function LogoutAllFrom-Az()
{
    Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue
    Clear-AzContext -Scope CurrentUser -Force -ErrorAction SilentlyContinue
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
}
function LoginTo-Az(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName = $null,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId = $null,
    [string] [Parameter(Mandatory = $false)] $AuthScope = $null,
    [string] [Parameter(Mandatory = $false)] $TenantId = $null)
{
    Write-Host "Login to Az" -ForegroundColor $CommandInfo
    if (-Not $TenantId) { $TenantId = $AlyaTenantId }

    try { Update-AzConfig -Scope Process -EnableLoginByWam $false -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Update-AzConfig -Scope Process -DisplaySurveyMessage $false -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Update-AzConfig -Scope Process -EnableDataCollection $false -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}

    if ($AlyaIsDevOpsPipeline)
    {
        Write-Host "  within DevOps"
        $AlyaContext = Get-CustomersContext
        if (-Not $AlyaContext)
        {
            throw "Not able to get devOps az context. Please select a connection in the pipeline task."
        }
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
        if (-Not $AlyaContext)
        {
            #PowerShell login
            #Write-Host "  PowerShell login"
            if ($SubscriptionId)
            {
                if ($AuthScope)
                {
                    Connect-AzAccount -Environment $AlyaAzureEnvironment -Tenant $TenantId -Subscription $SubscriptionId -AuthScope $AuthScope | Out-Null
                }
                else
                {
                    Connect-AzAccount -Environment $AlyaAzureEnvironment -Tenant $TenantId -Subscription $SubscriptionId | Out-Null
                }
            }
            elseif ($SubscriptionName)
            {
                if ($AuthScope)
                {
                    Connect-AzAccount -Environment $AlyaAzureEnvironment -Tenant $TenantId -Subscription $SubscriptionName -AuthScope $AuthScope | Out-Null
                }
                else
                {
                    Connect-AzAccount -Environment $AlyaAzureEnvironment -Tenant $TenantId -Subscription $SubscriptionName | Out-Null
                }
            }
            else
            {
                if ($AuthScope)
                {
                    Connect-AzAccount -Environment $AlyaAzureEnvironment -Tenant $TenantId -AuthScope $AuthScope | Out-Null
                }
                else
                {
                    Connect-AzAccount -Environment $AlyaAzureEnvironment -Tenant $TenantId | Out-Null
                }
            }
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

function LoginTo-MgGraph(
    [string] [Parameter(Mandatory = $false)] $SubscriptionName = $null,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId = $null,
    [string[]] [Parameter(Mandatory = $false)] $Scopes = $null)
{
    Write-Host "Login to Graph" -ForegroundColor $CommandInfo

    try { Set-MgGraphOption -EnableLoginByWAM $false -ErrorAction SilentlyContinue | Out-Null } catch {}

    if ($AlyaIsDevOpsPipeline)
    {
        Write-Host "  within DevOps"

        LoginTo-Az -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -TenantId $AlyaTenantId -AsSecureString
        Connect-MGGraph -AccessToken $token.Token -Environment $AlyaGraphEnvironment -NoWelcome

        $mgContext = Get-MgContext | Where-Object { $_.TenantId -eq $AlyaTenantId } -ErrorAction SilentlyContinue
        if (-Not $mgContext)
        {
            throw "Not able to get devOps graph context. Please select a connection in the pipeline task."
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
            if ($null -ne $AlyaGraphAppId) {
                Connect-MGGraph -Environment $AlyaGraphEnvironment -ClientId $AlyaGraphAppId -Scopes $Scopes -TenantId $AlyaTenantId -NoWelcome
            } else {
                Connect-MGGraph -Environment $AlyaGraphEnvironment -Scopes $Scopes -TenantId $AlyaTenantId -NoWelcome
            }
            $mgContext = Get-MgContext | Where-Object { $_.TenantId -eq $AlyaTenantId } -ErrorAction SilentlyContinue
            if (-Not $Global:AlyaMgContext)
            {
                #Required after a consent, otherwise you run into a login mess
                # TODO check bug still there, way to check if consent happended
                $mgContext = Disconnect-MgGraph
                if ($null -ne $AlyaGraphAppId) {
                    Connect-MGGraph -Environment $AlyaGraphEnvironment -ClientId $AlyaGraphAppId -Scopes $Scopes -TenantId $AlyaTenantId -NoWelcome
                } else {
                    Connect-MGGraph -Environment $AlyaGraphEnvironment -Scopes $Scopes -TenantId $AlyaTenantId -NoWelcome
                }
                $mgContext = Get-MgContext | Where-Object { $_.TenantId -eq $AlyaTenantId } -ErrorAction SilentlyContinue
                $Global:AlyaMgContext = $mgContext
            }

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

        if (-Not $mgContext)
        {
            Write-Error "Not logged in to Graph!" -ErrorAction Continue
            Exit 1
        }
    }
}
#LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"
#Get-MgUser -UserId "any@alyaconsulting.ch"

function LoginTo-DataGateway()
{
    Write-Host "Login to DataGateway" -ForegroundColor $CommandInfo

    $isLoggedIn = $false
    try
    {
        Get-DataGatewayAccessToken
        $isLoggedIn = $true
    }
    catch { }
    if (-Not $isLoggedIn)
    {
        $creds = Get-Credential -Message "Please provide DataGatewayApp credentials. User is the AppId. Password is the the client secret."
        return Connect-DataGatewayServiceAccount -ApplicationId $creds.UserName -ClientSecret $creds.Password -Tenant $AlyaTenantId
    }
    return $null
}

function Get-AudienceAccessToken(
    [string] [Parameter(Mandatory = $false)] $audience = "74658136-14ec-4630-ad9b-26e160ff0fc6",
    [string] [Parameter(Mandatory = $false)] $SubscriptionName = $null,
    [string] [Parameter(Mandatory = $false)] $SubscriptionId = $null,
    [string] [Parameter(Mandatory = $false)] $TenantId = $null)
{
    if (-Not $TenantId) { $TenantId = $AlyaTenantId }
    $AlyaContext = Get-CustomersContext -TenantId $TenantId -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($AlyaContext.Account, $AlyaContext.Environment, $TenantId, $null, "Never", $null, $audience)
    if (-Not $token -or -Not $token.AccessToken)
    {
        throw "Can't aquire an access token."
    }
    return $token.AccessToken
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

function LoginTo-Teams()
{
    Write-Host "Login to Teams" -ForegroundColor $CommandInfo
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
        if ([string]::IsNullOrEmpty($AlyaTeamsEnvironment)) {
            Connect-MicrosoftTeams
        } else {
            Connect-MicrosoftTeams -TeamsEnvironmentName $AlyaTeamsEnvironment
        }
    }

    $TenantDetail = Get-CsTenant -ErrorAction SilentlyContinue
    if (-Not $TenantDetail)
    {
        Write-Error "Not logged in to Teams!" -ErrorAction Continue
        Exit 1
    }
}

function LoginTo-EXO([String[]]$commandsToLoad = $null)
{
    Write-Host "Login to EXO" -ForegroundColor $CommandInfo

    $actConnection = Get-ConnectionInformation | Where-Object { $_.IsEopSession -eq $false -and $_.State -eq "Connected" -and $_.TenantID -eq $AlyaTenantId -and $_.TokenExpiryTimeUTC -gt [DateTime]::UtcNow }
    if (-Not $actConnection)
    {
        if ($commandsToLoad)
        {
            Connect-ExchangeOnline -ExchangeEnvironmentName $AlyaExchangeEnvironment -ShowBanner:$false -ShowProgress $true -CommandName $commandsToLoad
        }
        else
        {
            Connect-ExchangeOnline -ExchangeEnvironmentName $AlyaExchangeEnvironment -ShowBanner:$false -ShowProgress $true
        }
    }
}

function LoginTo-IPPS()
{
    Write-Host "Login to IPPS" -ForegroundColor $CommandInfo
    $actConnection = Get-ConnectionInformation | Where-Object { $_.IsEopSession -eq $true -and $_.State -eq "Connected" -and $_.TenantID -eq $AlyaTenantId -and $_.TokenExpiryTimeUTC -gt [DateTime]::UtcNow }
    if (-Not $actConnection)
    {
        if ($AlyaLoginEndpoint -eq "https://login.microsoftonline.com") {
            Connect-IPPSSession -ShowBanner:$false
        } else {
            Connect-IPPSSession -ShowBanner:$false -AzureADAuthorizationEndpointUri $AlyaLoginEndpoint
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

function LoginTo-SPO()
{
    Write-Host "Login to SPO" -ForegroundColor $CommandInfo
    $Site = $null
    try { $Site = Get-SPOSite -Identity $AlyaSharePointAdminUrl -ErrorAction SilentlyContinue } catch {}
    if (-Not $Site)
    {
        Connect-SPOService -Region $AlyaSharePointEnvironment -Url $AlyaSharePointAdminUrl -ModernAuth $true -AuthenticationUrl "https://login.microsoftonline.com/organizations"
    }
    try { $Site = Get-SPOSite -Identity $AlyaSharePointAdminUrl -ErrorAction SilentlyContinue } catch {}
    if (-Not $Site)
    {
        throw "Not logged in to SPO!"
    }
}

function ReloginTo-PnP(
    [string] [Parameter(Mandatory = $true)] $Url,
    [string] [Parameter(Mandatory = $false)] $ClientId = $null,
    [string] [Parameter(Mandatory = $false)] $Thumbprint = $null
    )
{
    return LoginTo-PnP -Url $Url -ClientId $ClientId -Thumbprint $Thumbprint -Relogin $true
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
    try { $null = Disconnect-PnPOnline -Connection $Connection -ErrorAction SilentlyContinue } catch {}
}

function LoginTo-PnP(
    [string] [Parameter(Mandatory = $true)] $Url,
    [string] [Parameter(Mandatory = $false)] $TenantAdminUrl = $null,
    [object] [Parameter(Mandatory = $false)] $Connection = $null,
    [string] [Parameter(Mandatory = $false)] $ClientId = $null,
    [string] [Parameter(Mandatory = $false)] $Thumbprint = $null,
    [bool] [Parameter(Mandatory = $false)] $Relogin = $false
    )
{
    Write-Host "Login to SharePointPnPPowerShellOnline '$($Url)'" -ForegroundColor $CommandInfo

    if ([string]::IsNullOrEmpty($AlyaPnPAppId) -or $AlyaPnPAppId -eq "PleaseSpecify")
    {
        Write-Warning "We need to register the PnP app"
        & "$AlyaScripts\sharepoint\Register-PnPApp.ps1"
        throw "Please restart this script"
    }

    if ([string]::IsNullOrEmpty($TenantAdminUrl))
    {
        $TenantAdminUrl = $AlyaSharePointAdminUrl
    }
    if ($null -eq $Connection -and $null -ne $Global:AlyaPnpAdminConnection)
    {
        $Connection = $Global:AlyaPnpAdminConnection
    }
    $env:PNPPOWERSHELL_DISABLETELEMETRY = "true"

    $AlyaConnection = $null
    $CreatedConnection = $false
    if ($ClientId -and $Thumbprint)
    {
        $AlyaConnection = $Global:AlyaPnpConnections | Where-Object { $_.Url.TrimEnd("/") -eq $Url.TrimEnd("/") -and $_.ClientId -eq $ClientId }
    }
    else
    {
        $AlyaConnection = $Global:AlyaPnpConnections | Where-Object { $_.Url.TrimEnd("/") -eq $Url.TrimEnd("/") }
    }

    if ($null -ne $AlyaConnection -and $Relogin)
    {
        $null = Disconnect-PnPOnline -Connection $AlyaConnection
        if ($ClientId -and $Thumbprint)
        {
            $Global:AlyaPnpConnections = $Global:AlyaPnpConnections | Where-Object { $_.Url.TrimEnd("/") -ne $Url.TrimEnd("/") -and $_.ClientId -ne $ClientId }
        }
        else
        {
            $Global:AlyaPnpConnections = $Global:AlyaPnpConnections | Where-Object { $_.Url.TrimEnd("/") -ne $Url.TrimEnd("/") }
        }
        $AlyaConnection = $null
    }

    if ($null -eq $AlyaConnection)
    {
        if ($ClientId -and $Thumbprint)
        {
            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -Url $Url -TenantAdminUrl $TenantAdminUrl -ReturnConnection -ClientId $ClientId -Thumbprint $Thumbprint -Tenant $AlyaTenantName
        }
        else
        {
            if (-Not $Global:AlyaPnpAdminConnection) {
                try {
                    if ([string]::IsNullOrEmpty($AlyaPnPAppId)) {
                        if ($AlyaPnpEnvironment -eq "Production") {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -Url $TenantAdminUrl -ReturnConnection -Interactive -ValidateConnection
                        } else {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -Url $TenantAdminUrl -ReturnConnection -Interactive -ValidateConnection
                        }
                    } else {
                        if ($AlyaPnpEnvironment -eq "Production") {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -ClientId $AlyaPnPAppId -Url $TenantAdminUrl -ReturnConnection -Interactive
                        } else {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -ClientId $AlyaPnPAppId -Url $TenantAdminUrl -ReturnConnection -Interactive -ValidateConnection
                        }
                    }
                }
                catch {
                    Write-Warning $_.Exception
                    Register-PnPManagementShellAccess -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment
                    try {
                        if ($AlyaPnpEnvironment -eq "Production") {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -Url $TenantAdminUrl -ReturnConnection -Interactive -ValidateConnection
                        } else {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -Url $TenantAdminUrl -ReturnConnection -Interactive -ValidateConnection
                        }
                    }
                    catch {
                        Write-Warning "Launch in browser: SharePoint, PowerApps, PowerAutomate, Teams, OneDrive"
                        Write-Warning "Try to register the PnP app with the following url in a browser. Check error messages in url."
                        Register-PnPManagementShellAccess -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -ShowConsentUrl
                        pause
                        if ($AlyaPnpEnvironment -eq "Production") {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -Url $TenantAdminUrl -ReturnConnection -Interactive -ValidateConnection
                        } else {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -Url $TenantAdminUrl -ReturnConnection -Interactive -ValidateConnection
                        }
                    }
                }
                $Global:AlyaPnpAdminConnection = $AlyaConnection
                if (-Not $Connection)
                {
                    $Connection = $Global:AlyaPnpAdminConnection
                }
            }
            if ($Url -ne $TenantAdminUrl) {
                try {
                    if ([string]::IsNullOrEmpty($AlyaPnPAppId)) {
                        if ($AlyaPnpEnvironment -eq "Production") {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -Url $Url -Connection $Connection -ReturnConnection -Interactive -ValidateConnection
                        } else {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -Url $Url -Connection $Connection -ReturnConnection -Interactive -ValidateConnection
                        }
                    } else {
                        if ($AlyaPnpEnvironment -eq "Production") {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -ClientId $AlyaPnPAppId -Url $Url -Connection $Connection -ReturnConnection -Interactive -ValidateConnection
                        } else {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -ClientId $AlyaPnPAppId -Url $Url -Connection $Connection -ReturnConnection -Interactive -ValidateConnection
                        }
                    }
                }
                catch {
                    Register-PnPManagementShellAccess
                    try {
                        if ($AlyaPnpEnvironment -eq "Production") {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -Url $Url -Connection $Connection -ReturnConnection -Interactive -ValidateConnection
                        } else {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -Url $Url -Connection $Connection -ReturnConnection -Interactive -ValidateConnection
                        }
                    }
                    catch {
                        Write-Warning "Try to register the PnP app with the following url in a browser. Check error messages in url."
                        Register-PnPManagementShellAccess -ShowConsentUrl
                        pause
                        if ($AlyaPnpEnvironment -eq "Production") {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -Url $Url -Connection $Connection -ReturnConnection -Interactive -ValidateConnection
                        } else {
                            $AlyaConnection = Connect-PnPOnline -Tenant $AlyaTenantName -AzureEnvironment $AlyaPnpEnvironment -Url $Url -Connection $Connection -ReturnConnection -Interactive -ValidateConnection
                        }
                    }
                }
            }
        }
        $CreatedConnection = $true
    }

    $AlyaContext = $null
    try { $AlyaContext = Get-PnPContext -Connection $AlyaConnection -ErrorAction SilentlyContinue } catch [System.InvalidOperationException] {}
    if (-Not $AlyaContext)
    {
        throw "Not logged in to SharePointPnPPowerShellOnline!"
    }

    if ($CreatedConnection)
    {
        $Global:AlyaPnpConnections += $AlyaConnection
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
        throw "Not logged in to AADRM!"
    }
}

function LoginTo-AIP()
{
    Write-Host "Login to AIP" -ForegroundColor $CommandInfo
    $ServiceDetail = $null
    try { $ServiceDetail = Get-AipService -ErrorAction SilentlyContinue } catch [Microsoft.RightsManagementServices.Online.Admin.PowerShell.AdminClientException] {}
    if ($null -eq $ServiceDetail)
    {
        Connect-AipService -Environment $AlyaAzureEnvironment -Tenant $AlyaTenantId
    }
    $ServiceDetail = $null
    try { $ServiceDetail = Get-AipService -ErrorAction SilentlyContinue } catch [Microsoft.RightsManagementServices.Online.Admin.PowerShell.AdminClientException] {}
    if ($null -eq $ServiceDetail)
    {
        throw "Not logged in to AIP!"
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
        if (Test-Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.1\WebDriver.dll") {
            Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.1\WebDriver.dll"
        } else {
            Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.0\WebDriver.dll"
        }
    } else {
        Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\net48\WebDriver.dll"
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
        if (Test-Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.1\WebDriver.dll") {
            Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.1\WebDriver.dll"
        } else {
            Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\netstandard2.0\WebDriver.dll"
        }
    } else {
        Add-Type -Path "$($AlyaTools)\Packages\Selenium.WebDriver\lib\net48\WebDriver.dll"
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

# SIG # Begin signature block
# MIIvCQYJKoZIhvcNAQcCoIIu+jCCLvYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB6fG3vpHLkmK/q
# uA+g0OTfA/3Gc+9tFDMZX6zQrq8MdaCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDuFcQyq
# 2eWr1HL7iVvF0meHcsrMJUhX6EYv6TY+YWsSMA0GCSqGSIb3DQEBAQUABIICAKsv
# cMRh8pntHwidAC39/T9YBOScP9dtNDMaoF1gBXzwtwq+3VJ31hA3fUthYsjQogNW
# gLpfYApk18cjkSIdiQLeNrbavhLYqzP5Iz/eKn75NofczWaLfgQnYQ1iduhgsR1x
# qID1VQpDEmT60tr2/zFz0HoNogcwY3BbP9NiIQX3/Tann5FxvnP7fPqMCFk9OvsZ
# XlnI0FqbOhVvJCHMv4sMWCyqa2CPPbf/bn16Y09743Zq5S3KKASPP1RKuiLLV4eM
# rtPG3xXkmbpqKeN+HPabHC6H4o0iUTodRMgBExoQAQDzxje5NylRkJZeQT5kq/0C
# B7qRgTA+FM6L09K8zuaoBtRf7bBz60/WokVuzKpWXzFxcQcfGFImgp16v60CiFL1
# CVphddiT6YfdRYcW/CyDFAz3MAYkeMVZitVX+hTA5L3MGKl1gjIFvKkoe8OnGhnX
# a261V9WW8k5c/wwrjcGF9IeL34Vk3p/2ZLR4cMEPq5RwHXKnqeYmQuDSUKmV5eT4
# K393MpzO2XICkCdb97ua/R7tlEJSfcSoxV6PwkT+XTtip22XvLoatjaGJ66BW/Te
# ycg+WWowcK1CAyIzpXXyt9GV4GRV41HZjqb34XRUmmts91m9Q7tuadVeOimRxQ2i
# VB+G1AN1WQtEA7I+lj7tIz/1R5utGjE5dQIRNT3JoYIWuzCCFrcGCisGAQQBgjcD
# AwExghanMIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEw
# gd8GCyqGSIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCCpwu7PkZjWfpK2zFTL0uXQFL4zfcJ3t4bp+xQCh8HOjwIUFa1l
# o1oi+XTJFRpP6fiq3jJVB4QYDzIwMjUwNzExMDU0NDA3WjADAgEBoFikVjBUMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwh
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMC
# AQICEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNp
# Z24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5
# WhcNMzQxMjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFs
# U2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWdu
# MSAtIFI2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4
# PuCF6+aqCj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb
# 5gk0Xydy3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJSc
# RV1W6/6efi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy
# 5RJY+o1NWhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY
# 0Lie04DuKbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2Z
# wbI6yiFHaS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYh
# KUlrMH9+2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5s
# WtX1qvCzk6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGo
# MIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYD
# VR0OBBYEFIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQC
# MEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSB
# gzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2Ev
# Z3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2Jh
# bHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaA
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9j
# cmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG
# 9w0BAQwFAAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26
# IFq7fQMIrN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76Tkv
# L+v2f4mHolGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftP
# ttS+G/MhNUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIl
# S3Ki74CU15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt
# 8DT4RQj9LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5
# lgJkgXEc1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD
# 9hQchjiGkyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71
# yzGKWnbAWQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGL
# ZtJFJzGJD7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVA
# GXCqHsh62QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZ
# MIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAw
# MDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOv
# dYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt
# 0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHP
# vIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFU
# UweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16
# ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS
# 2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm1
# 9m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIG
# bxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMD
# Ad6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/Miy
# Tdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9
# GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGG
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDD
# vWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEB
# BDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jv
# b3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29t
# L3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0B
# AQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYW
# axlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCy
# z+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQ
# cXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0
# Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59e
# odaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8
# oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1
# If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbcl
# IA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2M
# tnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB
# +SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIID
# a6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQL
# ExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjET
# MBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAw
# MDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQK
# EwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4
# QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTe
# c5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWy
# ZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7tt
# U+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrK
# otudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKF
# t3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTfl
# puwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2Fm
# CWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5
# paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4O
# hxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwo
# TK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki
# 5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnm
# XNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJE
# lrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMp
# mY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6
# JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG
# 7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/
# gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324G
# abbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5
# MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO7
# 7oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4st
# Q1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjx
# guhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJ
# YIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZI
# hvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcN
# AQkEMSIEIOAV84ypyojtjAyzdPOJGdpsBywvHayNADOdp8Um1vHGMIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1or
# d69gXP0wczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAT80D
# DhVJpyH1umI/O5p6kfZZm3cwkNgTsXLX/7I9NRbTg8xofW6CyyVBL0uhm8roU+y/
# fwmNR5FFbhJtaLJz1gMmGmsHYJFC7XpdPmvX29EwRmwBoukzrkaOa2/5oxLcSxR2
# 7dQXYRO//Rg3JtkdgoR9EmGDIUIJtLTaug2ne8/ok2vn4L/Hpw+C1XC//HlfUS+u
# Y6z2e6Ui5bUtzG6WuHwpmHIaGwudCbCgR9axgaz7QWUe7me+AHpYXy2EwUhuRvSP
# FR4VXLSKl4QsuFKFegqFcKAsQ8uRbydGWml8cQbO5UnSUP3KN85sURRo97HleNLY
# nqTfuf3N5Q1vSlOhCFLlJdI/UcFh3F7N76L81HT/kFJXnKi9w3LPLgUPQGzaI3cT
# CZIqlVajeyfpQrRgG/ilGqlJTa0g5+AgcOeXFUcWAibansIgtI2vDt1cSK5X2voK
# Lvp9LnyrNxmgYiK202oyPpEK/htLjcu85v8ki9HLPShYfuXcpnvJ977J48Fo
# SIG # End signature block
