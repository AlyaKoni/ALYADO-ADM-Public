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
    07.10.2025 Konrad Brunner       Initial Version
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Updates and synchronizes PowerShell modules used in Azure Automation runtime environments to their latest or defined locked versions.

.DESCRIPTION
The Update-RuntimeEnvironmentPackages.ps1 script connects to an Azure Automation Account, retrieves all PowerShell-based runtime environments, and checks all associated modules and packages. It compares installed versions against the latest versions available on the PowerShell Gallery or locked versions defined in the configuration. When updates are required, it automatically updates or replaces outdated packages within the runtime environment. The script also includes filtering options to target specific runtime environments or packages by name, prefix, or partial name.

.PARAMETER Language
Specifies the language of the runtime environment to process. Defaults to "PowerShell".

.PARAMETER ProcessOnlyRunTimeEnvironment
Specifies a single runtime environment name to process. If not provided, all runtime environments are processed.

.PARAMETER ProcessOnlyPackagesWithPartialName
Processes only those packages whose names partially match the provided strings. Accepts an array of string values.

.PARAMETER ProcessOnlyPackagesWithNameStarting
Processes only those packages whose names start with one of the provided prefixes. Defaults to "Az." and "Microsoft.Graph.".

.PARAMETER ProcessOnlyPackagesWithName
Processes only the specified package names. Defaults to a list of common Azure and Microsoft modules.

.PARAMETER VersionsLocks
Specifies a set of version locks for specific modules. Each lock is an object with a Name and Version property. A Version value of $null indicates the latest version should be used.

.INPUTS
None. The script does not accept pipeline input.

.OUTPUTS
None. The script writes progress and status information to the host and log file but does not produce objects to the pipeline.

.EXAMPLE
PS> .\Update-RuntimeEnvironmentPackages.ps1 -Language "PowerShell"

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [string]$Language = "PowerShell",
    [string]$ProcessOnlyRunTimeEnvironment = $null,
    [string[]]$ProcessOnlyPackagesWithPartialName = $null,
    [string[]]$ProcessOnlyPackagesWithNameStarting = @("Az.","Microsoft.Graph."),
    [string[]]$ProcessOnlyPackagesWithName = @(
        "Az",
        "azure cli",
        "Microsoft.Graph",
        "AIPService", 
        "AzTable", 
        "ExchangeOnlineManagement", 
        "ImportExcel", 
        "Microsoft.Online.SharePoint.PowerShell", 
        "MicrosoftTeams", 
        "MSAL.PS", 
        "PnP.PowerShell"
    ),
    [object]$VersionsLocks = @( @{Name="ExampleModuleName"; Version=$null} ) #Version $null means latest
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\automation\Update-RuntimeEnvironmentPackages-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAutomation)"
$AutomationAccountName = "$($AlyaNamingPrefix)aacc$($AlyaResIdAutomationAccount)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Automation"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Automation | Update-RuntimeEnvironmentPackages | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking ressource group
Write-Host "Checking ressource group for automation account" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    throw "Ressource Group not found"
}

# Checking automation account
Write-Host "Checking automation account" -ForegroundColor $CommandInfo
$AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
if (-Not $AutomationAccount)
{
    throw "Automation Account not found"
}
$AutomationAccountId = "/subscriptions/$($AutomationAccount.SubscriptionId)/resourceGroups/$($AutomationAccount.ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName"

# Checking runtime environments
Write-Host "Checking runtime environments" -ForegroundColor $CommandInfo
$reqUrl = "$($AutomationAccountId)/runtimeEnvironments?api-version=2024-10-23"
$resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
if ($resp.StatusCode -ge 400)
{
    throw "Error getting runtime environments: $($resp.Content)"
}
$runEnvs = $resp.Content | ConvertFrom-Json
$runEnvs = $runEnvs.value | Where-Object { $_.properties.runtime.language -eq $Language }
if (-Not $runEnvs)
{
    throw "Can't get runtime environments"
}

foreach($runEnv in $runEnvs)
{
    Write-Host "Runtime environment: $($runEnv.name)" -ForegroundColor $MenuColor
    if (-Not [string]::IsNullOrEmpty($ProcessOnlyRunTimeEnvironment) -and $runEnv.name -ne $ProcessOnlyRunTimeEnvironment)
    {
        continue
    }
    $runEnvName = $runEnv.name

    if ($runEnv.properties.description -like "System-generated*")
    {
        Write-Host "Skipping System-generated runtime environment"
        continue
    }

    # Checking existing default packages
    Write-Host "Checking existing default packages" -ForegroundColor $CommandInfo
    $allPackages = @()
    foreach($package in $runEnv.properties.defaultPackages.PSObject.Properties.Name)
    {
        $allPackages += @{
            name = $package
            properties = @{
                version = $runEnv.properties.defaultPackages.$package
                isDefault = $true
            }
        }
    }

    # Checking existing custom packages
    Write-Host "Checking existing custom packages" -ForegroundColor $CommandInfo
    $reqUrl = "$($AutomationAccountId)/runtimeEnvironments/$runEnvName/packages?api-version=2024-10-23"
    $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
    if ($resp.StatusCode -ge 400)
    {
        throw "Error getting packages: $($resp.Content)"
    }
    $packages = $resp.Content | ConvertFrom-Json
    $packages = $packages.value
    $allPackages += $packages

    # Updating packages
    Write-Host "Updating packages" -ForegroundColor $CommandInfo
    foreach ($package in $allPackages)
    {
        $packageName = $package.name

        $doPackage = $null
        if ($ProcessOnlyPackagesWithName -and $null -ne $ProcessOnlyPackagesWithName)
        {
            $doPackage = $ProcessOnlyPackagesWithName | Where-Object { $packageName -eq $_ }
        }
        if ($null -eq $doPackage -and $ProcessOnlyPackagesWithPartialName -and $null -ne $ProcessOnlyPackagesWithPartialName)
        {
            $doPackage = $ProcessOnlyPackagesWithPartialName | Where-Object { $packageName -like "*$_*" }
        }
        if ($null -eq $doPackage -and $ProcessOnlyPackagesWithNameStarting -and $null -ne $ProcessOnlyPackagesWithNameStarting)
        {
            $doPackage = $ProcessOnlyPackagesWithNameStarting | Where-Object { $packageName -like "$_*" }
        }
        if (-Not $doPackage -and ($ProcessOnlyPackagesWithPartialName -or $ProcessOnlyPackagesWithNameStarting))
        {
            Write-Host "Skipping package $packageName" -ForegroundColor $CommandInfo
            continue
        }
        $packageActVersion = $package.properties.version
        Write-Host "Checking package $packageName, current version is $packageActVersion" -ForegroundColor $CommandInfo

        # Get latest module version from PowerShell Gallery
        $moduleUrl = $null
        $retries = 10
        do
        {
            Start-Sleep -Seconds ((10-$retries)*2)
                try {
                    $cnt = 0
                    $SearchResult = @()
                    do {
                        $Url = "https://www.powershellgallery.com/api/v2/Packages()?`$filter=Id eq '$packageName'&`$top=100&`$skip=$($cnt*100)"
                        $SearchResultCnt = Invoke-RestMethod -Method Get -Uri $Url -UseBasicParsing -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 600
                        $SearchResult += $SearchResultCnt
                        $cnt++
                    } while ($SearchResultCnt.Length -eq 100)
                    if($SearchResult.Length -and $SearchResult.Length -gt 1) {
                        if ($packageVersion)
                        {
                            $SearchResult = $SearchResult | Where-Object { $_.properties.Version -eq $packageVersion }
                        }
                        else
                        {
                            if ($AllowPrereleases)
                            {
                                $SearchResult = ($SearchResult | Sort-Object { if ($_.properties.Version.Contains("-")) { [Version]$_.properties.Version.Substring(0, $_.properties.Version.IndexOf("-")) } else { [Version]$_.properties.Version } } -Descending)[0]
                            } else {
                            	$SearchResult = $SearchResult | Where-Object { $_.properties.IsLatestVersion."#text" -eq "true" }
                            }
                        }
                    }
                    if ($SearchResult.id)
                    {
                        $moduleUrl = $SearchResult.id
                    }
                } catch {
                    Write-Warning $_.Exception.Message
                }
                try {
                    if (-Not $moduleUrl)
                    {
                        if ($AllowPrereleases)
                        {
                            $Url = "https://www.powershellgallery.com/api/v2/Search()?`$filter={1}&searchTerm=%27{0}%27&targetFramework=%27%27&includePrerelease=true&`$skip=0&`$top=100"
                        } else {
                            $Url = "https://www.powershellgallery.com/api/v2/Search()?`$filter={1}&searchTerm=%27{0}%27&targetFramework=%27%27&includePrerelease=false&`$skip=0&`$top=100"
                        }
                        $Url = if ($packageVersion) {
                            $Url -f $packageName, "Version%20eq%20'$packageVersion'"
                        } else {
                            $Url -f $packageName, 'IsLatestVersion'
                        }
                        $SearchResult = Invoke-RestMethod -Method Get -Uri $Url -UseBasicParsing -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 600

                        if($SearchResult.Length -and $SearchResult.Length -gt 1) {
                            $SearchResult = $SearchResult | Where-Object -FilterScript {
                                return $_.properties.title -eq $packageName
                            }
                            if($SearchResult.Length -and $SearchResult.Length -gt 1) {
                                if ($AllowPrereleases)
                                {
                                    $SearchResult = ($SearchResult | Sort-Object { if ($_.properties.Version.Contains("-")) { [Version]$_.properties.Version.Substring(0, $_.properties.Version.IndexOf("-")) } else { [Version]$_.properties.Version } } -Descending)[0]
                                } else {
                                	$SearchResult = $SearchResult | Where-Object { $_.properties.IsLatestVersion."#text" -eq "true" }
                                }
                            }
                        }
                        if ($SearchResult.id)
                        {
                            $moduleUrl = $SearchResult.id
                        }
                    }
                } catch {
                    Write-Warning $_.Exception.Message
                }
            $retries--
        } while ($null -eq $moduleUrl -and $retries -ge 0)
        if ($null -eq $moduleUrl)
        {
                throw "Could not find module $packageName on PowerShell Gallery. Possibly PowerShell Gallery is down or this may be a module you imported from a different location."
        }

        $packageDetails = Invoke-RestMethod -Method Get -UseBasicParsing -Uri $moduleUrl -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 600
        $packageReqVersion = $packageDetails.entry.properties.version
        if ($null -eq $packageReqVersion -or $packageReqVersion -eq "")
        {
            throw "Could not determine latest version of module $packageName on PowerShell Gallery"
        }
        if ($null -ne $VersionsLocks)
        {
            $versionLock = $VersionsLocks | Where-Object { $_.Name -eq $packageName }
            if ($versionLock -and $null -ne $versionLock.Version -and $versionLock.Version -ne "")
            {
                $packageReqVersion = $versionLock.Version
            }
        }
        Write-Host "Package $($packageName): Current version is $packageActVersion, required version is $packageReqVersion"

        $packageContentUrl = "https://www.powershellgallery.com/api/v2/package/$packageName/$packageReqVersion"
        do {
            try {
                $req = Invoke-WebRequest -Uri $packageContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 600
            }
            catch {
                $req = $_.Exception.Response
            }
            $packageContentUrl = $req.Headers.Location.AbsoluteUri
        } while ($packageContentUrl -and !$packageContentUrl.Contains(".nupkg"))
        if ($null -eq $packageContentUrl -or $packageContentUrl -eq "")
        {
            throw "Could not determine content URL of module $packageName version $packageReqVersion on PowerShell Gallery"
        }

        # Checking if the package needs to be updated
        do
        {
            if ($packageActVersion -ne $packageReqVersion)
            {
                Write-Host "Updating package $packageName from version $packageActVersion to $packageReqVersion"
                if ($package.properties.isDefault -eq $true)
                {
                    Write-Host "Updating default package"
                    $reqUrl = "$($AutomationAccountId)/runtimeEnvironments/$($runEnvName)?api-version=2024-10-23"
                    $body = @{
                        properties = @{
                            defaultPackages = @{
                                $packageName = $packageReqVersion
                            }
                        }
                    }
                    try {
                        $resp = Invoke-AzRestMethod -Method Patch -Path $reqUrl -Payload ($body | ConvertTo-Json -Depth 10)
                        if ($resp.StatusCode -ge 400)
                        {
                            $err = $resp.Content | ConvertFrom-Json
                            if ($err.message -like "*is not a supported version for default package*")
                            {
                                Write-Warning "Version $packageReqVersion of package $packageName is not supported as default package. Extracting version from error message."
                                if ($err.message -match "Supported versions are(.*)$")
                                {
                                    $supportedVersions = $matches[1].Split(", -:".ToCharArray(), [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { [Version]$_.Trim(".").Trim() } | Sort-Object
                                    $packageReqVersion = $supportedVersions[-1]
                                    Write-Host "Extracted version $packageReqVersion"
                                    continue
                                }
                                else
                                {
                                    throw "Could not extract supported versions from error message"
                                }
                            }
                            else
                            {
                                throw "Error updating package: $($resp.Content)"
                            }
                        }
                        else
                        {
                            Write-Host $resp.Content
                        }
                    }
                    catch {
                        Write-Error "Error updating default package: $($_.Exception.Message)" -ErrorAction Continue
                        Write-Error $_.Exception -ErrorAction Continue
                    }
                }
                else
                {
                    Write-Host "Updating custom package"
                    $reqUrl = "$($AutomationAccountId)/runtimeEnvironments/$runEnvName/packages/$($packageName)?api-version=2024-10-23"
                    $body = @{
                        properties = @{
                            contentLink = @{
                                uri = $packageContentUrl
                                version = $packageReqVersion
                                contentHash = @{
                                    algorithm = $packageDetails.entry.properties.PackageHashAlgorithm
                                    value = $packageDetails.entry.properties.PackageHash
                                    #TODO value = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($packageDetails.entry.properties.PackageHash))
                                }
                            }
                        }
                    }
                    try {
                        $resp = Invoke-AzRestMethod -Method Patch -Path $reqUrl -Payload ($body | ConvertTo-Json -Depth 10)
                        if ($resp.StatusCode -ge 400)
                        {
                            throw "Error updating package: $($resp.Content)"
                        }
                        else
                        {
                            Write-Host $resp.Content
                        }
                        do {
                            Start-Sleep -Seconds 10
                            $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
                            $pkg = $resp.Content | ConvertFrom-Json
                            Write-Host "provisioningState $($pkg.properties.provisioningState)"
                        } while ( $pkg.properties.provisioningState -eq "Updating" -or $pkg.properties.provisioningState -eq "Creating" )
                        Write-Host "ProvisioningState is now $($pkg.properties.provisioningState)"
                        $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
                        $pkg = $resp.Content | ConvertFrom-Json
                        if ($pkg.properties.version -ne $packageReqVersion)
                        {
                            Write-Warning "Update was not working, trying to delete and re-create the package"
                            $resp = Invoke-AzRestMethod -Method Delete -Path $reqUrl
                            if ($resp.StatusCode -ge 400)
                            {
                                throw "Error deleting package: $($resp.Content)"
                            }
                            do {
                                try {
                                    $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
                                    if ($resp.StatusCode -eq 404)
                                    {
                                        break
                                    }
                                } catch {
                                    break
                                }
                                $pkg = $resp.Content | ConvertFrom-Json
                                Write-Host "provisioningState $($pkg.properties.provisioningState)"
                                Start-Sleep -Seconds 10
                            } while ( $pkg.properties.provisioningState -eq "Updating" -or $pkg.properties.provisioningState -eq "Deleting" )
                            $resp = Invoke-AzRestMethod -Method Put -Path $reqUrl -Payload ($body | ConvertTo-Json -Depth 10)
                            if ($resp.StatusCode -ge 400)
                            {
                                throw "Error installing package: $($resp.Content)"
                            }
                            else
                            {
                                Write-Host $resp.Content
                            }
                            do {
                                Start-Sleep -Seconds 10
                                $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
                                $pkg = $resp.Content | ConvertFrom-Json
                                Write-Host "provisioningState $($pkg.properties.provisioningState)"
                            } while ( $pkg.properties.provisioningState -eq "Updating" -or $pkg.properties.provisioningState -eq "Creating" )
                            Write-Host "ProvisioningState is now $($pkg.properties.provisioningState)"
                        }
                    }
                    catch {
                        Write-Error "Error updating default package: $($_.Exception.Message)" -ErrorAction Continue
                        Write-Error $_.Exception -ErrorAction Continue
                    }
                }
            }
            else
            {
                Write-Host "Package $packageName is up to date"
            }
            break
        }
        while ($true)
    }

}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDSwlRVr4KBBrJb
# gx4LSlF3ORlFiURd6gKMVNrQdYIjo6CCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBLtgS5kMm2SJD7w
# 1D02IT830e97HA3E+3qkFClQrfTzMA0GCSqGSIb3DQEBAQUABIICAGAAhJZYxxh8
# k+29PB/NzkIAsXhfP06FiUyyez7x9YtCIh+Kg/PwNfuVClmc8/p77URm+ndks/6K
# bz9y7Qu6cRjYJi7lwixjofTynmK/sOODJEHq52VJ03KOR0oe17qf9KkEFDh0tLMl
# AQqgFWt9UscU+182tbsaY/ELOOBrUaBKCTA5ggi4FM3nK1loWkAHgmymSOQjtoo5
# P61o+S3OWF6tlFWBSVuiUojs57d3tWG1W6R3HiTs2QdL39pb+dySvx/GVSU1tzf2
# Ht8RBpSOqLUxL452HbmoeBLxlaeBeqlHmlwAtuiSSQeRk9jvXeSe2SqaLt9kL8/E
# 69YI8DKW6gV+MWvulURp0F0Q62z7Yy7YlOlO46q3YM3Z/EOR9Tr7gq0RqpoMKh+F
# DpjDQB4fphIGWr3ZXzlsrVEFoKYRT47faeLKssXa4m+P14JRe/PFu91OX51BbduF
# qo5I74wBWUCn/45TLzHGCTDBrINcbYqCWI60qC+31tUJ2ULVOXAmr7YxcJvWZn7N
# UR1+0tXIK62wcOC9Mxn43la+7cHoOt2SY0aQGKSd1muYsu1Fs75cwJxbCUM+gCUY
# jdR4Hymkf9NeSL5O2s1XZuAK6TmFyYXJOpZWCvjaNwTTEl7GGvq9PSlvC/8Jf1Qb
# TxteTNFkxeXnkI91FSKi/hk0Hyde4qXZoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCCb938LRHSHM1+5Cj3UoSDMD+kbfh0qZdbYqUfGNPX8pwIUTSXOx63AVkPs
# X3IKnNXCBX++AA4YDzIwMjYwMjEwMTEzMTIwWjADAgEBoFikVjBUMQswCQYDVQQG
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
# IJd/pPK2aIjvqa6oJ8zY5q+hVxIcE/FwfF9fSKrF3yrGMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAPWDEWdgL0WiQ
# ybasOamU/OWKz7/GmJCtSpcJKwSfL5ETSehhqVGqCYQJPe8J9h5gen6rvV27Jgnd
# maEoSk7+Q7RL7x2jvteWjmyy9FKFrroxp7CEjk3Fj92DvlzdnS7ZIry8mkvHfYJR
# dsNZDJdzWkCeyk0iAevbR+Akiv2KM/ufthP75GPUed44HkpSsXRuNmd1xniRL7my
# FYyaNMUXJM2GTBrl8GQBBS6sNERIcm990Inqt3H5w8Fqs+Toiq69xvQ0Brms2DfX
# iO/8LSVnHmOijY6WJPddYWlsQvU2tI18Id5Vw1CHMPX6/SN492NSvkSbgkgEfkK4
# EIF+QyWCZ3AfeRAYrNYHLWWqOYXY2a1Kb2MnYPSnDPILbw82SkRkPhzytLg5Gdtv
# Hj/+TD5o6YiN1VBadv4yo+KfV+G6F/7bcL74UJhCOv/QJYgVxxXGZ01mCMb8MXNm
# dbnvICmw4fDVwqzd3Mo6suFWPDoGv0iBmpnSTC3AxkWUzIfX65gF
# SIG # End signature block
