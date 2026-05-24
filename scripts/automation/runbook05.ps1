#Requires -Version 7.0

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
    09.10.2025 Konrad Brunner       Initial Version
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Checks and updates PowerShell runtime environment packages in an Azure Automation account.

.DESCRIPTION
The runbook connects to Azure using a managed identity and RunAs account credentials to manage and update PowerShell modules in Azure Automation runtime environments. It verifies current module versions against the latest available in the PowerShell Gallery and updates default and custom packages as necessary. The script supports retry mechanisms, handles version locking, and ensures environments remain aligned with supported module versions.

.INPUTS
None. All configuration values are defined in the script placeholders or environment.

.OUTPUTS
Status messages regarding login, resource validation, package checking, updating operations, and any encountered errors.

.EXAMPLE
PS> .\runbook05.ps1

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

# Defaults
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
$Global:ErrorActionPreference = "Stop"
$Global:ProgressPreference = "SilentlyContinue"
$VerbosePreference = "Continue"
$ProgressPreference = "Continue"

# Runbook
$AlyaResourceGroupName = "##AlyaResourceGroupName##"
$AlyaAutomationAccountName = "##AlyaAutomationAccountName##"
$AlyaRunbookName = "##AlyaRunbookName##"

# RunAsAccount
$AlyaAzureEnvironment = "##AlyaAzureEnvironment##"
$AlyaApplicationId = "##AlyaApplicationId##"
$AlyaTenantId = "##AlyaTenantId##"
$AlyaCertificateKeyVaultName = "##AlyaCertificateKeyVaultName##"
$AlyaCertificateSecretName = "##AlyaCertificateSecretName##"
$AlyaSubscriptionId = "##AlyaSubscriptionId##"
$AlyaSubscriptionIds = "##AlyaSubscriptionIds##"

# Mail settings
$AlyaFromMail = "##AlyaFromMail##"
$AlyaToMail = "##AlyaToMail##"

# Group settings
$grpNameAllExt = "##AlyaAllExternalsGroup##"
$grpNameAllInt = "##AlyaAllInternalsGroup##"
$grpNameDefTeam = "##AlyaDefaultTeamsGroup##"
$grpNamePrjTeam = "##AlyaProjectTeamsGroup##"

# Other settings
$Language = "PowerShell"
$ProcessOnlyRunTimeEnvironment = $null
$ProcessOnlyPackagesWithPartialName = $null
$ProcessOnlyPackagesWithNameStarting = @("Az.", "Microsoft.Graph.")
$ProcessOnlyPackagesWithName = @(
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
    "PnP.PowerShell",
    "Microsoft.Identity.Client",
    "PackageManagement",
    "PowerShellGet"
)
$VersionsLocks = @( @{Name = "ExampleModuleName"; Version = $null } ) #Version $null means latest
$RequestCache = @{}
$Errors = @()

# Login
Write-Output "Login to Az using system-assigned managed identity"
Disable-AzContextAutosave -Scope Process | Out-Null
try {
    $AzureContext = (Connect-AzAccount -Identity -Environment $AlyaAzureEnvironment -Tenant $AlyaTenantId).Context
}
catch {
    throw "There is no system-assigned user identity. Aborting."; 
    exit 99
}
$AzureContext = Set-AzContext -Subscription $AlyaSubscriptionId -DefaultProfile $AzureContext

# Login-AzureAutomation
$retries = 10
do {
    Start-Sleep -Seconds ((10 - $retries) * 4)
    try {
        $RunAsCertificate = Get-AutomationCertificate -Name "AzureRunAsCertificate"
        try { Disconnect-AzAccount }catch {}
        Write-Output "Logging in to Az..."
        if (!$AlyaApplicationId -or $AlyaApplicationId.Contains("##")) {
            $ErrorMessage = "Missing application id."
            throw $ErrorMessage            
        }
	
        Write-Output "Logging in to Az ($AlyaAzureEnvironment)..."
        Write-Output "  Thumbprint $($RunAsCertificate.Thumbprint)"
        Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null
        Add-AzAccount `
            -ServicePrincipal `
            -TenantId $AlyaTenantId `
            -ApplicationId $AlyaApplicationId `
            -CertificateThumbprint $RunAsCertificate.Thumbprint `
            -Environment $AlyaAzureEnvironment
        Select-AzSubscription -SubscriptionId $AlyaSubscriptionId  | Write-Verbose
        $Context = Get-AzContext
        break
    }
    catch {
        try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
        $retries--
        if ($retries -lt 0) {
            Write-Error "Max retries reached!" -ErrorAction Continue
            # Check during certificate update
            $isCertUpdating = $false
            if ($certUpdateDay -gt 0) {
                if ( (Get-Date).Day -eq $certUpdateDay ) {
                    $isCertUpdating = $true
                }
            }
            else {
                $weekDay = (Get-Date).DayOfWeek.value__
                if ($weekDay -eq $certUpdateWeekDay -and $weekNumber -eq $certUpdateWeekDayWeek) {
                    $isCertUpdating = $true
                }
            }
            if ($isCertUpdating) {
                if ( (Get-Date).Hour -ge $certUpdateStartCheckHour -and (Get-Date).Hour -le $certUpdateStopCheckHour ) {
                    Write-Error "Guessing cert update! Exiting..." -ErrorAction Continue
                    exit
                }
            }
            else {
                throw
            }
        }
    }
} while ($true)

try {
    Write-Output "`n`n====================================================="
    Write-Output "Automation | Update-RuntimeEnvironmentPackages | AZURE"
    Write-Output "=====================================================`n"

    # Getting context
    $Context = Get-AzContext
    if (-Not $Context) {
        throw "Can't get Az context! Not logged in?"
    }

    # Checking ressource group
    Write-Output "Checking ressource group for automation account"
    $ResGrp = Get-AzResourceGroup -Name $AlyaResourceGroupName -ErrorAction SilentlyContinue
    if (-Not $ResGrp) {
        throw "Ressource Group not found"
    }

    # Checking automation account
    Write-Output "Checking automation account"
    $AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $AlyaResourceGroupName -Name $AlyaAutomationAccountName -ErrorAction SilentlyContinue
    if (-Not $AutomationAccount) {
        throw "Automation Account not found"
    }
    $AutomationAccountId = "/subscriptions/$($AutomationAccount.SubscriptionId)/resourceGroups/$($AutomationAccount.ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$AlyaAutomationAccountName"

    # Checking runtime environments
    Write-Output "Checking runtime environments"
    $reqUrl = "$($AutomationAccountId)/runtimeEnvironments?api-version=2024-10-23"
    $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
    if ($resp.StatusCode -ge 400) {
        throw "Error getting runtime environments: $($resp.Content)"
    }
    $runEnvs = $resp.Content | ConvertFrom-Json
    $runEnvs = $runEnvs.value | Where-Object { $_.properties.runtime.language -eq $Language }
    if (-Not $runEnvs) {
        throw "Can't get runtime environments"
    }

    foreach ($runEnv in $runEnvs) {
        Write-Output "=================================================="
        Write-Output "Runtime environment: $($runEnv.name)"
        Write-Output "=================================================="
        if (-Not [string]::IsNullOrEmpty($ProcessOnlyRunTimeEnvironment) -and $runEnv.name -ne $ProcessOnlyRunTimeEnvironment) {
            continue
        }
        $runEnvName = $runEnv.name

        if ($runEnv.properties.description -like "System-generated*") {
            Write-Output "Skipping System-generated runtime environment"
            continue
        }

        # Checking existing default packages
        Write-Output "Checking existing default packages"
        $allPackages = @()
        foreach ($package in $runEnv.properties.defaultPackages.PSObject.Properties.Name) {
            $allPackages += @{
                name       = $package
                properties = @{
                    version   = $runEnv.properties.defaultPackages.$package
                    isDefault = $true
                }
            }
        }

        # Checking existing custom packages
        Write-Output "Checking existing custom packages"
        $reqUrl = "$($AutomationAccountId)/runtimeEnvironments/$runEnvName/packages?api-version=2024-10-23"
        $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
        if ($resp.StatusCode -ge 400) {
            throw "Error getting packages: $($resp.Content)"
        }
        $packages = $resp.Content | ConvertFrom-Json
        $packages = $packages.value
        $allPackages += $packages

        # Updating packages
        Write-Output "Updating packages"
        foreach ($package in $allPackages) {
            $packageName = $package.name

            $doPackage = $null
            if ($ProcessOnlyPackagesWithName -and $null -ne $ProcessOnlyPackagesWithName) {
                $doPackage = $ProcessOnlyPackagesWithName | Where-Object { $packageName -eq $_ }
            }
            if ($null -eq $doPackage -and $ProcessOnlyPackagesWithPartialName -and $null -ne $ProcessOnlyPackagesWithPartialName) {
                $doPackage = $ProcessOnlyPackagesWithPartialName | Where-Object { $packageName -like "*$_*" }
            }
            if ($null -eq $doPackage -and $ProcessOnlyPackagesWithNameStarting -and $null -ne $ProcessOnlyPackagesWithNameStarting) {
                $doPackage = $ProcessOnlyPackagesWithNameStarting | Where-Object { $packageName -like "$_*" }
            }
            if (-Not $doPackage -and ($ProcessOnlyPackagesWithPartialName -or $ProcessOnlyPackagesWithNameStarting)) {
                Write-Warning "Skipping package $packageName"
                continue
            }
	        if ("azure cli" -eq $packageName) {
	            Write-Warning "Skipping package $packageName. Not yet implemented!"
	            continue
	        }
            $packageActVersion = $package.properties.version
            Write-Output "Checking package $packageName, current version is $packageActVersion"

            # Get latest module version from PowerShell Gallery
            $moduleUrl = $null
            $retries = 100
            do {
                Start-Sleep -Seconds ((100 - $retries) * 2)
                try {
                    $cnt = 0
                    $BaseUrl = "https://www.powershellgallery.com/api/v2/Packages()?`$filter=Id eq '$packageName'&`$top=100&`$skip=$($cnt*100)"
                    if ($RequestCache[$BaseUrl]) {
                        $moduleUrl = $RequestCache[$BaseUrl]
                        Write-Output "moduleUrl from request cache: $moduleUrl"
                    }
                    else {
                        $SearchResult = @()
                        do {
                            $Url = "https://www.powershellgallery.com/api/v2/Packages()?`$filter=Id eq '$packageName'&`$top=100&`$skip=$($cnt*100)"
                            $SearchResultCnt = Invoke-RestMethod -Method Get -Uri $Url -UseBasicParsing -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 600
                            $SearchResult += $SearchResultCnt
                            $cnt++
                        } while ($SearchResultCnt.Length -eq 100)
                        if ($SearchResult.Length -and $SearchResult.Length -gt 1) {
                            if ($packageVersion) {
                                $SearchResult = $SearchResult | Where-Object { $_.properties.Version -eq $packageVersion }
                            }
                            else {
                                if ($AllowPrereleases) {
                                    $SearchResult = ($SearchResult | Sort-Object { if ($_.properties.Version.Contains("-")) { [Version]$_.properties.Version.Substring(0, $_.properties.Version.IndexOf("-")) } else { [Version]$_.properties.Version } } -Descending)[0]
                                }
                                else {
                                    $SearchResult = $SearchResult | Where-Object { $_.properties.IsLatestVersion."#text" -eq "true" }
                                }
                            }
                        }
                        if ($SearchResult.id) {
                            $moduleUrl = $SearchResult.id
                            $RequestCache[$BaseUrl] = $moduleUrl
                        }
                    }
                }
                catch {
                    Write-Warning $_.Exception.Message
                }
                try {
                    if (-Not $moduleUrl) {
                        if ($AllowPrereleases) {
                            $Url = "https://www.powershellgallery.com/api/v2/Search()?`$filter={1}&searchTerm=%27{0}%27&targetFramework=%27%27&includePrerelease=true&`$skip=0&`$top=100"
                        }
                        else {
                            $Url = "https://www.powershellgallery.com/api/v2/Search()?`$filter={1}&searchTerm=%27{0}%27&targetFramework=%27%27&includePrerelease=false&`$skip=0&`$top=100"
                        }
                        $Url = if ($packageVersion) {
                            $Url -f $packageName, "Version%20eq%20'$packageVersion'"
                        }
                        else {
                            $Url -f $packageName, 'IsLatestVersion'
                        }
                        if ($RequestCache[$Url]) {
                            $moduleUrl = $RequestCache[$Url]
                            Write-Output "moduleUrl from request cache: $moduleUrl"
                        }
                        else {
                            $SearchResult = Invoke-RestMethod -Method Get -Uri $Url -UseBasicParsing -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 600
	
                            if ($SearchResult.Length -and $SearchResult.Length -gt 1) {
                                $SearchResult = $SearchResult | Where-Object -FilterScript {
                                    return $_.properties.title -eq $packageName
                                }
                                if ($SearchResult.Length -and $SearchResult.Length -gt 1) {
                                    if ($AllowPrereleases) {
                                        $SearchResult = ($SearchResult | Sort-Object { if ($_.properties.Version.Contains("-")) { [Version]$_.properties.Version.Substring(0, $_.properties.Version.IndexOf("-")) } else { [Version]$_.properties.Version } } -Descending)[0]
                                    }
                                    else {
                                        $SearchResult = $SearchResult | Where-Object { $_.properties.IsLatestVersion."#text" -eq "true" }
                                    }
                                }
                            }
                            if ($SearchResult.id) {
                                $moduleUrl = $SearchResult.id
                                $RequestCache[$Url] = $moduleUrl
                            }
                        }
                    }
                }
                catch {
                    Write-Warning $_.Exception.Message
                }
                $retries--
            	if ($retries -lt 100) { Write-Host "Retries left: $retries" }
            } while ($null -eq $moduleUrl -and $retries -ge 0)
            if ($null -eq $moduleUrl) {
                throw "Could not find module $packageName on PowerShell Gallery. Possibly PowerShell Gallery is down or this may be a module you imported from a different location."
            }

            $packageDetails = Invoke-RestMethod -Method Get -UseBasicParsing -Uri $moduleUrl -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 600
            $packageReqVersion = $packageDetails.entry.properties.version
            if ($null -eq $packageReqVersion -or $packageReqVersion -eq "") {
                throw "Could not determine latest version of module $packageName on PowerShell Gallery"
            }
            if ($null -ne $VersionsLocks) {
                $versionLock = $VersionsLocks | Where-Object { $_.Name -eq $packageName }
                if ($versionLock -and $null -ne $versionLock.Version -and $versionLock.Version -ne "") {
                    $packageReqVersion = $versionLock.Version
                }
            }
            Write-Output "Package $($packageName): Current version is $packageActVersion, required version is $packageReqVersion"

            $startPackageContentUrl = "https://www.powershellgallery.com/api/v2/package/$packageName/$packageReqVersion"
            $retries = 100
            do {
                if ($RequestCache[$startPackageContentUrl]) {
                    Write-Output "packageContentUrl from request cache"
                    $packageContentUrl = $RequestCache[$startPackageContentUrl]
                }
                else {
                    $packageContentUrl = $startPackageContentUrl
                    try {
                        $req = Invoke-WebRequest -Uri $packageContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 600
                    }
                    catch {
                        $req = $_.Exception.Response
                    }
                    $packageContentUrl = $req.Headers.Location.AbsoluteUri
                }
                if (-Not $packageContentUrl) { $packageContentUrl = $startPackageContentUrl }
                $retries--
            } while ($packageContentUrl -and !$packageContentUrl.Contains(".nupkg") -and $retries -ge 0)
            if ($null -eq $packageContentUrl -or $packageContentUrl -eq "") {
                throw "Could not determine content URL of module $packageName version $packageReqVersion on PowerShell Gallery"
            }
            $RequestCache[$startPackageContentUrl] = $packageContentUrl

            # Checking if the package needs to be updated
            do {
                if ($packageActVersion -ne $packageReqVersion) {
                    Write-Output "Updating package $packageName from version $packageActVersion to $packageReqVersion"
                    if ($package.properties.isDefault -eq $true) {
                        Write-Output "Updating default package"
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
                            if ($resp.StatusCode -ge 400) {
                                $err = $resp.Content | ConvertFrom-Json
                                if ($err.message -like "*is not a supported version for default package*") {
                                    Write-Warning "Version $packageReqVersion of package $packageName is not supported as default package. Extracting version from error message."
                                    if ($err.message -match "Supported versions are(.*)$") {
                                        $supportedVersions = $matches[1].Split(", -:".ToCharArray(), [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { [Version]$_.Trim(".").Trim() } | Sort-Object
                                        $packageReqVersion = $supportedVersions[-1]
                                        Write-Output "Extracted version $packageReqVersion"
                                        continue
                                    }
                                    else {
                                        throw "Could not extract supported versions from error message"
                                    }
                                }
                                else {
                                    throw "Error updating package: $($resp.Content)"
                                }
                            }
                            else {
                                Write-Output $resp.Content
                            }
                        }
                        catch {
                            Write-Error "Error updating default package: $($_.Exception.Message)" -ErrorAction Continue
                            Write-Error $_.Exception -ErrorAction Continue
                            $Errors += $_.Exception
                        }
                    }
                    else {
                        Write-Output "Updating custom package"
                        $reqUrl = "$($AutomationAccountId)/runtimeEnvironments/$runEnvName/packages/$($packageName)?api-version=2024-10-23"
                        $body = @{
                            properties = @{
                                contentLink = @{
                                    uri         = $packageContentUrl
                                    version     = $packageReqVersion
                                    contentHash = @{
                                        algorithm = $packageDetails.entry.properties.PackageHashAlgorithm
                                        value     = $packageDetails.entry.properties.PackageHash
                                        #TODO value = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($packageDetails.entry.properties.PackageHash))
                                    }
                                }
                            }
                        }
                        try {
                            $resp = Invoke-AzRestMethod -Method Patch -Path $reqUrl -Payload ($body | ConvertTo-Json -Depth 10)
                            if ($resp.StatusCode -ge 400) {
                                throw "Error updating package: $($resp.Content)"
                            }
                            else {
                                Write-Output $resp.Content
                            }
                            do {
                                Start-Sleep -Seconds 10
                                $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
                                $pkg = $resp.Content | ConvertFrom-Json
                                Write-Output "provisioningState $($pkg.properties.provisioningState)"
                            } while ( $pkg.properties.provisioningState -eq "Updating" -or $pkg.properties.provisioningState -eq "Creating" )
                            Write-Output "ProvisioningState is now $($pkg.properties.provisioningState)"
                            $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
                            $pkg = $resp.Content | ConvertFrom-Json
                            if ($pkg.properties.version -ne $packageReqVersion) {
                                Write-Warning "Update was not working, trying to delete and re-create the package"
                                $resp = Invoke-AzRestMethod -Method Delete -Path $reqUrl
                                if ($resp.StatusCode -ge 400) {
                                    throw "Error deleting package: $($resp.Content)"
                                }
                                do {
                                    try {
                                        $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
                                        if ($resp.StatusCode -eq 404) {
                                            break
                                        }
                                    }
                                    catch {
                                        break
                                    }
                                    $pkg = $resp.Content | ConvertFrom-Json
                                    Write-Output "provisioningState $($pkg.properties.provisioningState)"
                                    Start-Sleep -Seconds 10
                                } while ( $pkg.properties.provisioningState -eq "Updating" -or $pkg.properties.provisioningState -eq "Deleting" )
                                $resp = Invoke-AzRestMethod -Method Put -Path $reqUrl -Payload ($body | ConvertTo-Json -Depth 10)
                                if ($resp.StatusCode -ge 400) {
                                    throw "Error installing package: $($resp.Content)"
                                }
                                else {
                                    Write-Output $resp.Content
                                }
                                do {
                                    Start-Sleep -Seconds 10
                                    $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
                                    $pkg = $resp.Content | ConvertFrom-Json
                                    Write-Output "provisioningState $($pkg.properties.provisioningState)"
                                } while ( $pkg.properties.provisioningState -eq "Updating" -or $pkg.properties.provisioningState -eq "Creating" )
                                Write-Output "ProvisioningState is now $($pkg.properties.provisioningState)"
                            }
                        }
                        catch {
                            Write-Error "Error updating custom package: $($_.Exception.Message)" -ErrorAction Continue
                            Write-Error $_.Exception -ErrorAction Continue
                            $Errors += $_.Exception
                        }
                    }
                }
                else {
                    Write-Output "Package $packageName is up to date"
                }
                break
            }
            while ($true)
        }

    }

    if ($Errors.Length -gt 0) { throw "Errors happended during execution. Please see log." }
    Write-Output "Done"


}
catch {
    Write-Error $_.Exception -ErrorAction Continue
    throw
}

# SIG # Begin signature block
# MIIwlQYJKoZIhvcNAQcCoIIwhjCCMIICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCArWv1IOVLi5WkA
# 4Rc5uUkv/OadFAzv0UNJqAbFSZVTC6CCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# giEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBa9H2Ao4VXI0pV1
# onlk/KuaT+sepT81XgyJnLPM8elOMA0GCSqGSIb3DQEBAQUABIICAI/L3HyaWdmf
# luO8puQFV08T0MBCgjQJmSnLyw4oyrv2pMm4kPsgjk+0fWBM9LRdRqzCUrXhRvEF
# OV2hjcLglhfrqfYSzXk4l60yB2hQzCWAGHpEk7dYehgcfO4yrc2ZsMe3clDSF6lG
# le6OzkHdkNvQ4+qgdkHrrn3osI5KQNO5x0+nymlrkwYOpR83+i3AdEHSQ1u4M+Wi
# pC83jOtdiSv21jo/QaVcYBZAbtPJIYeVLod1tiwD47ooru4duv5yfArD6lyEkqWv
# /S608Fed/FYP0k/JkmpZS2X/Tqgr2D/xUjO8w2oDepRjzChYMbkjkD5wbrc/aS1k
# wxWYJwcJufFiAAuGZkcodmRyybipR7VlHBB6roz+9idsE4mOp3ZWDDuexMvpl8nR
# DygEdzYUWSv/Uo3NydvqD5czGPcXye1U/K/yhcH83CAXFouTiRp2tNstT6bzTNWj
# 6iqmPR5KUaO+l6jj3Sfc8gPn1+Tn/kj53bIxKlP0XaA/NDVUlhuhq/NtizGIi4zJ
# ++3sirjMTnb55X/tt0tYL0/l/gkNhAajjuIcGjO6XzUBS5CdFdQ/nhT4Fl7EgWI+
# xudmr0Hmd9UnTT57EWpc07zI/XsL4p+ecevB66Qqoa+LeJKPC6uItYCfO/5dVdK8
# 2K+GS8rMASmoJSU7ayHMtGczY+XxD5lsoYId7TCCHekGCisGAQQBgjcDAwExgh3Z
# MIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIwgeQGCyqG
# SIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCGSAFlAwQC
# AQUABCAa4KzeiROK7odqvwN23drEoECqbhtfWz4tLw527Ll+TAIUIspq7+VXfwDU
# Yw34aAP2aRn8AeYYDzIwMjYwNTEyMDk1NTIyWjADAgEBoF2kWzBZMQswCQYDVQQG
# EwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFs
# c2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCCBHKgAwIB
# AgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNp
# Z24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUxMDE1MDcy
# NTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xv
# YmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNBIGZvciBD
# b2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDR
# So2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6rVD8pgy1
# sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6qADUMn96m
# qHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6CjX0t3wJfh
# L0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHux0InYS7R
# r54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKOC7QkFbkl
# hPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ0SoibbUq
# xsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQbPGs02Ba
# 8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+TfueCIU0C
# AwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEF
# BQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8dPIxlNigG
# GTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYBBQUHAQEE
# gZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dz
# b2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0cDovL3Nl
# Y3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGltZXN0YW1w
# Y2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmdsb2JhbHNp
# Z24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYDVR0gBE8w
# TTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8v
# d3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4IC
# AQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOfBvhcvoFQ
# w4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SCNLHs6vCg
# 6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdByiHteLxgj
# ugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRWLzPVcUkR
# k9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZsH8EXwiT
# UTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdPL/F8VCMK
# j3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWIV3hgRl+V
# yKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/xCB0/lSK
# LnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJsnmVbS0x
# 50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5+6PokOkQ
# 8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSIoAMCAQIC
# EQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNVBAYTAkJF
# MRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWdu
# IFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00MTA3MTYw
# MDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNh
# MTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFtcGluZyBD
# QSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW+O19i+Ld
# AoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzoZ3nN0CMn
# cZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hfGMG4PJvY
# FvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSaZKraMxFt
# 676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJexYwEVU0
# GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVrYXEdhfVL
# wuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfFJC4P5FW1
# SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z8oTvSaSI
# REovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDzPk+UbLmg
# ZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlTZbVHdqNi
# u0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxUYgoVSxqb
# 4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1UdDwEB/wQE
# AwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/AgEAMB0G
# A1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRGshx34XsV
# 8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcwAYYraHR0
# cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBEBggrBgEF
# BQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvdGltZXN0
# YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAIMAYGBFUd
# IAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1n//quXGL
# VfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM+YjPEf8A
# tC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3yZ6Vcu6Ha
# 0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8njTvAwaT
# MGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534nUINB9whO
# RicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+sQdBidnP
# uLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTfd4yw4nQd
# k1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7NacoTVxZnKG
# kv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZxci6TX78
# smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDXQbEfa93l
# hikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6DC74n5+O5
# bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkqhkiG9w0B
# AQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UE
# ChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEyMDkwMDAw
# MDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBS
# b290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0M+wn3BI4
# IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0lHI7cQ0a
# 72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/WrNU0Pn1k7
# 9S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8NyiwAS+CA6
# YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOooMUz5IWqo
# zfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+PuNF2cvN8
# oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMsDpt3UCA0
# QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvbQhQFB6r7
# FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6SW/bPnf+
# uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jhan+HKd45
# m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32xRdvPBUQ
# sA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNVHQ8BAf8E
# BAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
# HQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwFo5MT4qLn
# 4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJodHRwOi8v
# b2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9odHRwOi8v
# c2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2BgNVHR8E
# LzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3Js
# MEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5n
# bG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAi0i6
# Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l74Z/4omN
# laV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VPZnpmqUdU
# M7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+CLDZZCv5
# 6vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPVSbj/S9Il
# T0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTVha1Fe7Wf
# uy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXeP6Z/xyjv
# oW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb5O1mjj2A
# naSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZmIVHCh5i
# 2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDaI4lgH4Nx
# krXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvxbwPBKVLi
# lL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgECAg5F5rsD
# gzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWdu
# IFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xv
# YmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMaw
# iGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjI
# ElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0y
# BqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3
# YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHN
# V5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTah
# b1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV
# 2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9
# ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmF
# zzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT
# 6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEw
# DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOT
# E+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1Og
# MA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jW
# ZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMT
# VlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgH
# M3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3b
# mZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9Bx
# gXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1e
# bcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRg
# emSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2Zla
# tJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQl
# p7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l3
# 1VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MF
# WsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2Jh
# bFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBSNDUgVGlt
# ZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCGSAFlAwQC
# AqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3DQEJNDEe
# MBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJBDEyBDC2
# yeRaE189DcWnRNEK6EdxWn8v6oIEkw7ngtCEXXWCh93QgpMvuh8+cmtwBN5akMUw
# gbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS858bMJhdk
# iChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xv
# YmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5lIFI0NSBU
# aW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcN
# AQEMBQAEggGAQPXeMmR0u3qk3OKA5z3zrDMSbkHzOEKiWfncR9bkMa8i6JTsC/jA
# MqGKURbM2QtOpiO4zt/Oj/fYGIjFeHoO7gbqaz14AQP5jf6stzlsQSP22SrFqa6b
# ZQ46k/fmTTekYnDrv2OWIrOD6oloKiRdUW+zZGUwjkdHIyYqHanhP4LtAq4h1CbF
# mBh8qm1na9vdm0D9+FOZJiArkvGEpXVo7s6aFs/lIIenLPprErEQcPkTFXwiTkVA
# 9lc9lxN/VEvtxFqvlNhj6rPwa8ZylEyWF1gm3ZUsAi9FKhOaiWm259qXOjhrXo1F
# kB6EHwis4avwyGwmEygKheamuYzyiWAtZYnHQvvEu64pgd22Tm82vs/7pcOOLf6B
# vHJ7gkjG5acMXiZueYN/fF4Jegk0LUhCwhE1Mxhbrx4RabK4Lc+8lutuE39q3orR
# sMRdbt4U2P5naO/OhVAe1GKrLgcLibOkauu31nbx9WgGzPlcRG06RZHNpri/9ULg
# Fe/Nm/9SROlS
# SIG # End signature block
