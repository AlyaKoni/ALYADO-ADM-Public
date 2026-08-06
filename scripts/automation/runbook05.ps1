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
[System.Net.ServicePointManager]::SecurityProtocol =[System.Net.SecurityProtocolType]::Tls12
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
            throw
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
        Write-Output "Runtime environment: $($runEnv.name) on account: $AutomationAccountName"
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
            $retries = 20
            do {
                Start-Sleep -Seconds ((20 - $retries) * 4)
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
            	if ($retries -lt 15) { Write-Output "Retries left: $retries" }
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
            Write-Output "Package $($packageName): Current version is $packageActVersion, required version is $packageReqVersion, provisioningState is $($package.properties.provisioningState)"

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

            if ([string]::IsNullOrWhiteSpace($packageActVersion) -and $package.properties.provisioningState -ne "Failed") {
                Write-Output "Was not able to determine current version of package $packageName."
            }

            # Checking if the package needs to be updated
            do {
                if ($packageActVersion -ne $packageReqVersion -or $package.properties.provisioningState -eq "Failed") {
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
                            # Update (PATCH) n ot working as expected, so we delete and re-create the package instead
                            # $resp = Invoke-AzRestMethod -Method Patch -Path $reqUrl -Payload ($body | ConvertTo-Json -Depth 10)
                            # if ($resp.StatusCode -ge 400) {
                            #     throw "Error updating package: $($resp.Content)"
                            # }
                            # else {
                            #     Write-Output "Actual:"
                            #     Write-Output $resp.Content
                            #     Write-Output "Requested:"
                            #     Write-Output ($body | ConvertTo-Json -Depth 10)
                            # }
                            # do {
                            #     Start-Sleep -Seconds 10
                            #     $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
                            #     $pkg = $resp.Content | ConvertFrom-Json
                            #     Write-Output "provisioningState $($pkg.properties.provisioningState)"
                            # } while ( $pkg.properties.provisioningState -eq "Updating" -or $pkg.properties.provisioningState -eq "Creating" -or $pkg.properties.provisioningState -eq "ContentValidated" -or $pkg.properties.provisioningState -eq "ConnectionTypeImported" -or $pkg.properties.provisioningState -eq "RunningImportModuleRunbook" )
                            # Write-Output "ProvisioningState is now $($pkg.properties.provisioningState)"
    
                            # $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
                            # $pkg = $resp.Content | ConvertFrom-Json
                            # if ($pkg.properties.version -ne $packageReqVersion -or $pkg.properties.provisioningState -eq "Failed") {
                                # Write-Warning "Update was not working, trying to delete and re-create the package"
                                $pretries = 3
                                $toBeDeleted = $true
                                do
                                {
                                    try {
                                        $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
                                        $pkg = $resp.Content | ConvertFrom-Json
                                        if ($resp.StatusCode -eq 404) {
                                            $toBeDeleted = $false
                                        }
                                    } catch {
                                        $toBeDeleted = $false
                                    }
                                    if ($toBeDeleted) {
                                        Write-Output "Deleting package $packageName"
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
                                    }
                                    Write-Output "Installing package $packageName"
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
                                    } while ( $pkg.properties.provisioningState -eq "Updating" -or $pkg.properties.provisioningState -eq "Creating" -or $pkg.properties.provisioningState -eq "ContentValidated" -or $pkg.properties.provisioningState -eq "ConnectionTypeImported" -or $pkg.properties.provisioningState -eq "RunningImportModuleRunbook" )
                                    Write-Output "ProvisioningState is now $($pkg.properties.provisioningState)"

                                    if ($pkg.properties.provisioningState -ne "Succeeded" -and $pkg.properties.provisioningState -ne "Failed") {
                                        Write-Warning "Unknown provisioningState $($pkg.properties.provisioningState) for package $packageName. Waiting 120 seconds and checking again."
                                        Start-Sleep -Seconds 120
                                        $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
                                        $pkg = $resp.Content | ConvertFrom-Json
                                    }
                                    if ($pkg.properties.provisioningState -eq "Succeeded") {
                                        Write-Output "Package $packageName updated to version $packageReqVersion"
                                        break
                                    }

                                    if ($pretries -lt 0)
                                    {
                                        throw "Could not update package $packageName to version $packageReqVersion after multiple attempts"
                                    }
                                    $pretries--
                                } while ($true)
                            # }
                        }
                        catch {
                            Write-Error "Error updating package: $($_.Exception.Message)" -ErrorAction Continue
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
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA0EfCi3T/KNTdT
# vjJa7p65BUCqJArMxj4jyOT0Y3ZXjKCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDkBGKWp
# WN2pvmYIXWzZwFR9AcCPgBUM1xLQrEtQztRLMA0GCSqGSIb3DQEBAQUABIICAJFr
# bH7SMltudkXHJpsUwAWNFC/tXpJ7RmUGDZqyj0iGbHHUC1nQ/goGi5KLuqpiYhax
# vudqFRtJtiRBu/VwvUiMpqBFaesrtvcNiaO1leqb6ETz/Dv7SJg8peHliOSebyFh
# nt9xm/HFwd4xpXmYrxBhbOjydFezF3sAsA2E5PMzWIsgb1IH6+68/VeXEFAtRB8w
# EbyY0N7nVcBhsNpMYoeqbbApWNIqZ2W3k9lZE1UrJzdv7jjk86lbTOb97G2Sii8k
# 6Kk0WN+jskzY7i6I+38Q2HcDDCC0TDyfYIjmFIeVaZG+Vz0oE6mS3S5pcfPMp9ki
# qnU020XA4A0qMSp9ZLvdeQLvdjtcbv8YxZGPfAjwrRpWNzmuzu/I33It0zVMA4uA
# EbuyOMYt/GcgeYCpccq800TmJ0Gdk2fYwpcIHTrdqO67zqoMvZuMpHNfLg6l68wX
# aIMtAp+QpDiVw2u47eaCDoMMCKUwT7UWTWUfVyhn5URD8DaqoGe2igMCoUZWh0lU
# QWV/bwsdmXp2E2QCKp5yTxivO0n7BJYPXeM/za4bwwMJjzJf50FVhctiwdlKIG54
# FsOitEw4A1otMfk8WDh36GSS0ksM/7tgHNGkcMWcfxspuDyRj6FWNFywFUCj0dfb
# KcMQQ7+nJnmzbLl9nNwvoXci3CMdESlP46Ig9N7moYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCBtXWJsQsqN4ki79uH6vcHIaFJe5cNYB0cvLADtnh4e6wIUadRm
# QRgINPPmymhtAFTR/+eVTRQYDzIwMjYwODA0MTAyMTM4WjADAgEBoF2kWzBZMQsw
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
# BDEyBDDKitO6x1VybEGPt9f7V+5j9c6ccr/yI7z0vIVN+p+oA/tH1cbJ73p9lJ+9
# c/DSEncwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAEVGWYSSLQWFyaFyFCYY2dxHDrk7859C3zAowujEopYDQ
# f9FotJUEkhAPy74UhKM29wGDVa+jn1HRDqqXLpe+SodnM203yBSKtlAxPGl0rngZ
# ukyrFc4T4h1F8p7fGZxo90M+OHzMT5AedkQIs+RUFLX5iU/r316BSeTkbSGEfOKB
# a6qnKqmUCkuh7qZliTIh9VuI/TqdToPi4eC4uswPEils+6GFrup87ruOTN9hhuLU
# i9zzaaLh5Us4oS1I/7dKxF5z32Ik2OLvOx9R38XAuQu2xcYdAi6+jfNJZKvW2HdB
# fBsxo4XbGu2pIGRshh7R3ll/iT7HqAgG+aFLxe+r+Yqs0oGhPQbEIGGDXToA09JE
# D9Dy1hf1gBmG5iIKOcQrEbcGqQv5yJ0RmSzqBFrBciQ50egRHEvx4m3gkySMHzVl
# qUcar+lGvrMTx/lBgAXg3IFHVa8SUqhYMiOBu2kYWDp3mxkLvJ1M2eizroVRbQqu
# 1U9dG4tR/fuEH5b8Ruir
# SIG # End signature block
