#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

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
    14.11.2019 Konrad Brunner       Initial Version
    18.10.2021 Konrad Brunner       Move to Az
    23.01.2022 Konrad Brunner       Fixed issue with new found dependency module
    04.08.2023 Konrad Brunner       Changed from params to constants and new managed identity login
	02.09.2024 Konrad Brunner       Fixed LatestModuleVersionOnGallery
    31.10.2024 Konrad Brunner       Robuster Url handling

#>

<#
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT License.
#>

<#
.SYNOPSIS
Update Azure PowerShell modules in an Azure Automation account.

.DESCRIPTION
This Azure Automation runbook updates Azure PowerShell modules imported into an
Azure Automation account with the module versions published to the PowerShell Gallery.

Prerequisite: an Azure Automation account with an Azure Run As account credential.

.PARAMETER ResourceGroupName
The Azure resource group name.

.PARAMETER AutomationAccountName
The Azure Automation account name.

.PARAMETER SimultaneousModuleImportJobCount
(Optional) The maximum number of module import jobs allowed to run concurrently.

.PARAMETER AzureModuleClass
(Optional) The class of module that will be updated (AzureRM or Az)
If set to Az, this script will rely on only Az modules to update other modules.
Set this to Az if your runbooks use only Az modules to avoid conflicts.

.PARAMETER AzureEnvironment
(Optional) Azure environment name.

.PARAMETER Login
(Optional) If $false, do not login to Azure.

.PARAMETER ModuleVersionOverrides
(Optional) Module versions to use instead of the latest on the PowerShell Gallery.
If $null, the currently published latest versions will be used.
If not $null, must contain a JSON-serialized dictionary, for example:
    '{ "AzureRM.Compute": "5.8.0", "AzureRM.Network": "6.10.0" }'
or
    @{ 'AzureRM.Compute'='5.8.0'; 'AzureRM.Network'='6.10.0' } | ConvertTo-Json

.PARAMETER PsGalleryApiUrl
(Optional) PowerShell Gallery API URL.

.LINK
https://docs.microsoft.com/en-us/azure/automation/automation-update-azure-modules
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
$ErrorActionPreference = "Continue"
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

# Mail settings
$AlyaFromMail = "##AlyaFromMail##"
$AlyaToMail = "##AlyaToMail##"

# Other settings
$SimultaneousModuleImportJobCount = 10
$AzureModuleClass = "Az"
$Login = $true
$ModuleVersionOverrides = $null
$PsGalleryApiUrl = "https://www.powershellgallery.com/api/v2"

#region Constants
$script:AzureRMProfileModuleName = "AzureRM.Profile"
$script:AzureRMAutomationModuleName = "AzureRM.Automation"
$script:GetAzureRmAutomationModule = "Get-AzureRmAutomationModule"
$script:NewAzureRmAutomationModule = "New-AzureRmAutomationModule"

$script:AzAccountsModuleName = "Az.Accounts"
$script:AzAutomationModuleName = "Az.Automation"
$script:GetAzAutomationModule = "Get-AzAutomationModule"
$script:NewAzAutomationModule = "New-AzAutomationModule"

$script:AzureSdkOwnerName = "azure-sdk"

#endregion

#region Functions

function ConvertJsonDictTo-HashTable($JsonString) {
    try {
        $JsonObj = ConvertFrom-Json $JsonString -ErrorAction Stop
    }
    catch [System.ArgumentException] {
        throw "Unable to deserialize the JSON string for parameter ModuleVersionOverrides: ", $_
    }

    $Result = @{}
    foreach ($Property in $JsonObj.PSObject.Properties) {
        $Result[$Property.Name] = $Property.Value
    }

    $Result
}

# Use the managed identity to login to Azure
function Login-AzureAutomation([bool] $AzModuleOnly) {
    try {
        # Login
        Write-Output "Login to Az using system-assigned managed identity"
        Disable-AzContextAutosave -Scope Process | Out-Null
        try {
            $AzureContext = (Connect-AzAccount -Identity -Environment $AlyaAzureEnvironment).Context
        }
        catch {
            throw "There is no system-assigned user identity. Aborting."; 
            exit 99
        }
        $AzureContext = Set-AzContext -Subscription $AlyaSubscriptionId -DefaultProfile $AzureContext
    }
    catch {
        try { Write-Output ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
        throw
    }
}

# Checks the PowerShell Gallery for the latest available version for the module
function Get-ModuleDependencyAndLatestVersion([string] $ModuleName) {

    $ModuleUrlFormat = "$PsGalleryApiUrl/Search()?`$filter={1}&searchTerm=%27{0}%27&targetFramework=%27%27&includePrerelease=false&`$skip=0&`$top=40"
        
    $ForcedModuleVersion = $ModuleVersionOverridesHashTable[$ModuleName]

    $CurrentModuleUrl =
    if ($ForcedModuleVersion) {
        $ModuleUrlFormat -f $ModuleName, "Version%20eq%20'$ForcedModuleVersion'"
    }
    else {
        $ModuleUrlFormat -f $ModuleName, 'IsLatestVersion'
    }

    Write-Warning $CurrentModuleUrl
    $retries = 10
    while ($true) {
        try {
            $SearchResult = Invoke-RestMethod -Method Get -Uri $CurrentModuleUrl -UseBasicParsing
            break
        }
        catch {
            $retries--
            if ($retries -lt 0) {
                throw $_
            }
            Write-Warning "Retrying"
            Start-Sleep -Seconds ((10 - $retries) * 4)
        }
    }
    
    if (!$SearchResult) {
        Write-Verbose "Could not find module $ModuleName on PowerShell Gallery. This may be a module you imported from a different location. Ignoring this module"
    }
    else {
        if ($SearchResult.Length -and $SearchResult.Length -gt 1) {
            $SearchResult = $SearchResult | Where-Object { $_.title.InnerText -eq $ModuleName }
        }

        if (!$SearchResult) {
            Write-Verbose "Could not find module $ModuleName on PowerShell Gallery. This may be a module you imported from a different location. Ignoring this module"
        }
        else {
            Write-Warning $SearchResult.id
            $retries = 10
            while ($true) {
                try {
                    $PackageDetails = Invoke-RestMethod -Method Get -UseBasicParsing -Uri $SearchResult.id
                    break
                }
                catch {
                    $retries--
                    if ($retries -lt 0) {
                        throw $_
                    }
                    Write-Warning "Retrying"
                    Start-Sleep -Seconds ((10 - $retries) * 4)
                }
            }

            # Ignore the modules that are not published as part of the Azure SDK
            if ($PackageDetails.entry.properties.Owners -ne $script:AzureSdkOwnerName) {
                Write-Warning "Module : $ModuleName is not part of azure sdk. Ignoring this."
            }
            else {
                $ModuleVersion = $PackageDetails.entry.properties.version
                $Dependencies = $PackageDetails.entry.properties.dependencies

                @($ModuleVersion, $Dependencies)
            }
        }
    }
}

function Get-ModuleContentUrl($ModuleName) {
    $ModuleContentUrlFormat = "$PsGalleryApiUrl/package/{0}"
    $VersionedModuleContentUrlFormat = "$ModuleContentUrlFormat/{1}"

    $ForcedModuleVersion = $ModuleVersionOverridesHashTable[$ModuleName]
    if ($ForcedModuleVersion) {
        $VersionedModuleContentUrlFormat -f $ModuleName, $ForcedModuleVersion
    }
    else {
        $ModuleContentUrlFormat -f $ModuleName
    }
}

# Imports the module with given version into Azure Automation
function Import-AutomationModule([string] $ModuleName, [bool] $UseAzModule = $false) {

    $NewAutomationModule = $null
    $GetAutomationModule = $null
    if ($UseAzModule) {
        $GetAutomationModule = $script:GetAzAutomationModule
        $NewAutomationModule = $script:NewAzAutomationModule
    }
    else {
        $GetAutomationModule = $script:GetAzureRmAutomationModule
        $NewAutomationModule = $script:NewAzureRmAutomationModule
    }

    $LatestModuleVersionOnGallery = Get-ModuleDependencyAndLatestVersion $ModuleName
    if ($LatestModuleVersionOnGallery -is [Array]) { $LatestModuleVersionOnGallery = (Get-ModuleDependencyAndLatestVersion $ModuleName)[0] }

    $ModuleContentUrl = Get-ModuleContentUrl $ModuleName
    # Find the actual blob storage location of the module
    do {
        $ModuleContentUrl = (Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore).Headers.Location 
    } while (!$ModuleContentUrl.Contains(".nupkg"))

    $CurrentModule = & $GetAutomationModule `
        -Name $ModuleName `
        -ResourceGroupName $AlyaResourceGroupName `
        -AutomationAccountName $AlyaAutomationAccountName

    if ($CurrentModule.Version -eq $LatestModuleVersionOnGallery) {
        Write-Output "Module : $ModuleName is already present with version $LatestModuleVersionOnGallery. Skipping Import"
    }
    else {
        Write-Output "Importing $ModuleName module of version $LatestModuleVersionOnGallery to Automation"

        & $NewAutomationModule `
            -ResourceGroupName $AlyaResourceGroupName `
            -AutomationAccountName $AlyaAutomationAccountName `
            -Name $ModuleName `
            -ContentLink $ModuleContentUrl > $null
    }
}

# Parses the dependency got from PowerShell Gallery and returns name and version
function GetModuleNameAndVersionFromPowershellGalleryDependencyFormat([string] $Dependency) {
    if ($null -eq $Dependency) {
        throw "Improper dependency format"
    }

    $Tokens = $Dependency -split ":"
    if ($Tokens.Count -ne 3) {
        throw "Improper dependency format"
    }

    $ModuleName = $Tokens[0]
    $ModuleVersion = $Tokens[1].Trim("[", "]")

    @($ModuleName, $ModuleVersion)
}

# Validates if the given list of modules has already been added to the module import map
function AreAllModulesAdded([string[]] $ModuleListToAdd) {
    $Result = $true

    foreach ($ModuleToAdd in $ModuleListToAdd) {
        $ModuleAccounted = $false

        # $ModuleToAdd is specified in the following format:
        #       ModuleName:ModuleVersionSpecification:
        # where ModuleVersionSpecification follows the specifiation
        # at https://docs.microsoft.com/en-us/nuget/reference/package-versioning#version-ranges-and-wildcards
        # For example:
        #       AzureRm.profile:[4.0.0]:
        # or
        #       AzureRm.profile:3.0.0:
        # In any case, the dependency version specification is always separated from the module name with
        # the ':' character. The explicit intent of this runbook is to always install the latest module versions,
        # so we want to completely ignore version specifications here.
        $ModuleNameToAdd = $ModuleToAdd -replace '\:.*', ''
            
        foreach ($AlreadyIncludedModules in $ModuleImportMapOrder) {
            if ($AlreadyIncludedModules -contains $ModuleNameToAdd) {
                $ModuleAccounted = $true
                break
            }
        }

        #Write-Warning "ToAdd $ModuleNameToAdd $ModuleAccounted"
        
        if (!$ModuleAccounted) {
            $Result = $false
            break
        }
    }

    $Result
}

# Creates a module import map. This is a 2D array of strings so that the first
# element in the array consist of modules with no dependencies.
# The second element only depends on the modules in the first element, the
# third element only dependes on modules in the first and second and so on. 
function Create-ModuleImportMapOrder([bool] $AzModuleOnly) {
    $ModuleImportMapOrder = $null
    $ProfileOrAccountsModuleName = $null
    $GetAutomationModule = $null

    # Use the relevant module class to avoid conflicts
    if ($AzModuleOnly) {
        $ProfileOrAccountsModuleName = $script:AzAccountsModuleName
        $GetAutomationModule = $script:GetAzAutomationModule
    }
    else {
        $ProfileOrAccountsModuleName = $script:AzureRmProfileModuleName
        $GetAutomationModule = $script:GetAzureRmAutomationModule
    }

    # Get all the non-conflicting modules in the current automation account
    #Write-Warning "$GetAutomationModule"
    $CurrentAutomationModuleList = & $GetAutomationModule `
        -ResourceGroupName $AlyaResourceGroupName `
        -AutomationAccountName $AlyaAutomationAccountName |
    ? {
        ($AzModuleOnly -and ($_.Name -eq 'Az' -or $_.Name -like 'Az.*')) -or
        (!$AzModuleOnly -and ($_.Name -eq 'AzureRM' -or $_.Name -like 'AzureRM.*' -or
            $_.Name -eq 'Azure' -or $_.Name -like 'Azure.*'))
    }
    $CurrentAutomationModuleList = $CurrentAutomationModuleList.Name

    # Get the latest version of the AzureRM.Profile OR Az.Accounts module
    #Write-Warning "ProfileOrAccountsModuleName: $($ProfileOrAccountsModuleName)"
    $VersionAndDependencies = Get-ModuleDependencyAndLatestVersion $ProfileOrAccountsModuleName
    #Write-Warning "VersionAndDependencies start: $($VersionAndDependencies[1])"

    $ModuleEntry = $ProfileOrAccountsModuleName
    $ModuleEntryArray = , $ModuleEntry
    $ModuleImportMapOrder += , $ModuleEntryArray
    #Write-Warning "ModuleEntry $($ModuleEntry)"
    #Write-Warning "ModuleEntryArray $($ModuleEntryArray)"
    #Write-Warning "ModuleImportMapOrder $($ModuleImportMapOrder)"

    $WorkingAutomationModuleList = $CurrentAutomationModuleList

    do {
        Write-Warning "WorkingAutomationModuleList $($WorkingAutomationModuleList.Count)"
        $NextAutomationModuleList = $null
        $CurrentChainVersion = $null
        # Add it to the list if the modules are not available in the same list 
        foreach ($Name in $WorkingAutomationModuleList) {
            #$Name = $Module.Name
            if (-Not $Name -or $Name.Length -eq 0) { continue }

            Write-Warning "Checking dependencies for $Name"
            $VersionAndDependencies = Get-ModuleDependencyAndLatestVersion $Name
            if ($null -eq $VersionAndDependencies) {
                continue
            }

            $Dependencies = $VersionAndDependencies[1].Split("|")
            #Write-Warning "VersionAndDependencies: $($VersionAndDependencies[1])"

            #Write-Warning "Checking $($Dependencies.Count) dependendencies"
            foreach ($Dependency in $Dependencies) {
                if ($Dependency.IndexOf(":") -gt -1) {
                    $Modulename = $Dependency.Substring(0, $Dependency.IndexOf(":"))
                }
                else {
                    $Modulename = $Dependency
                }
                #Write-Warning "  Checking Modulename $Modulename"
                $moduleExists = $CurrentAutomationModuleList -contains $Modulename
                if (-Not $moduleExists) {
                    Write-Warning "Found new module in dependencies: $Dependency"
                    $NextAutomationModuleList += , $Modulename
                    $CurrentAutomationModuleList += , $Modulename
                }
            }

            $allDependenciesAdded = AreAllModulesAdded $Dependencies
            $allEntriesAdded = AreAllModulesAdded $Name
            #Write-Warning "allDependenciesAdded $allDependenciesAdded"
            #Write-Warning "allEntriesAdded $allEntriesAdded"

            # If the previous list contains all the dependencies then add it to current list
            if ((-not $Dependencies) -or ($allDependenciesAdded)) {
                Write-Warning "Adding module $Name to dependency chain"
                $CurrentChainVersion += , $Name
            }
            else {
                # else add it back to the main loop variable list if not already added
                if (!$allEntriesAdded) {
                    Write-Warning "Module $Name does not have all dependencies added yet. Moving module for later import"
                    #$NextAutomationModuleList += ,$Module
                    $NextAutomationModuleList += , $Name
                }
            }
        }

        #Write-Warning "NextAutomationModuleList $NextAutomationModuleList"
        #Write-Warning "CurrentChainVersion $CurrentChainVersion"

        $ModuleImportMapOrder += , $CurrentChainVersion
        #Write-Warning "ModuleImportMapOrder $ModuleImportMapOrder"
        $WorkingAutomationModuleList = $NextAutomationModuleList

    } while ($null -ne $WorkingAutomationModuleList)

    $ModuleImportMapOrder
}

# Wait and confirm that all the modules in the list have been imported successfully in Azure Automation
function Wait-AllModulesImported(
    [Collections.Generic.List[string]] $ModuleList,
    [int] $Count,
    [bool] $UseAzModule = $false) {

    $GetAutomationModule = if ($UseAzModule) {
        $script:GetAzAutomationModule
    }
    else {
        $script:GetAzureRmAutomationModule
    }

    $i = $Count - $SimultaneousModuleImportJobCount
    if ($i -lt 0) { $i = 0 }

    for ( ; $i -lt $Count; $i++) {
        $Module = $ModuleList[$i]

        Write-Output ("Checking import Status for module : {0}" -f $Module)
        $maxRetries = 10
        while ($true) {
            $AutomationModule = & $GetAutomationModule `
                -Name $Module `
                -ResourceGroupName $AlyaResourceGroupName `
                -AutomationAccountName $AlyaAutomationAccountName

            Write-Output ("ProvisioningState: $($AutomationModule.ProvisioningState)")
            $IsTerminalProvisioningState = ($AutomationModule.ProvisioningState -eq "Succeeded") -or
            ($AutomationModule.ProvisioningState -eq "Failed")

            if ($IsTerminalProvisioningState) {
                break
            }

            Write-Verbose ("Module {0} is getting imported" -f $Module)
            Start-Sleep -Seconds 30
            $maxRetries--
            if ($maxRetries -lt 0) {
                Write-Error "Was not able to install module within 300 seconds. Breaking now." -ErrorAction Continue
                break
            }
        }

        if ($AutomationModule.ProvisioningState -ne "Succeeded") {
            Write-Error ("Failed to import module : {0}. Status : {1}" -f $Module, $AutomationModule.ProvisioningState)                
        }
        else {
            Write-Output ("Successfully imported module : {0}" -f $Module)
        }
    }               
}

# Uses the module import map created to import modules. 
# It will only import modules from an element in the array if all the modules
# from the previous element have been added.
function Import-ModulesInAutomationAccordingToDependency([string[][]] $ModuleImportMapOrder, [bool] $UseAzModule) {

    foreach ($ModuleList in $ModuleImportMapOrder) {
        $i = 0
        Write-Output "Importing Array of modules : $ModuleList"
        foreach ($Module in $ModuleList) {
            Write-Verbose ("Importing module : {0}" -f $Module)
            Import-AutomationModule -ModuleName $Module -UseAzModule $UseAzModule
            $i++
            if ($i % $SimultaneousModuleImportJobCount -eq 0) {
                # It takes some time for the modules to start getting imported.
                # Sleep for sometime before making a query to see the status
                Start-Sleep -Seconds 20
                Wait-AllModulesImported -ModuleList $ModuleList -Count $i -UseAzModule $UseAzModule
            }
        }

        if ($i -lt $SimultaneousModuleImportJobCount) {
            Start-Sleep -Seconds 20
            Wait-AllModulesImported -ModuleList $ModuleList -Count $i -UseAzModule $UseAzModule
        }
    }
}

function Update-ProfileAndAutomationVersionToLatest([string] $AutomationModuleName) {

    # Get the latest azure automation module version 
    $VersionAndDependencies = Get-ModuleDependencyAndLatestVersion $AutomationModuleName

    # Automation only has dependency on profile
    $ModuleDependencies = GetModuleNameAndVersionFromPowershellGalleryDependencyFormat $VersionAndDependencies[1]
    $ProfileModuleName = $ModuleDependencies[0]

    # Create web client object for downloading data
    $WebClient = New-Object System.Net.WebClient

    # Download AzureRM.Profile to temp location
    $ModuleContentUrl = Get-ModuleContentUrl $ProfileModuleName
    $ProfileURL = (Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore).Headers.Location
    $ProfilePath = Join-Path $env:TEMP ($ProfileModuleName + ".zip")
    $WebClient.DownloadFile($ProfileURL, $ProfilePath)

    # Download AzureRM.Automation to temp location
    $ModuleContentUrl = Get-ModuleContentUrl $AutomationModuleName
    $AutomationURL = (Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore).Headers.Location
    $AutomationPath = Join-Path $env:TEMP ($AutomationModuleName + ".zip")
    $WebClient.DownloadFile($AutomationURL, $AutomationPath)

    # Create folder for unzipping the Module files
    $PathFolderName = New-Guid
    $PathFolder = Join-Path $env:TEMP $PathFolderName

    # Unzip files
    $ProfileUnzipPath = Join-Path $PathFolder $ProfileModuleName
    $cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
    if ($cmdTst) {
        Expand-Archive -Path $ProfilePath -DestinationPath $ProfileUnzipPath -Force #AlyaAutofixed
    }
    else {
        Expand-Archive -Path $ProfilePath -OutputPath $ProfileUnzipPath -Force #AlyaAutofixed
    }
    $AutomationUnzipPath = Join-Path $PathFolder $AutomationModuleName
    $cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
    if ($cmdTst) {
        Expand-Archive -Path $AutomationPath -DestinationPath $AutomationUnzipPath -Force #AlyaAutofixed
    }
    else {
        Expand-Archive -Path $AutomationPath -OutputPath $AutomationUnzipPath -Force #AlyaAutofixed
    }

    # Import modules
    Import-Module (Join-Path $ProfileUnzipPath ($ProfileModuleName + ".psd1")) -Force -Verbose
    Import-Module (Join-Path $AutomationUnzipPath ($AutomationModuleName + ".psd1")) -Force -Verbose
}

#endregion

#region Main body

if ($ModuleVersionOverrides) {
    $ModuleVersionOverridesHashTable = ConvertJsonDictTo-HashTable $ModuleVersionOverrides
}
else {
    $ModuleVersionOverridesHashTable = @{}
}


$UseAzModule = $null
$AutomationModuleName = $null

# We want to support updating Az modules. This means this runbook should support upgrading using only Az modules
if ($AzureModuleClass -eq "Az") {
    $UseAzModule = $true
    $AutomationModuleName = $script:AzAutomationModuleName
}
elseif ( $AzureModuleClass -eq "AzureRM") {
    $UseAzModule = $false
    $AutomationModuleName = $script:AzureRMAutomationModuleName
}
else {
    Write-Error "Invalid AzureModuleClass: '$AzureModuleClass'. Must be either Az or AzureRM" -ErrorAction Stop
}

# Import the latest version of the Az automation and accounts version to the local sandbox
Write-Output "Update-ProfileAndAutomationVersionToLatest"
try {
    Update-ProfileAndAutomationVersionToLatest $AutomationModuleName
}
catch {
    Write-Warning $_.Exception
}
if ($Login) {
    Login-AzureAutomation $UseAzModule
}

Write-Output "Create-ModuleImportMapOrder"
$ModuleImportMapOrder = Create-ModuleImportMapOrder $UseAzModule
Write-Output "Import-ModulesInAutomationAccordingToDependency"
Import-ModulesInAutomationAccordingToDependency $ModuleImportMapOrder $UseAzModule

Write-Output "Done"

#endregion

# SIG # Begin signature block
# MIIwlQYJKoZIhvcNAQcCoIIwhjCCMIICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDxnTRI0nhtTpzH
# PiaUqg8FaAuD1yVqL0FF83Kt3pp60aCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGDvU89YJO2uaHt6
# RN9sJFI7PvGwGKMlrhqHLr+cP+kjMA0GCSqGSIb3DQEBAQUABIICAFAEcVNPydEr
# OjiP/gv5u7RfYW4qr1upNrt5SfoknX4QTVR2LMH1lOh9BoMHWr30Y0UifNlRGp76
# SAK33VOwsFkwSoktkszsq/lEsJMoeusnzGqN4S1PJw/KthIkRJ+2ymiy1XOJd7fJ
# CbaA4J7kWr9yq1eXJ2uBxCF3UdPAyF6gbJ/G69/LHbj4UqjU2dsWI/ocTrO8IcWI
# oPc8wAuSEYsg+M+XqqSdwq8DnEL/LmMNNeS6TsD1n0BQ6fCV0/Mfixr6RQGwMVo4
# LMJv8bQq6h4ys9UiN0iD88NiFromsN/lU/hR8dti084t+2lMis71Zg2e9IYs91aD
# 30DWKm+nAbE2tG7NPVa3OP+/GAG9b5vxLn7xAv0aPs5SY/Grjc65qxYu3pMrTio8
# aBywHkMe0rIVv5BLgbRkQr8n4qCkMkV3wiZLVX1FibSGYbUj7pXEvqpmtCd9H9wg
# K12OH/p1dmVq/r7xH0q7VmhK82ZpyXSxcky54YogDDZDJse81y1HGbobXLLW/3bZ
# N3XKtgWqwJ34OtvugBI9s9+6LN+jQdge3RvWu3agpZKayNc+zl2biVkrcZj73TjI
# fFRlXt5Go4NmqOHB8xfKeuGxoSdtJsKJYes4+JDUyluQ59MA03GA/c/s1aa148Xy
# enB73Js8OkUqNr6vZYcOgAUTqDyr7HxzoYId7TCCHekGCisGAQQBgjcDAwExgh3Z
# MIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIwgeQGCyqG
# SIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCGSAFlAwQC
# AQUABCDenIRqHvR0vFkiBKJgdy1BsGn+OtnluuK6IJVlMfAEkAIUANUBd5ye7OmO
# OJdqjFd6PFMaZOcYDzIwMjYwNTEyMDk1NTUxWjADAgEBoF2kWzBZMQswCQYDVQQG
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
# MBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJBDEyBDCz
# +vnSXat/CDLqT3xumlnocd75/dn9VtwS6ijNzrSwjYD9JM0tqM/BtqkAfg+4Lgsw
# gbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS858bMJhdk
# iChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xv
# YmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5lIFI0NSBU
# aW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcN
# AQEMBQAEggGAnlr+67ujtyIdjfmu7Qwip4VLEulOHshVE/6W/Xf0kux8SbNxPtSz
# vojVhqVmfShunDAde0m2BsJ1O4PxR8lqeOjnmWTUZ7sZZed+AXlYPlWem7nRkk/Z
# 6tkk6SCLebTXFiqaD9XrD4MO7dS+vMGz1LzTpo1dDx+EwVrg3kirQa5ixEbsUWrW
# DFbUjB70k2DcVmVm2a8092475qLa9BfA+FL+riS49ysfOhMnaBf5bqHAcEWGCd9H
# UMeqG9PTP38VCxSYT8Xf+NsITNFhm2VxA6UvEs6AaEtVU5PQKUbVW0HZ294YmMfH
# MlOYd0xRiVng/qD1UkJXWdl+fU3vYD3sRf2eLJcbqLW7wotnB2g44wR2qMrU6kPk
# GjPDZPrZPMwN3VtOyPqMuOALmAAXEqoDUQhqAxjwTMTUczN/J7uronsCMT2sJVfa
# p0YdNkL/pJHGjlY8phQpRO9jM+5sdrcEZ1ibrNKXoTGqdn/e2+OMWrCZrYyAblY0
# dYxeQt65jsnh
# SIG # End signature block
