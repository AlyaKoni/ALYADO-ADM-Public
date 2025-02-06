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
    try{
        $JsonObj = ConvertFrom-Json $JsonString -ErrorAction Stop
    } catch [System.ArgumentException] {
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
        try
        {
            $AzureContext = (Connect-AzAccount -Identity -Environment $AlyaAzureEnvironment).Context
        }
        catch
        {
            throw "There is no system-assigned user identity. Aborting."; 
            exit 99
        }
        $AzureContext = Set-AzContext -Subscription $AlyaSubscriptionId -DefaultProfile $AzureContext
    } catch {
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
        } else {
            $ModuleUrlFormat -f $ModuleName, 'IsLatestVersion'
        }

    Write-Warning $CurrentModuleUrl
    $retries = 10
    while ($true)
    {
        try {
            $SearchResult = Invoke-RestMethod -Method Get -Uri $CurrentModuleUrl -UseBasicParsing
            break
        }
        catch {
            $retries--
            if ($retries -lt 0)
            {
                throw $_
            }
            Write-Warning "Retrying"
            Start-Sleep -Seconds ((10-$retries)*4)
        }
    }
    
    if (!$SearchResult) {
        Write-Verbose "Could not find module $ModuleName on PowerShell Gallery. This may be a module you imported from a different location. Ignoring this module"
    } else {
        if ($SearchResult.Length -and $SearchResult.Length -gt 1) {
            $SearchResult = $SearchResult | Where-Object { $_.title.InnerText -eq $ModuleName }
        }

        if (!$SearchResult) {
            Write-Verbose "Could not find module $ModuleName on PowerShell Gallery. This may be a module you imported from a different location. Ignoring this module"
        } else {
            Write-Warning $SearchResult.id
            $retries = 10
            while ($true)
            {
                try {
                    $PackageDetails = Invoke-RestMethod -Method Get -UseBasicParsing -Uri $SearchResult.id
                    break
                }
                catch {
                    $retries--
                    if ($retries -lt 0)
                    {
                        throw $_
                    }
                    Write-Warning "Retrying"
                    Start-Sleep -Seconds ((10-$retries)*4)
                }
            }

            # Ignore the modules that are not published as part of the Azure SDK
            if ($PackageDetails.entry.properties.Owners -ne $script:AzureSdkOwnerName) {
                Write-Warning "Module : $ModuleName is not part of azure sdk. Ignoring this."
            } else {
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
    } else {
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
    } else {
        $GetAutomationModule = $script:GetAzureRmAutomationModule
        $NewAutomationModule = $script:NewAzureRmAutomationModule
    }

	$LatestModuleVersionOnGallery = Get-ModuleDependencyAndLatestVersion $ModuleName
    if ($LatestModuleVersionOnGallery -is [Array]) ( $LatestModuleVersionOnGallery = (Get-ModuleDependencyAndLatestVersion $ModuleName)[0] )

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
    } else {
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

    $Tokens = $Dependency -split":"
    if ($Tokens.Count -ne 3) {
        throw "Improper dependency format"
    }

    $ModuleName = $Tokens[0]
    $ModuleVersion = $Tokens[1].Trim("[","]")

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
            
        foreach($AlreadyIncludedModules in $ModuleImportMapOrder) {
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
    } else {
        $ProfileOrAccountsModuleName = $script:AzureRmProfileModuleName
        $GetAutomationModule = $script:GetAzureRmAutomationModule
    }

    # Get all the non-conflicting modules in the current automation account
	#Write-Warning "$GetAutomationModule"
    $CurrentAutomationModuleList = & $GetAutomationModule `
                                        -ResourceGroupName $AlyaResourceGroupName `
                                        -AutomationAccountName $AlyaAutomationAccountName |
        ?{
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
    $ModuleEntryArray = ,$ModuleEntry
    $ModuleImportMapOrder += ,$ModuleEntryArray
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
			foreach($Dependency in $Dependencies)
			{
                if ($Dependency.IndexOf(":") -gt -1) {
				    $Modulename = $Dependency.Substring(0, $Dependency.IndexOf(":"))
                } else {
				    $Modulename = $Dependency
                }
	        	#Write-Warning "  Checking Modulename $Modulename"
				$moduleExists = $CurrentAutomationModuleList -contains $Modulename
				if (-Not $moduleExists)
				{
					Write-Warning "Found new module in dependencies: $Dependency"
					$NextAutomationModuleList += ,$Modulename
					$CurrentAutomationModuleList += ,$Modulename
				}
			}

			$allDependenciesAdded = AreAllModulesAdded $Dependencies
			$allEntriesAdded = AreAllModulesAdded $Name
        	#Write-Warning "allDependenciesAdded $allDependenciesAdded"
        	#Write-Warning "allEntriesAdded $allEntriesAdded"

            # If the previous list contains all the dependencies then add it to current list
            if ((-not $Dependencies) -or ($allDependenciesAdded)) {
                Write-Warning "Adding module $Name to dependency chain"
                $CurrentChainVersion += ,$Name
            } else {
                # else add it back to the main loop variable list if not already added
                if (!$allEntriesAdded) {
                    Write-Warning "Module $Name does not have all dependencies added yet. Moving module for later import"
                    #$NextAutomationModuleList += ,$Module
                    $NextAutomationModuleList += ,$Name
                }
            }
        }

    	#Write-Warning "NextAutomationModuleList $NextAutomationModuleList"
    	#Write-Warning "CurrentChainVersion $CurrentChainVersion"

        $ModuleImportMapOrder += ,$CurrentChainVersion
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
    } else {
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
            if ($maxRetries -lt 0)
            {
                Write-Error "Was not able to install module within 300 seconds. Breaking now." -ErrorAction Continue
                break
            }
        }

        if ($AutomationModule.ProvisioningState -ne "Succeeded") {
            Write-Error ("Failed to import module : {0}. Status : {1}" -f $Module, $AutomationModule.ProvisioningState)                
        } else {
            Write-Output ("Successfully imported module : {0}" -f $Module)
        }
    }               
}

# Uses the module import map created to import modules. 
# It will only import modules from an element in the array if all the modules
# from the previous element have been added.
function Import-ModulesInAutomationAccordingToDependency([string[][]] $ModuleImportMapOrder, [bool] $UseAzModule) {

    foreach($ModuleList in $ModuleImportMapOrder) {
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
    if ($cmdTst)
    {
        Expand-Archive -Path $ProfilePath -DestinationPath $ProfileUnzipPath -Force #AlyaAutofixed
    }
    else
    {
        Expand-Archive -Path $ProfilePath -OutputPath $ProfileUnzipPath -Force #AlyaAutofixed
    }
    $AutomationUnzipPath = Join-Path $PathFolder $AutomationModuleName
    $cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
    if ($cmdTst)
    {
        Expand-Archive -Path $AutomationPath -DestinationPath $AutomationUnzipPath -Force #AlyaAutofixed
    }
    else
    {
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
} else {
    $ModuleVersionOverridesHashTable = @{}
}


$UseAzModule = $null
$AutomationModuleName = $null

# We want to support updating Az modules. This means this runbook should support upgrading using only Az modules
if ($AzureModuleClass -eq "Az") {
    $UseAzModule = $true
    $AutomationModuleName = $script:AzAutomationModuleName
} elseif ( $AzureModuleClass -eq "AzureRM") {
    $UseAzModule = $false
    $AutomationModuleName = $script:AzureRMAutomationModuleName
} else {
     Write-Error "Invalid AzureModuleClass: '$AzureModuleClass'. Must be either Az or AzureRM" -ErrorAction Stop
}

# Import the latest version of the Az automation and accounts version to the local sandbox
Write-Output "Update-ProfileAndAutomationVersionToLatest"
try
{
	Update-ProfileAndAutomationVersionToLatest $AutomationModuleName
}
catch
{
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
# MIIvGwYJKoZIhvcNAQcCoIIvDDCCLwgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDHjZjrODQkI3nN
# s93bRP6PCFfNcct36OHBMbktNERb+6CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxghnmMIIZ4gIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAphBpjN
# lXFzNzRkKa1tfo28G2mBeLzZQUVlt+gBLCDvMA0GCSqGSIb3DQEBAQUABIICAGN9
# GgRG7enOxRn9L1M8ZVG91Zxl6kaVkkhhUl5hlsOD7nwA1D7Y5HEQ/HxHSuWdD8OC
# K59/JRCk6BrRuWA/fbpbyM6AywjpoP8pUKv9VCtOcDGZauDmfbhbFb2d+9Y5xFmQ
# pq13gJ3RbMW6tNkBmcvhtV+97QudlrDGdZRtXLjpD5LlMxZCLyDQFj6ECnvCZ2Mz
# rgsnE2RxDJU7fUgD6F36BU49tmCQe26eIPaNIj/UD32XfQzOIGBHGjE+/MF1wGji
# a5x7ExPiaY3DAburMwJV8K6ij8a5RheExfbFnLwr6Out52HJqQL/nz6/g1Z4x0z8
# 0jn/Y0smMKFK9Y0eW32vkq+qt/AOz/7pwYha0cLC51mDS5lyfFcebaMYMIcZqAWI
# zGAEqGJDmzIj1IaEwFmIMcyVj8wIgdt3Qc/AyeHoHKUJ/PABz4hFqW43aKcnnaXO
# BaagW0RhM9oRbrjGspoJTl2+rcXw45hu+HesdUhJY3iJo1YejQhTMVanE481xTMT
# Wa62okzZHWDc+1zSvUvFph81krg8UYSX9bXoWntDjX1SxbIQynGrdUetvoa0p7kN
# 8pweta9FgZWeijsBS/08haOTeJrRjzumGDZ1J6Hi3wDc7VvUuG9b+8fhc9d2oPer
# sOAErnioV5tsSElnsdrpQY5YhkSBcBVrnDLe3HXDoYIWzTCCFskGCisGAQQBgjcD
# AwExgha5MIIWtQYJKoZIhvcNAQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEw
# gegGCyqGSIb3DQEJEAEEoIHYBIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCDY03/2zZU9XX+6nHbMSoI4xMugySHnie4yNXuAYPR9fwIUS+lK
# iVAtNH8LbEQz7FKikWZyYNUYDzIwMjUwMjA2MTkxMDE4WjADAgEBoGGkXzBdMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwq
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2IC0gMjAyMzExoIISVDCC
# BmwwggRUoAMCAQICEAGb6t7ITWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAwWzEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMT
# KEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjMx
# MTA3MTcxMzQwWhcNMzQxMjA5MTcxMzQwWjBdMQswCQYDVQQGEwJCRTEZMBcGA1UE
# CgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9y
# IENvZGVTaWduMSAtIFI2IC0gMjAyMzExMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
# MIIBigKCAYEA6oQ3UGg8lYW1SFRxl/OEcsmdgNMI3Fm7v8tNkGlHieUs2PGoan5g
# N0lzm7iYsxTg74yTcCC19SvXZgV1P3qEUKlSD+DW52/UHDUu4C8pJKOOdyUn4Ljz
# fWR1DJpC5cad4tiHc4vvoI2XfhagxLJGz2DGzw+BUIDdT+nkRqI0pz4Yx2u0tvu+
# 2qlWfn+cXTY9YzQhS8jSoxMaPi9RaHX5f/xwhBFlMxKzRmUohKAzwJKd7bgfiWPQ
# HnssW7AE9L1yY86wMSEBAmpysiIs7+sqOxDV8Zr0JqIs/FMBBHkjaVHTXb5zhMub
# g4htINIgzoGraiJLeZBC5oJCrwPr1NDag3rDLUjxzUWRtxFB3RfvQPwSorLAWapU
# l05tw3rdhobUOzdHOOgDPDG/TDN7Q+zw0P9lpp+YPdLGulkibBBYEcUEzOiimLAd
# M9DzlR347XG0C0HVZHmivGAuw3rJ3nA3EhY+Ao9dOBGwBIlni6UtINu41vWc9Q+8
# iL8nLMP5IKLBAgMBAAGjggGoMIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFPlOq764+Fv/wscD9EHunPjWdH0/MFYG
# A1UdIARPME0wCAYGZ4EMAQQCMEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8E
# AjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3Au
# Z2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdo
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0
# ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6
# MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNo
# YTM4NGc0LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAlfRnz5OaQ5KDF3bWIFW8if/k
# X7LlFRq3lxFALgBBvsU/JKAbRwczBEy0tGL/xu7TDMI0oJRcN5jrRPhf+CcKAr4e
# 0SQdI8svHKsnerOpxS8M5OWQ8BUkHqMVGfjvg+hPu2ieI299PQ1xcGEyfEZu8o/R
# nOhDTfqD4f/E4D7+3lffBmvzagaBaKsMfCr3j0L/wHNp2xynFk8mGVhz7ZRe5Bqi
# EIIHMjvKnr/dOXXUvItUP35QlTSfkjkkUxiDUNRbL2a0e/5bKesexQX9oz37obDz
# K3kPsUusw6PZo9wsnCsjlvZ6KrutxVe2hLZjs2CYEezG1mZvIoMcilgD9I/snE7Q
# 3+7OYSHTtZVUSTshUT2hI4WSwlvyepSEmAqPJFYiigT6tJqJSDX4b+uBhhFTwJN7
# OrTUNMxi1jVhjqZQ+4h0HtcxNSEeEb+ro2RTjlTic2ak+2Zj4TfJxGv7KzOLEcN0
# kIGDyE+Gyt1Kl9t+kFAloWHshps2UgfLPmJV7DOm5bga+t0kLgz5MokxajWV/vbR
# /xeKriMJKyGuYu737jfnsMmzFe12mrf95/7haN5EwQp04ZXIV/sU6x5a35Z1xWUZ
# 9/TVjSGvY7br9OIXRp+31wduap0r/unScU7Svk9i00nWYF9A43aZIETYSlyzXRrZ
# 4qq/TVkAF55gZzpHEqAwggZZMIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqG
# SIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMw
# EQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYy
# MDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDwAuIwI/rgG+GadLOvdYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64H
# iifuV6PENe2zNMeswwzrgGZt0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//
# NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe
# 9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirU
# IceU/kKWO/ELsX9/RpgOhz16ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0Kvq
# WsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50
# xHAotIB7vSqbu4ThDqxvDbm19m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU
# 2EESwVX9bpHFu7FMCEue1EIGbxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE
# 6giunUlnEYuC5a1ahqdm/TMDAd6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3s
# qSbldwKsDlcMCdFhniaI/MiyTdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac
# 0zd0hNkdZqs0c48efXxeltY9GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCC
# ASUwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3Ay
# Lmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8v
# Y3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0g
# ADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBv
# c2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZM
# v9sbB3DG+wsJrQA6YDMfOcYWaxlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7A
# I4zGhf5LFST5GETsH8KkrNCyz+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG
# 0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0
# +X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3Wd
# rG9KyC5qucqIwxIwTrIIc59eodaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXa
# jR63Wy+ILj198fKRMAWcznt8oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpI
# iScseeI85Zse46qEgok+wEr1If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ
# 7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx
# 773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZq
# HcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV
# 5yBZtnjGpGqqIpswggWDMIIDa6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG
# 9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEG
# A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAw
# MDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9v
# dCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxT
# aWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns8
# 9w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0b
# WsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZ
# gQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ
# 3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2M
# sonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI5
# 5KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPF
# OJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4Py
# XhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYF
# AJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWV
# ZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlw
# g3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4IC
# AQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/A
# VJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6x
# CCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc
# 053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6q
# TFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvd
# OxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJd
# w+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ
# 4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4Z
# sRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3
# nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZ
# xRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8w
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb
# 6t7ITWuP92w6ny4BJBYwCwYJYIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZI
# hvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEIMkdjBTBysbY7DLcLRMSKHj0+zpdtddi
# 0MW8tXfudHg/MIGwBgsqhkiG9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe
# 4U9su3aCN6VF0BBb8EURveJfgqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJ
# KoZIhvcNAQELBQAEggGAYIRuXpbDhRnIwgPxVDFHAfIO1GtNvG3pQ5P9UlQvWQ+X
# R9oVm7f2HXnfWYkeFFOVTEFobk5UwcyGROJLEIbHcXBpfrqcJOvdsgu/swfy+rvS
# P7VJSplT6wC0EOdOr6sHh+n8Ul9lECjSP01wfI0KdSmpachyyJ0zJf94xeoCMPrD
# 7E1v+GQr4dW5WXeGSOMSXT8QN4D9kk+i2PBXQMSxd2LGjgxH7qbsSDF1PKCHfMbp
# 3xq5jMrTgFT4SXUDuwenXgmS8THo8PvUdvBvrHoQWRFheM/Q0h14kSWiaSleE/q1
# C0xr+ByZbklyi3bdqZeDCjK3K06XX9y92RpdzlncpIvjRrFucI9HF+LdAKqUBtrm
# hVpvTTNYIgi3YJojutIwOSlBXzzEYP4KKhAIS8QtUSPUwRuPsBFHSXSTWlmo+C7h
# EQuSc5fw/pJ21G2hZwL7/4ZSzC0JhEVeKVGLwLrB6vgOwAsHysG35YAdlr7XJ2KV
# IK/HAEkNCmdQGS/0amgK
# SIG # End signature block
