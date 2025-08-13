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
# MIIvCQYJKoZIhvcNAQcCoIIu+jCCLvYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBiXp/GSW6zK3SY
# TbGSzfzhiymV1ZCpfwuixX2a6OT5FqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGdc7mlT
# 1+l5f2fMqj4Q/FERORKYZnL+Z8BMe3BJ5L25MA0GCSqGSIb3DQEBAQUABIICAHeS
# pfENlk41n0l8VuckyUpK7yAqB+BBxatMb51R6am2ls7IVtik/CRXmuuyUTeoRjla
# pdKa8hkS1fXMsnJgPzEcyZq/MRH1XlDBGpm8JM9/OdXlwMBYi3txIIIbFQVTRZv/
# BoGi27J59rxQOmX13uCy/cpMD3KwmKVXg68tDArBDVaxr2NKKFVwI3XIrlHzNyG3
# ecTUOoPXcjDLirXfwnvrjmjrEtg0YQf0q8wolt4iiajpcss/B1HTnb63JfqLJ9KF
# 52bRqBI5m3jwGrwCrCuj3AuiK295QWrUbD6hP2KCV9vMVzul4R2u0b2BoJ1VWEmg
# z2KQzKTyhPOh0kX3EWSUDW4Y9DbfaFyjkUD5X2XqYXsGnBn1t7NqgdQQMq8ggIfF
# y+6OKhg1lBxyIB4YNb0sOO1bGsNlr1bq24dVbUyz0KyNlk1pDu8R5QhpEMe/oEgX
# nVK/Uzs2VA2bcCkcYxCXi+bpTV+8KIagmSVTk0q7IKEzx/ifBQ5Jqca98LQc4ELG
# i/6+kFNTCAF9HhXQUecQG4g3who/yMClhvQ2RFMIuSlhfqI4Qy77NcL71BWlx0sM
# 1O3Yp2goNL5hGEDQYu8G9qtcQwtRJfFFP2PTPhrwdk4pqJMlCykxTaGjw6PuHXTx
# eRBcP/iUduQHteWSe387SXPYZXHwsHSzarUK3mTJoYIWuzCCFrcGCisGAQQBgjcD
# AwExghanMIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEw
# gd8GCyqGSIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCBE4+Y/i8wZV3o0NL265pyaXnRethwYpXMU35PJ5a+lYQIURFpG
# jkqb68aAAfrHdLP6KHJVKjsYDzIwMjUwNzIzMTIxMzQ2WjADAgEBoFikVjBUMQsw
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
# AQkEMSIEIL0QSbdp1iUNYp6GKyBC20/o4wqm/RZKkEPChjGDFLNkMIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1or
# d69gXP0wczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAA2xd
# oBbS7YgAJ2JW3MiZ+qDMS8c66k7RIya2xOWdx3J3HMzF2TS+n0J3596RYDFVhjrW
# 29NpMJ7Khq8nyJbMQUyDrHeoJeS87iPgkER2uuGvInQl51r/3zTV/nHYpVp9YtHt
# 5dN0cgcN7iLDODjF2PncRGAboILrJHjdESMjI97XkrSm8CcgvmW072KgiqL6OOLN
# S+DJmeWURk3l4VkUWE7ZwmNHbKgHz6wF9HJmV7VbRPe6W3caXa89ZTA1zWmYPY/e
# fIrQR/TFQab2D5iyLmV1NjafepULd3aJ3fYwJck+bgkssEwUrfLNnx5YImVwvRMz
# JcsHCkyeNx5MEHgn0HJoD+p+Be5degbj1UaKVOhVj/nTrocyvT4LdUe3QuYC5d1h
# K0xigBUrxjasCwK7ii82YiCKTfp7G5Y5P5HgJy1vxlnU2nLAmi6w1SZyO2nmo5lZ
# guhAIlVQxdedXQWBCRD+dVSvMHMS7bROlhroo/wF5mCDQ7/zfS39qMZSNdMf
# SIG # End signature block
