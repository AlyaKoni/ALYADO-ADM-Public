#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2023

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
    24.01.2022 Konrad Brunner       Fixed unwanted module updates

#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
param(
    [Parameter(Mandatory = $true)]
    [string] $ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string] $AutomationAccountName,

    [Parameter(Mandatory=$false)]
    [string] $AzureEnvironment = 'AzureCloud'
)
$ErrorActionPreference = "Stop"

# Constants
$RunAsConnectionName = "AzureRunAsConnection"
$ModulesToInstall = @( ##AlyaModules## ) #Version $null means latest

# Functions
Function GetModuleContentUrl
{   
param(
    [Parameter(Mandatory=$true)]
    [String] $ModuleName,

    [Parameter(Mandatory=$false)]
    [String] $ModuleVersion

)

    $Url = "https://www.powershellgallery.com/api/v2/Search()?`$filter=IsLatestVersion&searchTerm=%27$ModuleName%27&targetFramework=%27%27&includePrerelease=false&`$skip=0&`$top=40"
    $SearchResult = Invoke-RestMethod -Method Get -Uri $Url -UseBasicParsing

    if($SearchResult.Length -and $SearchResult.Length -gt 1) {
        $SearchResult = $SearchResult | Where-Object -FilterScript {
            return $_.properties.title -eq $ModuleName
        }
    }

    $PackageDetails = Invoke-RestMethod -Method Get -UseBasicParsing -Uri $SearchResult.id
    if(!$ModuleVersion) {
        $ModuleVersion = $PackageDetails.entry.properties.version
    }

    $ModuleContentUrl = "https://www.powershellgallery.com/api/v2/package/$ModuleName/$ModuleVersion"
    do {
        $ModuleContentUrl = (Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore).Headers.Location 

    } while(!$ModuleContentUrl.Contains(".nupkg"))

    $ModuleContentUrl
}

#Update profile and automation modules
function Update-ProfileAndAutomationVersionToLatest
{
    Write-Output "Importing Az.Accounts and Az.Automation modules"
    $ProfileModuleName = "Az.Accounts"
    $AutomationModuleName = "Az.Automation"
    $WebClient = New-Object System.Net.WebClient
    # Download Az.Profile to temp location
    $ProfileURL = GetModuleContentUrl $ProfileModuleName
    $ProfilePath = Join-Path $env:TEMP ($ProfileModuleName + ".zip")
    $WebClient.DownloadFile($ProfileURL, $ProfilePath)
    # Download Az.Automation to temp location
    $AutomationURL = GetModuleContentUrl $AutomationModuleName
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
try
{
	$Cmd = Get-Command -Name Get-AzAutomationModule -ErrorAction SilentlyContinue
	if (-Not $Cmd)
	{
		Update-ProfileAndAutomationVersionToLatest
	}
} catch {
	Write-Warning $_.Exception
}

# Login-AzureAutomation
try {
    $RunAsConnection = Get-AutomationConnection -Name $RunAsConnectionName
    Write-Output "Logging in to Az ($AzureEnvironment)..."
    Write-Output "  Thumbprint $($RunAsConnection.CertificateThumbprint)"
    Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null
    Add-AzAccount `
        -ServicePrincipal `
        -TenantId $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -Environment $AzureEnvironment
    Select-AzSubscription -SubscriptionId $RunAsConnection.SubscriptionID  | Write-Verbose
} catch {
    if (!$RunAsConnection) {
        Write-Output $RunAsConnectionName
        try { Write-Output ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
        Write-Output "Connection $RunAsConnectionName not found."
    }
    throw
}

# Import modules if they are not in the Automation account
try {
	foreach($ModuleToInstall in $ModulesToInstall)
	{
		$ModuleName = $ModuleToInstall.Name
		$ModuleVersion = $ModuleToInstall.Version
		Write-Output "Checking module $ModuleName $ModuleVersion ..."
		$AzureADGalleryURL = GetModuleContentUrl -ModuleName $ModuleName -ModuleVersion $ModuleVersion
		if (-Not $AzureADGalleryURL)
		{
			Write-Error "Can't find module $ModuleName" -ErrorAction Continue
		}

		$ADModule = Get-AzAutomationModule -ResourceGroupName $ResourceGroupName `
					    -AutomationAccountName $AutomationAccountName `
					    -Name $ModuleName -ErrorAction SilentlyContinue

		$toBeinstalled = $false
		if ([string]::IsNullOrEmpty($ADModule))
		{
			Write-Output "  Installing..."
			$toBeinstalled = $true
		}
        else
        {
			$AzureADGalleryURLActual = GetModuleContentUrl -ModuleName $ModuleName -ModuleVersion $ADModule.Version.ToString()
			if ($AzureADGalleryURL -ne $AzureADGalleryURLActual)
			{
				Write-Output "  Updating..."
				$toBeinstalled = $true
			}
        }

		if ($toBeinstalled)
		{
			Write-Output "    Importing $ModuleName module to Automation account"
			$AutomationModule = New-AzAutomationModule `
				-ResourceGroupName $ResourceGroupName `
				-AutomationAccountName $AutomationAccountName `
				-Name $ModuleName `
				-ContentLink $AzureADGalleryURL

			while((!([string]::IsNullOrEmpty($AutomationModule))) -and
				$AutomationModule.ProvisioningState -ne "Created" -and
				$AutomationModule.ProvisioningState -ne "Succeeded" -and
				$AutomationModule.ProvisioningState -ne "Failed")
			{
				Write-Verbose -Message "      Polling for module import completion"
				Start-Sleep -Seconds 10
				$AutomationModule = $AutomationModule | Get-AzAutomationModule
			}

			if($AutomationModule.ProvisioningState -eq "Failed") {
				throw "Importing $ModuleName module to Automation failed."
			}
		}  
	}
} catch {
    Write-Error $_.Exception -ErrorAction Continue
    throw
}
Write-Output "Done"
