#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2021

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
    14.11.2019 Konrad Brunner       Initial Version

#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
param(
    [Parameter(Mandatory = $true)]
    [string] $SubscriptionName,

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
$ModulesToInstall = @( @{Name="AzureAdPreview"; Version=$null}, @{Name="Microsoft.RDInfra.RDPowershell"; Version=$null} ) #Version $null means latest

# Functions
Function ImportAutomationModule
{   
param(

    [Parameter(Mandatory=$true)]
    [String] $ResourceGroupName,

    [Parameter(Mandatory=$true)]
    [String] $AutomationAccountName,

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

        $ActualUrl = $ModuleContentUrl
        $ModuleContentUrl = (Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore).Headers.Location 

    } while(!$ModuleContentUrl.Contains(".nupkg"))

    $ActualUrl = $ModuleContentUrl

    $AutomationModule = New-AzureRmAutomationModule `
        -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $AutomationAccountName `
        -Name $ModuleName `
        -ContentLink $ActualUrl -AzureRmContext $Context

    while(

        (!([string]::IsNullOrEmpty($AutomationModule))) -and
        $AutomationModule.ProvisioningState -ne "Created" -and
        $AutomationModule.ProvisioningState -ne "Succeeded" -and
        $AutomationModule.ProvisioningState -ne "Failed"

    ){
        Write-Verbose -Message "Polling for module import completion"
        Start-Sleep -Seconds 10
        $AutomationModule = $AutomationModule | Get-AzureRmAutomationModule -AzureRmContext $Context
    }


    if($AutomationModule.ProvisioningState -eq "Failed") {

        Write-Error "     Importing $ModuleName module to Automation failed." -ErrorAction Continue

    } else {
        $ActualUrl
    }
}

# Login-AzureAutomation
try {
    $RunAsConnection = Get-AutomationConnection -Name $RunAsConnectionName
    Write-Output "Logging in to AzureRm ($AzureEnvironment)..."
    Add-AzureRmAccount `
        -ServicePrincipal `
        -TenantId $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -Environment $AzureEnvironment
    Select-AzureRmSubscription -Subscription $SubscriptionName  | Write-Verbose
    $Context = Get-AzureRmContext
} catch {
    if (!$RunAsConnection) {
        Write-Output $RunAsConnectionName
        try { Write-Output ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
        Write-Output "Connection $RunAsConnectionName not found."
    }
    throw
}

try {
	# Import modules if they are not in the Automation account
	foreach($ModuleToInstall in $ModulesToInstall)
	{
		$ModuleName = $ModuleToInstall.Name
		$ModuleVersion = $ModuleToInstall.Version
		Write-Output "Checking module $ModuleName..."
		$ADModule = Get-AzureRMAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
								-Name $ModuleName -AzureRmContext $Context -ErrorAction SilentlyContinue
		if ([string]::IsNullOrEmpty($ADModule))
		{
			Write-Output "  Installing..."
			$AzureADGalleryURL = ImportAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
								-ModuleName $ModuleName -ModuleVersion $ModuleVersion
			if (-Not $AzureADGalleryURL)
			{
				Write-Error "Can't find module $ModuleName" -ErrorAction Continue
			}
			else
			{
				New-AzureRMAutomationModule `
					-ResourceGroupName $ResourceGroupName `
					-AutomationAccountName $AutomationAccountName `
					-Name $ModuleName `
					-ContentLink $AzureADGalleryURL
			}
		}
	}
} catch {
    Write-Error $_.Exception -ErrorAction Continue
    throw
}
