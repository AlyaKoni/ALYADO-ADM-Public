#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2022

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
    30.06.2022 Konrad Brunner       Initial Version

#>
[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\data\security\Onboard-SubscriptionsToDefender-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$StorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdAuditStorage)"
$LogAnaWrkspcName = "$($AlyaNamingPrefix)loga$($AlyaResIdLogAnalytics)"
$DefenderOnboardedServices = @("KeyVaults", "Dns", "Arm")
$DefenderOnboardedPolicies = @(
    @{Name="CIS Benchmark v1.3.0"; Policy="CIS Microsoft Azure Foundations Benchmark v1.3.0"},
    @{Name="Azure Security Benchmark"; Policy="Azure Security Benchmark"}
    #"ISO 27001:2013",
    #"Enable Azure Monitor for VMs"
)

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Storage"
Install-ModuleIfNotInstalled "Az.OperationalInsights"
Install-ModuleIfNotInstalled "Az.Security"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Defender | Onboard-SubscriptionsToDefender | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking ressource group
Write-Host "Checking ressource group $ResourceGroupName" -ForegroundColor $CommandInfo
$ResGrpParent = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrpParent)
{
    throw "Does not exist. Please create it first with Set-AzureAadAuditLogging.ps1"
}

# Checking storage account
Write-Host "Checking storage account $StorageAccountName" -ForegroundColor $CommandInfo
$StrgAccountParent = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-Not $StrgAccountParent)
{
    throw "Does not exist. Please create it first with Set-AzureAadAuditLogging.ps1"
}

# Checking log analytics workspace
Write-Host "Checking log analytics workspace $LogAnaWrkspcName" -ForegroundColor $CommandInfo
$LogAnaWrkspcParent = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $LogAnaWrkspcName -ErrorAction SilentlyContinue
if (-Not $LogAnaWrkspcParent)
{
    throw "Does not exist. Please create it first with Set-AzureAadAuditLogging.ps1"
}

# Setting auditing on subscriptions
foreach ($AlyaSubscriptionName in ($AlyaAllSubscriptions | Select-Object -Unique))
{
    Write-Host "Onboarding defender on subscription $AlyaSubscriptionName" -ForegroundColor $MenuColor

    # Switching to subscription
    $sub = Get-AzSubscription -SubscriptionName $AlyaSubscriptionName
    $null = Set-AzContext -Subscription $sub.Id
    $Context = Get-AzContext
    
    # Checking resource provider registration
    Write-Host "  Checking resource provider registration Microsoft.Security" -ForegroundColor $CommandInfo
    $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Security" -Location $AlyaLocation
    if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
    {
        Write-Warning "    Resource provider Microsoft.Security not registered. Registering now resource provider Microsoft.Security"
        Register-AzResourceProvider -ProviderNamespace "Microsoft.Security" | Out-Null
        do
        {
            Start-Sleep -Seconds 5
            $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Security" -Location $AlyaLocation
        } while ($resProv[0].RegistrationState -ne "Registered")
    }

    # Checking resource provider registration
    Write-Host "  Checking resource provider registration Microsoft.PolicyInsights" -ForegroundColor $CommandInfo
    $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.PolicyInsights" -Location $AlyaLocation
    if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
    {
        Write-Warning "    Resource provider Microsoft.PolicyInsights not registered. Registering now resource provider Microsoft.PolicyInsights"
        Register-AzResourceProvider -ProviderNamespace "Microsoft.PolicyInsights" | Out-Null
        do
        {
            Start-Sleep -Seconds 5
            $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.PolicyInsights" -Location $AlyaLocation
        } while ($resProv[0].RegistrationState -ne "Registered")
    }

    # Checking resource provider registration
    Write-Host "  Checking resource provider registration Microsoft.OperationsManagement" -ForegroundColor $CommandInfo
    $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.OperationsManagement" -Location $AlyaLocation
    if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
    {
        Write-Warning "    Resource provider Microsoft.OperationsManagement not registered. Registering now resource provider Microsoft.OperationsManagement"
        Register-AzResourceProvider -ProviderNamespace "Microsoft.OperationsManagement" | Out-Null
        do
        {
            Start-Sleep -Seconds 5
            $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.OperationsManagement" -Location $AlyaLocation
        } while ($resProv[0].RegistrationState -ne "Registered")
    }

    # Checking resource provider registration
    Write-Host "  Checking resource provider registration Microsoft.Insights" -ForegroundColor $CommandInfo
    $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Insights" -Location $AlyaLocation
    if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
    {
        Write-Warning "    Resource provider Microsoft.Insights not registered. Registering now resource provider Microsoft.Insights"
        Register-AzResourceProvider -ProviderNamespace "Microsoft.Insights" | Out-Null
        do
        {
            Start-Sleep -Seconds 5
            $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Insights" -Location $AlyaLocation
        } while ($resProv[0].RegistrationState -ne "Registered")
    }

    # Checking pricing tiers
    Write-Host "  Checking pricing tiers" -ForegroundColor $CommandInfo
    #(Get-AzSecurityPricing).name
    foreach($enabledService in $DefenderOnboardedServices)
    {
        $pricing = Get-AzSecurityPricing -Name $enabledService
        if ($pricing.PricingTier -eq "Free")
        {
            Write-Warning "Changed pricing tier of service '$enabledService' to 'Standard'"
            Set-AzSecurityPricing -Name $enabledService -PricingTier "Standard"
        }
    }

    # Registering workspace
    Write-Host "  Registering workspace" -ForegroundColor $CommandInfo
    Set-AzSecurityWorkspaceSetting -Name "default" -Scope "/subscriptions/$($sub.Id)" -WorkspaceId $LogAnaWrkspcParent.ResourceId

    # Configuring Continuous  export settings
    #TODO

    # Configuring data integration settings
    Set-AzSecuritySetting -SettingName "MCAS" -SettingKind "DataExportSettings" -Enabled $true
    Set-AzSecuritySetting -SettingName "WDATP" -SettingKind "DataExportSettings" -Enabled $true

    # Setting securit contact
    Write-Host "  Setting securit contact to $AlyaSecurityEmail" -ForegroundColor $CommandInfo
    Set-AzSecurityContact -Name "default" -Email $AlyaSecurityEmail -AlertAdmin -NotifyOnAlert

    # Registering policies
    Write-Host "  Registering policies" -ForegroundColor $CommandInfo
    #(Get-AzPolicySetDefinition).Properties.displayName | Where-Object { $_ -notlike "*Deprecated*" }
    foreach($enabledPolicy in $DefenderOnboardedPolicies)
    {
        #$enabledPolicy = $DefenderOnboardedPolicies[0]
        $Policy = Get-AzPolicySetDefinition | Where-Object {$_.Properties.displayName -eq $enabledPolicy.Policy}
        $assignmentName = "DFC '$($enabledPolicy.Name)' on '$($AlyaSubscriptionName)'"
        $assignmentDisplayName = "DFC '$($enabledPolicy.Name)' on '$($AlyaSubscriptionName)' <$($sub.Id)>"
        $assignmentName = $assignmentName.Replace("%", "-").Replace("&", "-").Replace("\", "-").Replace("?", "-").Replace("/", "-").Replace(":", "-").Replace("<", "-").Replace(">", "-").Replace(" ", "-")
        $pa = Get-AzPolicyAssignment -Name $assignmentName -Scope "/subscriptions/$($sub.Id)" -PolicyDefinitionId $Policy.PolicySetDefinitionId -ErrorAction SilentlyContinue
        if (-Not $pa)
        {
            Write-Warning "    Enabling '$($enabledPolicy.Policy)' policy"
            $null = New-AzPolicyAssignment -Name $assignmentName -DisplayName $assignmentDisplayName -PolicySetDefinition $Policy -Scope "/subscriptions/$($sub.Id)"
        }
    }
}

#Stopping Transscript
Stop-Transcript
