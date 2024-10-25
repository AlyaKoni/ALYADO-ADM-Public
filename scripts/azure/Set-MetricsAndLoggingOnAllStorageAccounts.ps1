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
    26.09.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$AnalyticsStorageAccountResourceGroupName,
    [Parameter(Mandatory=$true)]
    [string]$AnalyticsStorageAccountName,
    [Parameter(Mandatory=$true)]
    [string]$AnalyticsWrkspcResourceGroupName,
    [Parameter(Mandatory=$true)]
    [string]$AnalyticsWrkspcName
)

# Loading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Set-MetricsAndLoggingOnAllStorageAccounts-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Storage"
Install-ModuleIfNotInstalled "Az.OperationalInsights"
Install-ModuleIfNotInstalled "Az.Monitor"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "HHAG | Set-MetricsAndLoggingOnAllStorageAccounts | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking analytics storage ressource group
Write-Host "Checking analytics storage ressource group" -ForegroundColor $CommandInfo
$ResGrpLogAna = Get-AzResourceGroup -Name $AnalyticsStorageAccountResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrpLogAna)
{
    throw "Does not exist. Please create it first with the script \scripts\azure\Create-AzureLogAnalyticsWorkspace.ps1."
}

# Checking analytics storage account
Write-Host "Checking analytics storage account" -ForegroundColor $CommandInfo
$StrgAccountLogAna = Get-AzStorageAccount -ResourceGroupName $AnalyticsStorageAccountResourceGroupName -Name $AnalyticsStorageAccountName -ErrorAction SilentlyContinue
if (-Not $StrgAccountLogAna)
{
    throw "Does not exist. Please create it first with the script \scripts\azure\Create-AzureLogAnalyticsWorkspace.ps1."
}

# Checking analytics workspace ressource group
Write-Host "Checking analytics workspace ressource group" -ForegroundColor $CommandInfo
$ResGrpLogAna = Get-AzResourceGroup -Name $AnalyticsWrkspcResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrpLogAna)
{
    throw "Does not exist. Please create it first with the script \scripts\azure\Create-AzureLogAnalyticsWorkspace.ps1."
}

# Checking log analytics workspace
Write-Host "Checking log analytics workspace $AnalyticsWrkspcResourceGroupName" -ForegroundColor $CommandInfo
$WrkspcLogAna = Get-AzOperationalInsightsWorkspace -ResourceGroupName $AnalyticsResourceGroupName -Name $AnalyticsWrkspcName -ErrorAction SilentlyContinue
if (-Not $WrkspcLogAna)
{
    throw "Does not exist. Please create it first with the script \scripts\azure\Create-AzureLogAnalyticsWorkspace.ps1."
}

# Checking subscriptions
foreach ($AlyaSubscriptionName in ($AlyaAllSubscriptions | Select-Object -Unique))
{
    Write-Host "Checking subscription $AlyaSubscriptionName" -ForegroundColor $MenuColor
  
    # Switching to subscription
    $sub = Get-AzSubscription -SubscriptionName $AlyaSubscriptionName
    $null = Set-AzContext -Subscription $sub.Id
    $Context = Get-AzContext

    # Checking resource provider registration
    Write-Host "Checking resource provider registration Microsoft.Insights" -ForegroundColor $CommandInfo
    $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Insights" -Location $AlyaLocation
    if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
    {
        Write-Warning "  Resource provider Microsoft.Insights not registered. Registering now resource provider Microsoft.Insights"
        Register-AzResourceProvider -ProviderNamespace "Microsoft.Insights" | Out-Null
        do
        {
            Start-Sleep -Seconds 5
            $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Insights" -Location $AlyaLocation
        } while ($resProv[0].RegistrationState -ne "Registered")
    }

    $StrgAccounts = Get-AzStorageAccount
    foreach ($StrgAccount in $StrgAccounts)
    {
        $StorageAccountName = $StrgAccount.StorageAccountName
        Write-Host "Checking storage account $StorageAccountName" -ForegroundColor $CommandInfo
        $classicIsConfigured = $false
        $classicIsConfigured = $classicIsConfigured -or (Get-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "Blob" -MetricsType "Hour").MetricsLevel -ne "None"
        $classicIsConfigured = $classicIsConfigured -or (Get-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "File" -MetricsType "Hour").MetricsLevel -ne "None"
        $classicIsConfigured = $classicIsConfigured -or (Get-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "Queue" -MetricsType "Hour").MetricsLevel -ne "None"
        $classicIsConfigured = $classicIsConfigured -or (Get-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "Table" -MetricsType "Hour").MetricsLevel -ne "None"
        $classicIsConfigured = $classicIsConfigured -or (Get-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "Blob" -MetricsType "Minute").MetricsLevel -ne "None"
        $classicIsConfigured = $classicIsConfigured -or (Get-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "File" -MetricsType "Minute").MetricsLevel -ne "None"
        $classicIsConfigured = $classicIsConfigured -or (Get-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "Queue" -MetricsType "Minute").MetricsLevel -ne "None"
        $classicIsConfigured = $classicIsConfigured -or (Get-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "Table" -MetricsType "Minute").MetricsLevel -ne "None"
        $classicIsConfigured = $classicIsConfigured -or (Get-AzStorageServiceLoggingProperty -Context $StrgAccount.Context -ServiceType "Blob").LoggingOperations -ne "None"
        $classicIsConfigured = $classicIsConfigured -or (Get-AzStorageServiceLoggingProperty -Context $StrgAccount.Context -ServiceType "Queue").LoggingOperations -ne "None"
        $classicIsConfigured = $classicIsConfigured -or (Get-AzStorageServiceLoggingProperty -Context $StrgAccount.Context -ServiceType "Table").LoggingOperations -ne "None"
        if ($classicIsConfigured)
        {
            Write-Host "Disabling classic settings"
            Set-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "Blob" -MetricsType "Hour" -MetricsLevel "None"
            Set-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "File" -MetricsType "Hour" -MetricsLevel "None"
            Set-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "Queue" -MetricsType "Hour" -MetricsLevel "None"
            Set-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "Table" -MetricsType "Hour" -MetricsLevel "None"
            Set-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "Blob" -MetricsType "Minute" -MetricsLevel "None"
            Set-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "File" -MetricsType "Minute" -MetricsLevel "None"
            Set-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "Queue" -MetricsType "Minute" -MetricsLevel "None"
            Set-AzStorageServiceMetricsProperty -Context $StrgAccount.Context -ServiceType "Table" -MetricsType "Minute" -MetricsLevel "None"
            Set-AzStorageServiceLoggingProperty -Context $StrgAccount.Context -ServiceType "Blob" -LoggingOperations "None"
            Set-AzStorageServiceLoggingProperty -Context $StrgAccount.Context -ServiceType "Queue" -LoggingOperations "None"
            Set-AzStorageServiceLoggingProperty -Context $StrgAccount.Context -ServiceType "Table" -LoggingOperations "None"
        }

        # Setting diagnostic setting storage
        $DiagnosticRuleName = "$StorageAccountName-diag"
        Write-Host "Setting diagnostic setting $DiagnosticRuleName"
        $catListLog = @(); $catListMetric = @()
        Get-AzDiagnosticSettingCategory -ResourceId $StrgAccount.Id | ForEach-Object {
            if ($_.CategoryType -eq "Logs")
            {
                $catListLog += (New-AzDiagnosticSettingLogSettingsObject -Category $_.Name -Enabled $true)
            }
            else
            {
                $catListMetric += (New-AzDiagnosticSettingMetricSettingsObject -Category $_.Name -Enabled $true)
            }
        }
        $Settings = Get-AzDiagnosticSetting -ResourceId $StrgAccount.Id
        if ($Settings) { $DiagnosticRuleName = $Settings.Name }
        if ($StorageAccountName -eq $AnalyticsStorageAccountName) {
          $diagSetting = New-AzDiagnosticSetting -Name $DiagnosticRuleName -ResourceId $StrgAccount.Id -Log $catListLog -Metric $catListMetric -WorkspaceId $WrkspcLogAna.ResourceId
        } else {
          $diagSetting = New-AzDiagnosticSetting -Name $DiagnosticRuleName -ResourceId $StrgAccount.Id -Log $catListLog -Metric $catListMetric -WorkspaceId $WrkspcLogAna.ResourceId -StorageAccountId $StrgAccountLogAna.Id
        }

        # Setting diagnostic setting storage blobServices
        $DiagnosticRuleName = "$StorageAccountName-blobServices-diag"
        Write-Host "Setting diagnostic setting $DiagnosticRuleName"
        $catListLog = @(); $catListMetric = @()
        Get-AzDiagnosticSettingCategory -ResourceId ($StrgAccount.Id + "/blobServices/default") | ForEach-Object {
            if ($_.CategoryType -eq "Logs")
            {
                $catListLog += (New-AzDiagnosticSettingLogSettingsObject -Category $_.Name -Enabled $true)
            }
            else
            {
                $catListMetric += (New-AzDiagnosticSettingMetricSettingsObject -Category $_.Name -Enabled $true)
            }
        }
        $Settings = Get-AzDiagnosticSetting -ResourceId ($StrgAccount.Id + "/blobServices/default")
        if ($Settings) { $DiagnosticRuleName = $Settings.Name }
        if ($StorageAccountName -eq $AnalyticsStorageAccountName) {
          $diagSetting = New-AzDiagnosticSetting -Name $DiagnosticRuleName -ResourceId ($StrgAccount.Id + "/blobServices/default") -Log $catListLog -Metric $catListMetric -WorkspaceId $WrkspcLogAna.ResourceId
        } else {
          $diagSetting = New-AzDiagnosticSetting -Name $DiagnosticRuleName -ResourceId ($StrgAccount.Id + "/blobServices/default") -Log $catListLog -Metric $catListMetric -WorkspaceId $WrkspcLogAna.ResourceId -StorageAccountId $StrgAccountLogAna.Id
        }

        # Setting diagnostic setting storage queueServices
        $DiagnosticRuleName = "$StorageAccountName-queueServices-diag"
        Write-Host "Setting diagnostic setting $DiagnosticRuleName"
        $catListLog = @(); $catListMetric = @()
        Get-AzDiagnosticSettingCategory -ResourceId ($StrgAccount.Id + "/queueServices/default") | ForEach-Object {
            if ($_.CategoryType -eq "Logs")
            {
                $catListLog += (New-AzDiagnosticSettingLogSettingsObject -Category $_.Name -Enabled $true)
            }
            else
            {
                $catListMetric += (New-AzDiagnosticSettingMetricSettingsObject -Category $_.Name -Enabled $true)
            }
        }
        $Settings = Get-AzDiagnosticSetting -ResourceId ($StrgAccount.Id + "/queueServices/default")
        if ($Settings) { $DiagnosticRuleName = $Settings.Name }
        if ($StorageAccountName -eq $AnalyticsStorageAccountName) {
          $diagSetting = New-AzDiagnosticSetting -Name $DiagnosticRuleName -ResourceId ($StrgAccount.Id + "/queueServices/default") -Log $catListLog -Metric $catListMetric -WorkspaceId $WrkspcLogAna.ResourceId
        } else {
          $diagSetting = New-AzDiagnosticSetting -Name $DiagnosticRuleName -ResourceId ($StrgAccount.Id + "/queueServices/default") -Log $catListLog -Metric $catListMetric -WorkspaceId $WrkspcLogAna.ResourceId -StorageAccountId $StrgAccountLogAna.Id
        }

        # Setting diagnostic setting storage tableServices
        $DiagnosticRuleName = "$StorageAccountName-tableServices-diag"
        Write-Host "Setting diagnostic setting $DiagnosticRuleName"
        $catListLog = @(); $catListMetric = @()
        Get-AzDiagnosticSettingCategory -ResourceId ($StrgAccount.Id + "/tableServices/default") | ForEach-Object {
            if ($_.CategoryType -eq "Logs")
            {
                $catListLog += (New-AzDiagnosticSettingLogSettingsObject -Category $_.Name -Enabled $true)
            }
            else
            {
                $catListMetric += (New-AzDiagnosticSettingMetricSettingsObject -Category $_.Name -Enabled $true)
            }
        }
        $Settings = Get-AzDiagnosticSetting -ResourceId ($StrgAccount.Id + "/tableServices/default")
        if ($Settings) { $DiagnosticRuleName = $Settings.Name }
        if ($StorageAccountName -eq $AnalyticsStorageAccountName) {
          $diagSetting = New-AzDiagnosticSetting -Name $DiagnosticRuleName -ResourceId ($StrgAccount.Id + "/tableServices/default") -Log $catListLog -Metric $catListMetric -WorkspaceId $WrkspcLogAna.ResourceId
        } else {
          $diagSetting = New-AzDiagnosticSetting -Name $DiagnosticRuleName -ResourceId ($StrgAccount.Id + "/tableServices/default") -Log $catListLog -Metric $catListMetric -WorkspaceId $WrkspcLogAna.ResourceId -StorageAccountId $StrgAccountLogAna.Id
        }

        # Setting diagnostic setting storage fileServices
        $DiagnosticRuleName = "$StorageAccountName-fileServices-diag"
        Write-Host "Setting diagnostic setting $DiagnosticRuleName"
        $catListLog = @(); $catListMetric = @()
        Get-AzDiagnosticSettingCategory -ResourceId ($StrgAccount.Id + "/fileServices/default") | ForEach-Object {
            if ($_.CategoryType -eq "Logs")
            {
                $catListLog += (New-AzDiagnosticSettingLogSettingsObject -Category $_.Name -Enabled $true)
            }
            else
            {
                $catListMetric += (New-AzDiagnosticSettingMetricSettingsObject -Category $_.Name -Enabled $true)
            }
        }
        $Settings = Get-AzDiagnosticSetting -ResourceId ($StrgAccount.Id + "/fileServices/default")
        if ($Settings) { $DiagnosticRuleName = $Settings.Name }
        if ($StorageAccountName -eq $AnalyticsStorageAccountName) {
          $diagSetting = New-AzDiagnosticSetting -Name $DiagnosticRuleName -ResourceId ($StrgAccount.Id + "/fileServices/default") -Log $catListLog -Metric $catListMetric -WorkspaceId $WrkspcLogAna.ResourceId
        } else {
          $diagSetting = New-AzDiagnosticSetting -Name $DiagnosticRuleName -ResourceId ($StrgAccount.Id + "/fileServices/default") -Log $catListLog -Metric $catListMetric -WorkspaceId $WrkspcLogAna.ResourceId -StorageAccountId $StrgAccountLogAna.Id
        }
    }
}

#Stopping Transscript
Stop-Transcript
