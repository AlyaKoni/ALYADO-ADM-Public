#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

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
    02.03.2020 Konrad Brunner       Initial version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Create-AzureRecoveryVault-$($AlyaTimeString).log" | Out-Null

# Constants
$RessourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$RecoveryVaultName = "$($AlyaNamingPrefix)recv$($AlyaResIdRecoveryVault)"
$LogAnaRessourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$LogAnaWrkspcName = "$($AlyaNamingPrefix)loga$($AlyaResIdLogAnalytics)"
$LogAnaDiagnosticRuleName = "Diag-RecVault-$($RecoveryVaultName)"
$LogAnaStorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdAuditStorage)"
$BackupPolicyName = "NightlyPolicy"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Azure | Create-AzureRecoveryVault | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Register providers
Write-Host "Checking resource provider" -ForegroundColor $CommandInfo
$ResProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.RecoveryServices" -Location $AlyaLocation -ErrorAction SilentlyContinue
if (-Not $ResProv)
{
    Write-Warning "Resource provider not found. Registering the resource provider Microsoft.RecoveryServices"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.RecoveryServices"
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $RessourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $RessourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $RessourceGroupName -Location $AlyaLocation -Tag @{displayName="Main Infrastructure Services";ownerEmail=$Context.Account.Id}
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $LogAnaRessourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $LogAnaRessourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $LogAnaRessourceGroupName -Location $AlyaLocation -Tag @{displayName="Audit Logs";ownerEmail=$Context.Account.Id}
}

# Checking log analytics workspace
Write-Host "Checking log analytics workspace" -ForegroundColor $CommandInfo
$LogAnaWrkspc = Get-AzOperationalInsightsWorkspace -ResourceGroupName $LogAnaRessourceGroupName -Name $LogAnaWrkspcName -ErrorAction SilentlyContinue
if (-Not $LogAnaWrkspc)
{
    Write-Warning "Log analytics workspace not found. Creating the log analytics workspace $LogAnaWrkspcName"
    $LogAnaWrkspc = New-AzOperationalInsightsWorkspace -Name $LogAnaWrkspcName -ResourceGroupName $LogAnaRessourceGroupName -Location $AlyaLocation -Sku Standard -Tag @{displayName="Audit Log Workspace"}
    if (-Not $LogAnaWrkspc)
    {
        Write-Error "Log analytics workspace $StorageAccountName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Checking storage account
Write-Host "Checking storage account" -ForegroundColor $CommandInfo
$StrgAccount = Get-AzStorageAccount -ResourceGroupName $LogAnaRessourceGroupName -Name $LogAnaStorageAccountName -ErrorAction SilentlyContinue
if (-Not $StrgAccount)
{
    Write-Warning "Storage account not found. Creating the storage account $LogAnaStorageAccountName"
    $StrgAccount = New-AzStorageAccount -Name $LogAnaStorageAccountName -ResourceGroupName $LogAnaRessourceGroupName -Location $AlyaLocation -SkuName "Standard_LRS" -Kind BlobStorage -AccessTier Cool -Tag @{displayName="Audit Log Storage"}
    if (-Not $StrgAccount)
    {
        Write-Error "Storage account $LogAnaStorageAccountName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Checking recovery vault
Write-Host "Checking recovery vault" -ForegroundColor $CommandInfo
$RecVault = Get-AzRecoveryServicesVault -ResourceGroupName $RessourceGroupName -Name $RecoveryVaultName -ErrorAction SilentlyContinue
if (-Not $RecVault)
{
    Write-Warning "Recovery vault not found. Creating the recovery vault $RecoveryVaultName"
    $RecVault = New-AzRecoveryServicesVault -ResourceGroupName $RessourceGroupName -Name $RecoveryVaultName -Location $AlyaLocation

    Write-Host "Configuring recovery vault"
    Set-AzRecoveryServicesBackupProperties -Vault $RecVault -BackupStorageRedundancy GeoRedundant
    Set-AzRecoveryServicesAsrVaultContext -Vault $RecVault
    Set-AzRecoveryServicesAsrAlertSetting -CustomEmailAddress $AlyaGeneralInformEmail -EnableEmailSubscriptionOwner -LocaleID DE
    Set-AzRecoveryServicesAsrNotificationSetting -CustomEmailAddress $AlyaGeneralInformEmail -EnableEmailSubscriptionOwner -LocaleID DE
    #Get-AzDiagnosticSetting -ResourceId $RecVault.ID
    Set-AzDiagnosticSetting -Name $LogAnaDiagnosticRuleName -ResourceId $RecVault.ID -Enabled $True -Category AzureBackupReport -WorkspaceId $LogAnaWrkspc.ResourceId -StorageAccountId $StrgAccount.Id
}

# Checking backup policy
Write-Host "Checking backup policy" -ForegroundColor $CommandInfo
$BkpPol = Get-AzRecoveryServicesBackupProtectionPolicy -VaultId $RecVault.ID -Name $BackupPolicyName -ErrorAction SilentlyContinue
if (-Not $BkpPol)
{
    Write-Warning "Backup policy not found. Creating the backup policy $BackupPolicyName"
    $RecVault | Set-AzRecoveryServicesVaultContext
    #Get-AzRecoveryServicesBackupProtectionPolicy
    $schPol = Get-AzRecoveryServicesBackupSchedulePolicyObject -WorkloadType "AzureVM"
    [DATETIME]$BkpTime = "1:00"
    $BkpTime = $BkpTime.ToUniversalTime()
    $schPol.ScheduleRunTimes.Clear()
    $schPol.ScheduleRunTimes.Add($BkpTime)
    $retPol = Get-AzRecoveryServicesBackupRetentionPolicyObject -WorkloadType "AzureVM"
    $retPol.IsDailyScheduleEnabled     = $true
    $retPol.DailySchedule.DurationCountInDays = 8
    $retPol.IsWeeklyScheduleEnabled     = $true
    $retPol.WeeklySchedule.DurationCountInWeeks = 5
    $retPol.IsMonthlyScheduleEnabled    = $true
    $retPol.MonthlySchedule.DurationCountInMonths =  13
    $retPol.IsYearlyScheduleEnabled     = $false  #TODO $true not working yet
    $retPol.YearlySchedule.DurationCountInYears =  11
    $retPol.YearlySchedule.RetentionScheduleWeekly.DaysOfTheWeek = "Sunday"
    $retPol.YearlySchedule.RetentionScheduleWeekly.WeeksOfTheMonth = "First"
    $retPol.YearlySchedule.MonthsOfYear = "January"
    $retPol.YearlySchedule.RetentionScheduleFormatType = "Weekly"
    #$retPol.YearlySchedule.RetentionTimes = $BkpTime
    New-AzRecoveryServicesBackupProtectionPolicy `
        -VaultId $RecVault.ID `
        -SchedulePolicy $schPol `
        -RetentionPolicy $retPol `
        -BackupManagementType "AzureVM" `
        -Name $BackupPolicyName `
        -WorkloadType "AzureVM"
}

#Stopping Transscript
Stop-Transcript