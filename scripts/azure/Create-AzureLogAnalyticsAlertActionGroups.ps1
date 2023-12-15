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
    10.11.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\data\azure\Create-AzureLogAnalyticsAlertActionGroups-$($AlyaTimeString).log" | Out-Null

# Constants
$AuditingResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$AuditingResourceGroupTags = $null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Monitor"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "LogAnalytics | Create-AzureLogAnalyticsAlertActionGroups | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}
$AuditingResourceGroupTags = @{displayName="Audit Logs";ownerEmail=$Context.Account.Id}

function Prepare-ActionGroup ($AuditingSubscriptionName, $AuditingResourceGroupName, $AuditingActionGroupName, $AuditingActionGroupNameShort, $AuditingActionGroupEmails, $AuditingResourceGroupTags)
{
    # Checking resource provider registration
    Write-Host "Checking resource provider registration Microsoft.Insights" -ForegroundColor $CommandInfo
    $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Insights" -Location $AlyaLocation
    if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
    {
        Write-Host "Resource provider Microsoft.Insights not registered. Registering now resource provider Microsoft.Insights" -ForegroundColor $CommandWarning
        Register-AzResourceProvider -ProviderNamespace "Microsoft.Insights" | Out-Null
        do
        {
            Start-Sleep -Seconds 5
            $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Insights" -Location $AlyaLocation
        } while ($resProv[0].RegistrationState -ne "Registered")
    }

    # Checking ressource group
    Write-Host "Checking ressource group $AuditingResourceGroupName" -ForegroundColor $CommandInfo
    $ResGrpParent = Get-AzResourceGroup -Name $AuditingResourceGroupName -ErrorAction SilentlyContinue
    if (-Not $ResGrpParent)
    {
        Write-Host "    Does not exist. Creating it now" -ForegroundColor $CommandWarning
        $null = New-AzResourceGroup -Name $AuditingResourceGroupName -Location $AlyaLocation -Tag $AuditingResourceGroupTags
    }
    else
    {
        Write-Host "    Updating"
        $null = Set-AzResourceGroup -Name $AuditingResourceGroupName -Tag $AuditingResourceGroupTags
    }

    # Checking action group
    Write-Host "Checking action group $AuditingActionGroupName" -ForegroundColor $CommandInfo
    $actionGroup = Get-AzActionGroup -ResourceGroupName $AuditingResourceGroupName -Name $AuditingActionGroupName -ErrorAction SilentlyContinue
    $recvrs = @()
    foreach($recvr in $AuditingActionGroupEmails)
    {
        $recvrs += New-AzActionGroupEmailReceiverObject -Name ("EmailTo-"+$recvr) `
            -EmailAddress $recvr `
            -UseCommonAlertSchema $true
    }
    if (-Not $actionGroup) {
        Write-Warning "    Does not exist. Creating it now"
        New-AzActionGroup -Name $AuditingActionGroupName `
            -ResourceGroup $AuditingResourceGroupName `
            -ShortName $AuditingActionGroupNameShort `
            -EmailReceiver $recvrs `
            -Location "Global"
    } else {
        Write-Host "    Updating"
        Update-AzActionGroup -Name $AuditingActionGroupName `
            -ResourceGroup $AuditingResourceGroupName `
            -ShortName $AuditingActionGroupNameShort `
            -EmailReceiver $recvrs
    }
    $actionGroup = Get-AzActionGroup -ResourceGroupName $AuditingResourceGroupName -Name $AuditingActionGroupName
}

Prepare-ActionGroup `
    -AuditingSubscriptionName $AlyaSubscriptionName `
    -AuditingResourceGroupName $AuditingResourceGroupName `
    -AuditingActionGroupName "AlertSupportByMail" `
    -AuditingActionGroupNameShort "AlrtSupMail" `
    -AuditingActionGroupEmails @($AlyaSupportEmail) `
    -AuditingResourceGroupTags $AuditingResourceGroupTags

Prepare-ActionGroup `
    -AuditingSubscriptionName $AlyaSubscriptionName `
    -AuditingResourceGroupName $AuditingResourceGroupName `
    -AuditingActionGroupName "AlertSecurityByMail" `
    -AuditingActionGroupNameShort "AlrtSecMail" `
    -AuditingActionGroupEmails @($AlyaSecurityEmail) `
    -AuditingResourceGroupTags $AuditingResourceGroupTags

#Stopping Transscript
Stop-Transcript
