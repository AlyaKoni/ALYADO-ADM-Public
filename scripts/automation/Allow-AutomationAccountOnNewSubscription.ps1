﻿#Requires -Version 2.0

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
    18.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\automation\Allow-AutomationAccountOnNewSubscription-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAutomation)"
$AutomationAccountName = "$($AlyaNamingPrefix)aacc$($AlyaResIdAutomationAccount)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Automation"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Automation | Allow-AutomationAccountOnNewSubscription | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking ressource group
Write-Host "Checking ressource group for automation account" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Error "Ressource Group not found. Please create the Ressource Group $ResourceGroupName" -ErrorAction Continue
    Exit
}

# Checking automation account
Write-Host "Checking automation account" -ForegroundColor $CommandInfo
$AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
if (-Not $AutomationAccount)
{
    Write-Warning "Automation Account not found. Please create the Automation Account $AutomationAccountName"
    Exit
}

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$RunasAppName = "$($AutomationAccountName)RunAsApp"
$AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $RunasAppName
if (-Not $AzureAdServicePrincipal)
{
    Write-Warning "Automation Application not found. Please create the Automation Application $RunasAppName"
    Exit
}

# Checking automation service principal on all subscriptions
Write-Host "Checking automation service principal on all subscriptions"

$RunAsApplication = Get-AzADApplication -DisplayNameStartWith $RunasAppName -ErrorAction SilentlyContinue
Get-AzSubscription | Foreach-Object {
    write-host "Configuring app on subscription $($_.Name) $($_.Id)"
    Select-AzSubscription -SubscriptionId $_.Id
    $NewRole = Get-AzRoleAssignment -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -eq $RunasAppName -and $_.RoleDefinitionName -eq "Contributor"}
    While ($NewRole -eq $null)
    {
	    Try {
		    New-AzRoleAssignment -RoleDefinitionName "Contributor" -ServicePrincipalName $RunAsApplication.ApplicationId | Write-Verbose -ErrorAction SilentlyContinue
	    }
	    Catch {
		    $ErrorMessage = $_.Exception.Message
		    Write-Host "Error message: $($ErrorMessage)"
		    Write-Verbose "Service Principal not yet active, delay before adding the role assignment."
            Sleep 5
	    }
	    $NewRole = Get-AzRoleAssignment -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -eq $RunasAppName -and $_.RoleDefinitionName -eq "Contributor"}
        Write-Verbose "Added role assignment for Azure AD application $($RunasAppName)"
    }
}

# Adding new subscription to Start/Stop runbook
#TODO
Write-Host "Please update the runbook 4 with the new subscription id" -ForegroundColor Cyan

#Stopping Transscript
Stop-Transcript
