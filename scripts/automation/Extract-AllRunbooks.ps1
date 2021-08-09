#Requires -Version 5.1

<#
    Copyright (c) Alya Consulting, 2021

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
    23.06.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\automation\Extract-AllRunbooks-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Constants
$SolutionDataRoot = "$($AlyaData)\automation"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Automation | Extract-AllRunbooks | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Getting automation accounts
Write-Host "Getting automation accounts" -ForegroundColor $CommandInfo
if (-Not (Test-Path -Path $SolutionDataRoot -PathType Container))
{
    New-Item -Path $SolutionDataRoot -ItemType Directory -Force | Out-Null
}
$AutomationAccounts = Get-AzAutomationAccount -ErrorAction SilentlyContinue
if (-Not $AutomationAccounts)
{
    Write-Error "No Automation Account found" -ErrorAction Continue
    exit
}

# Export runbooks
Write-Host "Exporting automation runbooks" -ForegroundColor $CommandInfo
foreach($AutomationAccount in $AutomationAccounts)
{
    Write-Host "  From $($AutomationAccount.AutomationAccountName)"
    $AccountRoot = "$($SolutionDataRoot)\$($AutomationAccount.AutomationAccountName)"
    if (-Not (Test-Path -Path $AccountRoot -PathType Container))
    {
        $tmp = New-Item -Path $AccountRoot -ItemType Directory -Force | Out-Null
    }
    $runbooks = Get-AzAutomationRunbook -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName
    foreach($runbook in $runbooks)
    {
        Write-Host "    Exporting $($runbook.Name) to $($AccountRoot)"
        $tmp = Export-AzAutomationRunbook -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -Name $runbook.Name -Slot "Published" -OutputFolder $AccountRoot -Force
    }
}

#Stopping Transscript
Stop-Transcript