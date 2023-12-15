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
    01.05.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\automation\Remove-AllCustomModulesFromAutomationAccount-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

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
Write-Host "Automation | Remove-AllCustomModulesFromAutomationAccount | AZURE" -ForegroundColor $CommandInfo
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
    throw "Ressource Group does not exists. Please create the Ressource Group $ResourceGroupName"
}

function Delete-AllModules($psVersionSelector)
{
    Write-Host "Deleting '$psVersionSelector' modules" -ForegroundColor $CommandInfo
    $moduleList = ((Invoke-AzRestMethod `
        -Method "Get" `
        -SubscriptionId $Context.Subscription.Id `
        -ResourceGroupName $ResourceGroupName `
        -ResourceProviderName "Microsoft.Automation" `
        -ResourceType "automationAccounts" `
        -Name "$AutomationAccountName/$psVersionSelector" `
        -ApiVersion 2019-06-01).Content | ConvertFrom-Json -Depth 99).Value
    
    foreach($module in $moduleList)
    {
        Write-Host "$($module.name)"
        $Resp = Invoke-AzRestMethod `
            -Method "Delete" `
            -SubscriptionId $Context.Subscription.Id `
            -ResourceGroupName $AlyaAutomationLidsResourceGroupName `
            -ResourceProviderName "Microsoft.Automation" `
            -ResourceType "automationAccounts" `
            -Name "$AlyaAutomationLidsAccountName/$psVersionSelector/$($module.name)" `
            -ApiVersion 2019-06-01

        if ($Resp.StatusCode -ne 200)
        {
            Write-Host "  $($Resp.Content)"
        }
    }
}

Delete-AllModules -psVersionSelector "modules"
Delete-AllModules -psVersionSelector "powershell7Modules"

#Stopping Transscript
Stop-Transcript
