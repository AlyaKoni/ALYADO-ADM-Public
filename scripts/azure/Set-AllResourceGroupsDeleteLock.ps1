#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019, 2020

    This file is part of the Alya Base Configuration.
    The Alya Base Configuration is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
	Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
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
    18.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\automation\Set-AllResourceGroupsDeleteLock-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Azure | Set-AllResourceGroupsDeleteLock | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Main
$subs = Get-AzSubscription
foreach($sub in $subs)
{
    Select-AzSubscription -SubscriptionId $sub.Id
    $grps = Get-AzResourceGroup
    foreach($grp in $grps)
    {
        if ($grp.ResourceGroupName.ToLower().StartsWith($AlyaCompanyNameShort))
        {
            $actLock = Get-AzResourceLock -ResourceGroupName $grp.ResourceGroupName -LockName "AlyaDeleteLock" -ErrorAction SilentlyContinue
            if (-Not $actLock)
            {
                Write-Host "Locking resource group: $($grp.ResourceGroupName)" -ForegroundColor Cyan
                Set-AzResourceLock -LockLevel CanNotDelete -LockName "AlyaDeleteLock" -LockNotes "Please ask resource owner before unlocking or deleting any resource!" -ResourceGroupName $grp.ResourceGroupName -Force
            }
        }
    }
}

#Stopping Transscript
Stop-Transcript