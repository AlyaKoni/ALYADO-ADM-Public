#Requires -Version 2.0

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
    25.03.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aip\Enable-AIPIntegrationInGroups-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "AzureAdPreview"
    
# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AIP | Enable-AIPIntegrationInGroups | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Enabling AIP integration
Write-Host "Enabling AIP integration in AAD" -ForegroundColor $CommandInfo
$SettingTemplate = Get-AzureADDirectorySettingTemplate | where { $_.DisplayName -eq "Group.Unified" }
$Setting = Get-AzureADDirectorySetting | where { $_.DisplayName -eq "Group.Unified" }
if (-Not $Setting)
{
    Write-Warning "Setting not yet created. Creating one based on template."
    $Setting = $SettingTemplate.CreateDirectorySetting()
    $Setting["EnableMIPLabels"] = $true
    New-AzureADDirectorySetting -DirectorySetting $Setting
}
else
{
    $Setting["EnableMIPLabels"] = $true
    Set-AzureADDirectorySetting -Id $Setting.Id -DirectorySetting $Setting
}
$Setting.Values


# Syncing labels
Write-Host "Syncing labels" -ForegroundColor $CommandInfo
LoginTo-IPPS
Execute-AzureADLabelSync

#Stopping Transscript
Stop-Transcript
