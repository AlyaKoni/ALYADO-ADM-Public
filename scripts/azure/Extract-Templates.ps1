#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

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
    02.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Extract-Templates-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Azure | Extract-Templates | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error -Message "Can't get Az context! Not logged in?"
    Exit 1
}

# Exporting all resourcegroup templates
Write-Host "Exporting all resourcegroup templates" -ForegroundColor $CommandInfo
$TemplateRoot = "$($AlyaData)\azure\templates"
Write-Host "  to $($TemplateRoot)" -ForegroundColor $CommandInfo
if (-Not (Test-Path -Path $TemplateRoot -PathType Container))
{
    New-Item -Path $TemplateRoot -ItemType Directory -Force | Out-Null
}
Push-Location -Path $TemplateRoot

$grps = Get-AzResourceGroup
foreach($grp in $grps)
{
    Write-Host "Exporting: $($grp.ResourceId)"
    $fileName = ($grp.ResourceId -replace "/", "_") + ".json"
    Export-AzResourceGroup -ResourceGroupName $grp.ResourceGroupName -Path . -IncludeParameterDefaultValue -IncludeComments -Pre -Force
    Move-Item -Path ($grp.ResourceGroupName + ".json") -Destination ($AlyaSubscriptionName + "_" + $grp.ResourceGroupName) -Force
}
Pop-Location

#Stopping Transscript
Stop-Transcript