#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2023

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
    15.01.2021 Konrad Brunner       Initial Creation
    29.11.2023 Konrad Brunner       Switch to Graph

#>

[CmdletBinding()]
Param(
    [bool]$ProcessSharePoint = $true
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Delete-OfficeGroupPermanently-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"

# Logins
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AZURE | Delete-OfficeGroupPermanently | GRAPH" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$filterUrl = "https://graph.microsoft.com/beta/directory/deletedItems/microsoft.graph.group"
$softDeletedGroups = Get-MsGraphCollection -Uri $filterUrl
if ($softDeletedGroups -and $softDeletedGroups.Count -gt 0)
{
    Write-Host "Following groups are soft deleted and will be deleted permanently:" -ForegroundColor $CommandInfo
    foreach($softDeletedGroup in $softDeletedGroups)
    {
        Write-Host " - $($softDeletedGroup.displayName)"
    }
    pause
    foreach($softDeletedGroup in $softDeletedGroups)
    {
        Write-Host "Removing $($softDeletedGroup.displayName)"
        $filterUrl = "https://graph.microsoft.com/beta/directory/deletedItems/$($softDeletedGroup.id)"
        $null = Delete-MsGraphObject -Uri $filterUrl
    }

    if ($ProcessSharePoint)
    {
        Write-Host "Running $($AlyaScripts)\sharepoint\Clean-DeletedSites.ps1"
        & "$($AlyaScripts)\sharepoint\Clean-DeletedSites.ps1" -ProcessGroups $false
    }
}
else
{
    Write-Host "No groups found"
}

#Stopping Transscript
Stop-Transcript
