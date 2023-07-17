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
    11.10.2020 Konrad Brunner       Initial Version
    20.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$GroupToAllowExternalGuests
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\groups\Set-GroupExternalSharingEnabled-$($AlyaTimeString).log" | Out-Null

# Constants
if (-Not $GroupToAllowExternalGuests)
{
    throw "Please specify the group"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
    
# Logins
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# Graph stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Groups | Set-GroupExternalSharingEnabled | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking group
Write-Host "Checking group" -ForegroundColor $CommandInfo
$Group = Get-MgBetaGroup -Filter "DisplayName eq '$GroupToAllowExternalGuests'"
if (-Not $Group)
{
    throw "Group '$GroupToAllowExternalGuests' not found"
}

# Configuring settings template
Write-Host "Configuring settings template" -ForegroundColor $CommandInfo
$SettingTemplate = Get-MgBetaDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Group.Unified.Guest" }
$Setting = Get-MgBetaGroupSetting -GroupId $Group.Id | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
if (-Not $Setting)
{
    Write-Warning "Setting not yet created. Creating one based on template."
    $Values = @()
    foreach($dval in $SettingTemplate.Values) {
	    $Values += @{Name = $dval.Name; Value = $dval.DefaultValue}
    }
    $Setting = New-MgBetaGroupSetting -GroupId $Group.Id -DisplayName "Group.Unified.Guest" -TemplateId $SettingTemplate.Id -Values $Values
    $Setting = Get-MgBetaGroupSetting -GroupId $Group.Id | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
}

$Value = $Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }
if ($Value.Value -eq $true) {
    Write-Host "Setting 'AllowToAddGuests' was already set to '$true'"
} 
else {
    Write-Warning "Setting 'AllowToAddGuests' was set to '$($Value.Value)' updating to '$true'"
    ($Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }).Value = $true
}

Update-MgBetaGroupSetting -GroupId $Group.Id -DirectorySettingId $Setting.Id -Values $Setting.Values

#Stopping Transscript
Stop-Transcript
