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
    10.01.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$sourceGroup,
    [Parameter(Mandatory=$true)]
    [string]$destinationGroup,
    [bool]$mergeMembers = $true # Members in destinationGroup not in sourceGroup will be removed from destinationGroup
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Copy-GroupMemebers-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# AAD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Copy-GroupMemebers | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting source group
Write-Host "Getting source group" -ForegroundColor $CommandInfo
$srcGrp = Get-MgBetaGroup -Filter "DisplayName eq '$sourceGroup'"
if (-Not $srcGrp)
{
    $srcGrp = Get-MgBetaGroup -GroupId $sourceGroup
}
if (-Not $srcGrp)
{
    throw "Source group $sourceGroup not found"
}

# Getting destination group
Write-Host "Getting destination group" -ForegroundColor $CommandInfo
$dstGrp = Get-MgBetaGroup -Filter "DisplayName eq '$destinationGroup'"
if (-Not $dstGrp)
{
    $dstGrp = Get-MgBetaGroup -GroupId $destinationGroup
}
if (-Not $dstGrp)
{
    throw "Destination group $destinationGroup not found"
}
if ("DynamicMembership" -in $dstGrp.GroupTypes)
{
    throw "Destination group is of type DynamicMembership"
}

# Cleaning destination group members
if (-Not $mergeMembers)
{
    Write-Host "Cleaning destination group members" -ForegroundColor $CommandInfo
    $dstMembers = Get-MgBetaGroupMember -GroupId $dstGrp.Id -All
    foreach ($dstMember in $dstMembers)
    {
        Remove-MgBetaGroupMemberByRef -GroupId $dstGrp.Id -DirectoryObjectId $member.Id
    }
}

# Adding source group members
Write-Host "Adding source group members" -ForegroundColor $CommandInfo
$srcMembers = Get-MgBetaGroupMember -GroupId $srcGrp.Id -All
$dstMembers = Get-MgBetaGroupMember -GroupId $dstGrp.Id -All
foreach ($srcMember in $srcMembers)
{
    $exist = $dstMembers | Where-Object { $_.AdditionalProperties.userPrincipalName -eq $srcMember.AdditionalProperties.userPrincipalName }
    if (-Not $exist)
    {
        Write-Host "Adding $($srcMember.AdditionalProperties.userPrincipalName)"
        New-MgBetaGroupMember -GroupId $dstGrp.Id -DirectoryObjectId $srcMember.Id
    }
    else
    {
        Write-Host "Skipped $($srcMember.AdditionalProperties.userPrincipalName)"
    } 
}

#Stopping Transscript
Stop-Transcript
