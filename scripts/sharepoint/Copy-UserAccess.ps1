#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2023

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
    20.11.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$searchUpn,
    [Parameter(Mandatory=$true)]
    [string]$configureUpn
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Copy-UserAccess-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Login
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Copy-UserAccess | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting site collections
Write-Host "Getting site collections" -ForegroundColor $CommandInfo
$sitesToProcess = Get-PnPTenantSite -Connection $script:adminCon -Detailed -IncludeOneDriveSites | Where-Object { $_.Url -like "*/sites/*" }
$allUsers = Get-PnPAzureADUser -Connection $script:adminCon

$searchUser = $allUsers | Where-Object { $_.UserPrincipalName -eq $searchUpn }
if (-Not $searchUser)
{
    throw "User $searchUpn not found"
}
$configureUser = $allUsers | Where-Object { $_.UserPrincipalName -eq $configureUpn }
if (-Not $configureUser)
{
    throw "User $configureUpn not found"
}

foreach($siteToProcess in $sitesToProcess)
{
    Write-Host "$($siteToProcess.Url)" -ForegroundColor $CommandInfo
    $siteCon = LoginTo-PnP -Url $siteToProcess.Url

    $web = Get-PnPWeb -Connection $siteCon
    $roleAssignments = Get-PnPProperty -Connection $siteCon -ClientObject $web -Property "RoleAssignments"
    foreach($roleAssignment in $roleAssignments)
    {
        $loginName = Get-PnPProperty -Connection $siteCon -ClientObject $roleAssignment.Member -Property "LoginName"
        $principalType = Get-PnPProperty -Connection $siteCon -ClientObject $roleAssignment.Member -Property "PrincipalType"
        Write-Host "Assignment $principalType '$loginName'"
        if ($principalType -eq "User")
        {
            if ($loginName -like "*$searchUpn")
            {
                Write-Host "Found"
            }
        }
        if ($principalType -eq "SharePointGroup")
        {
            $members = Get-PnPGroupMember -Connection $siteCon -Identity $loginName #TODO does this work for sub webs?
            $searchFnd = $false
            $configureFnd = $false
            foreach($member in $members)
            {
                if ($member.LoginName -like "*$searchUpn")
                {
                    Write-Host "Found search"
                    $searchFnd = $true
                }
                if ($member.LoginName -like "*$configureUpn")
                {
                    Write-Host "Found configure"
                    $configureFnd = $true
                }
            }
            if ($searchFnd)
            {
                if (-Not $configureFnd)
                {
                    Write-Host "Adding configure"
                    Add-PnPGroupMember -Connection $siteCon -Group $loginName -LoginName $configureUpn
                }
            }
        }
    }

}

#Stopping Transscript
Stop-Transcript