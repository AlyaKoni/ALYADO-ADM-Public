#Requires -Version 7.0

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
    25.03.2023 Konrad Brunner       Initial Version
    20.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\data\sharepoint\dms\Configure-TermStoreAdministrators-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"
#throws in PS7
#Install-PackageIfNotInstalled "Microsoft.SharePointOnline.CSOM"
#Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM\lib\net45\Microsoft.SharePoint.Client.dll"
#Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM\lib\net45\Microsoft.SharePoint.Client.Runtime.dll"
#Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM\lib\net45\Microsoft.SharePoint.Client.Taxonomy.dll"

# Logging in
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Configure-TermStoreAdministrators | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking term store
Write-Host "Checking term store" -ForegroundColor $CommandInfo
$adminCnt = Get-PnPContext -Connection $adminCon
$adminCnt.ExecuteQuery()

$mms = [Microsoft.SharePoint.Client.Taxonomy.TaxonomySession]::GetTaxonomySession($adminCnt)
$adminCnt.Load($mms)
$adminCnt.Load($mms.TermStores)
$adminCnt.ExecuteQuery()

# Checking term store
Write-Host "Checking term store" -ForegroundColor $CommandInfo
$termStore = $mms.TermStores | Where-Object { $_.Name -like "Taxonomy*" }
$adminCnt.Load($termStore)
$adminCnt.Load($termStore.Groups)
$adminCnt.ExecuteQuery()

# Checking term group
Write-Host "Checking term group $AlyaCompanyNameShortM365" -ForegroundColor $CommandInfo
$TermGroup = $termStore.Groups | Where-Object { $_.Name -eq $AlyaCompanyNameShortM365 }
if (-Not $TermGroup)
{
    Write-Warning "$AlyaCompanyNameShortM365 term group does not exist, creating it now"
    $TermGroup = $termStore.CreateGroup($AlyaCompanyNameShortM365, [System.Guid]::NewGuid().ToString())
    $adminCnt.Load($TermGroup)
    $adminCnt.ExecuteQuery()
}

# Setting term group administrators
Write-Host "Setting term group administrators" -ForegroundColor $CommandInfo
$Web = Get-PnPWeb -Connection $adminCon
foreach($AlyaSharePointNewSiteCollectionAdmin in $AlyaSharePointNewSiteCollectionAdmins)
{
    $user = $Web.EnsureUser($AlyaSharePointNewSiteCollectionAdmin)
    $adminCnt.Load($user)
    $adminCnt.ExecuteQuery()
    $TermGroup.AddGroupManager($user.LoginName)
}

#TODO admins on store

#Stopping Transscript
Stop-Transcript
