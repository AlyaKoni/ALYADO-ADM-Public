#Requires -Version 7.0

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
    11.10.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string[]] [Parameter(Mandatory=$false)]
    $adminGroups = $null,
    [string[]] [Parameter(Mandatory=$false)]
    $adminUsers = $null
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Add-AdminsToAllSites-$($AlyaTimeString).log" | Out-Null

# CheckIng modules
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Login
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

# Getting site collections
Write-Host "Getting site collections" -ForegroundColor $CommandInfo
$retries = 10
do
{
    try
    {
        $sitesToProcess = Get-PnPTenantSite -Connection $adminCon -Detailed
        break
    }
    catch
    {
        Write-Error $_.Exception -ErrorAction Continue
        Write-Warning "Retrying $retries times"
        Start-Sleep -Seconds 15
        $retries--
        if ($retries -lt 0) { throw }
    }
} while ($true)

# Getting role groups
$siteCon = LoginTo-PnP -Url $AlyaSharePointUrl
$web = Get-PnPWeb -Connection $siteCon

$spAdminRoleName = "Company Administrator"
try {
    $gauser = $web.EnsureUser($spAdminRoleName)
    $gauser.Context.Load($gauser)
    Invoke-PnPQuery -Connection $siteCon
    $gauserLoginName = $gauser.LoginName
}
catch {
    $spAdminRoleName = "Global Administrator"
    try {
        $gauser = $web.EnsureUser($spAdminRoleName)
        $gauser.Context.Load($gauser)
        Invoke-PnPQuery -Connection $siteCon
        $gauserLoginName = $gauser.LoginName
    }
    catch {
        $gauserLoginName = $null
    }
}

$spAdminRoleName = "SharePoint Service Administrator"
try {
    $sauser = $web.EnsureUser($spAdminRoleName)
    $sauser.Context.Load($sauser)
    Invoke-PnPQuery -Connection $siteCon
    $sauserLoginName = $sauser.LoginName
}
catch {
    $spAdminRoleName = "SharePoint Administrator"
    try {
        $sauser = $web.EnsureUser($spAdminRoleName)
        $sauser.Context.Load($sauser)
        Invoke-PnPQuery -Connection $siteCon
        $sauserLoginName = $sauser.LoginName
    }
    catch {
        $sauserLoginName = $null
    }
}

# Defining functions
function CheckNotIn($searchFor, $searchIn)
{
    $notfnd = $true
    foreach($search in $searchIn)
    {
        if ($search -like "*$searchFor*") { $notfnd = $false ; break }
        if ($searchFor -like "*$search*") { $notfnd = $false ; break }
    }
    return $notfnd
}

# Defining admins
$owners = @()
$primaryAdmin = $null
if (-Not [string]::IsNullOrEmpty($gauserLoginName)) { if (CheckNotIn -searchFor $gauserLoginName -searchIn $owners) { $owners += $gauserLoginName ; if (-Not $primaryAdmin) { $primaryAdmin = $gauserLoginName } } }
if (-Not [string]::IsNullOrEmpty($sauserLoginName)) { if (CheckNotIn -searchFor $sauserLoginName -searchIn $owners) { $owners += $sauserLoginName ; if (-Not $primaryAdmin) { $primaryAdmin = $sauserLoginName } } }
if (-Not [string]::IsNullOrEmpty($AlyaSharePointNewSiteOwner) -and $AlyaSharePointNewSiteOwner -ne "PleaseSepcify") { if (CheckNotIn -searchFor $AlyaSharePointNewSiteOwner -searchIn $owners) { $owners += $AlyaSharePointNewSiteOwner ; if (-Not $primaryAdmin) { $primaryAdmin = $AlyaSharePointNewSiteOwner } } }
if (-Not [string]::IsNullOrEmpty($AlyaSharePointNewSiteAdditionalOwner) -and $AlyaSharePointNewSiteAdditionalOwner -ne "PleaseSepcify") { if (CheckNotIn -searchFor $AlyaSharePointNewSiteAdditionalOwner -searchIn $owners) { $owners += $AlyaSharePointNewSiteAdditionalOwner ; if (-Not $primaryAdmin) { $primaryAdmin = $AlyaSharePointNewSiteAdditionalOwner } } }
if ($AlyaSharePointNewSiteCollectionAdmins -and $AlyaSharePointNewSiteCollectionAdmins.Count -gt 0)
{
    foreach($AlyaSharePointNewSiteCollectionAdmin in $AlyaSharePointNewSiteCollectionAdmins)
    {
        if (-Not [string]::IsNullOrEmpty($AlyaSharePointNewSiteCollectionAdmin) -and $AlyaSharePointNewSiteCollectionAdmin -ne "PleaseSepcify") { if (CheckNotIn -searchFor $AlyaSharePointNewSiteCollectionAdmin -searchIn $owners) { $owners += $AlyaSharePointNewSiteCollectionAdmin ; if (-Not $primaryAdmin) { $primaryAdmin = $AlyaSharePointNewSiteCollectionAdmin } } }
    }
}
foreach($owner in $adminGroups)
{
    if (CheckNotIn -searchFor $owner -searchIn $owners) { $owners += $owner ; if (-Not $primaryAdmin) { $primaryAdmin = $owner } }
}
foreach($owner in $adminUsers)
{
    if (CheckNotIn -searchFor $owner -searchIn $owners) { $owners += $owner ; if (-Not $primaryAdmin) { $primaryAdmin = $owner } }
}

# Setting site admins
Write-Host "Setting site admins" -ForegroundColor $CommandInfo
foreach ($site in $sitesToProcess)
{
    if ($site.Template -like "Redirect*") { continue }
    if (-Not $site.Url.Contains("/sites/") -And $site.Url.TrimEnd("/") -ne $AlyaSharePointUrl.TrimEnd("/")) { continue }
    Write-Host "$($site.Url)"

    # CheckIng existing owners
    $sowners = $owners
    $sprimaryAdmin = $primaryAdmin
    $siteCon = LoginTo-PnP -Url $site.Url

    $tsite = Get-PnPTenantSite -Connection $adminCon -Identity $site.Url
    if ($tsite.OwnerLoginName -ne $sprimaryAdmin)
    {
        try {
            Set-PnPTenantSite -Connection $adminCon -Identity $site.Url -PrimarySiteCollectionAdmin $sprimaryAdmin
        }
        catch {
            try {
                Add-PnPSiteCollectionAdmin -Connection $siteCon -PrimarySiteCollectionAdmin $sprimaryAdmin
            }
            catch {
                Write-Warning "Not able to add primary admin $sprimaryAdmin"
                Write-Warning "Please add yourself or $sprimaryAdmin as site collection admin and rerun this script"
                continue
            }
        }
    }

    $admins = Get-PnPSiteCollectionAdmin -Connection $siteCon
    foreach($owner in $admins.LoginName)
    {
        if (CheckNotIn -searchFor $owner -searchIn $sowners) { $sowners += $owner ; if (-Not $sprimaryAdmin) { $sprimaryAdmin = $owner } }
    }

    # Setting site owners
    Set-PnPTenantSite -Connection $adminCon -Identity $site.Url -PrimarySiteCollectionAdmin $sprimaryAdmin -Owners $sowners
}

# Stopping Transscript
Stop-Transcript
