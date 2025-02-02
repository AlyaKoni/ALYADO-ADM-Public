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
    19.04.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Set-AdminsOnAllSites-$($AlyaTimeString).log" | Out-Null

# Checking modules
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
$rootCon = LoginTo-PnP -Url $AlyaSharePointUrl
$rweb = Get-PnPWeb -Connection $rootCon
$gauser.Context.Load($rweb.CurrentUser)
Invoke-PnPQuery -Connection $rootCon

$spAdminRoleName = "Company Administrator"
try {
    $gauser = $rweb.EnsureUser($spAdminRoleName)
    $gauser.Context.Load($gauser)
    Invoke-PnPQuery -Connection $rootCon
    $gauserLoginName = $gauser.LoginName
}
catch {
    $spAdminRoleName = "Global Administrator"
    try {
        $gauser = $rweb.EnsureUser($spAdminRoleName)
        $gauser.Context.Load($gauser)
        Invoke-PnPQuery -Connection $rootCon
        $gauserLoginName = $gauser.LoginName
    }
    catch {
        $gauserLoginName = $null
    }
}

$spAdminRoleName = "SharePoint Service Administrator"
try {
    $sauser = $rweb.EnsureUser($spAdminRoleName)
    $sauser.Context.Load($sauser)
    Invoke-PnPQuery -Connection $rootCon
    $sauserLoginName = $sauser.LoginName
}
catch {
    $spAdminRoleName = "SharePoint Administrator"
    try {
        $sauser = $rweb.EnsureUser($spAdminRoleName)
        $sauser.Context.Load($sauser)
        Invoke-PnPQuery -Connection $rootCon
        $sauserLoginName = $sauser.LoginName
    }
    catch {
        $sauserLoginName = $null
    }
}

$owners = @($rweb.CurrentUser.Email)
if (-Not [string]::IsNullOrEmpty($gauserLoginName))
{
    $owners += $gauserLoginName
}
else
{
    Write-Warning "Global Administrator Group not found"
}
if (-Not [string]::IsNullOrEmpty($sauserLoginName))
{
    $owners += $sauserLoginName
}
else
{
    Write-Warning "SharePoint Administrator Group not found"
}

foreach($AlyaSharePointNewSiteCollectionAdmin in $AlyaSharePointNewSiteCollectionAdmins)
{
    if ($AlyaSharePointNewSiteCollectionAdmin -ne "PleaceSpecify")
    {
        $owners += $AlyaSharePointNewSiteCollectionAdmin
    }
}

# Setting site admins
Write-Host "Setting site admins" -ForegroundColor $CommandInfo
foreach ($site in $sitesToProcess)
{
    if ($site.Template -like "Redirect*") { continue }
    if (-Not $site.Url.Contains("/sites/") -And $site.Url.TrimEnd("/") -ne $AlyaSharePointUrl.TrimEnd("/")) { continue }

    # Setting site owner
    $ctx = Get-PnPContext -Connection $adminCon
    $ctx.Load($ctx.Web.CurrentUser)
    Invoke-PnPQuery -Connection $adminCon
    Set-PnPTenantSite -Connection $adminCon -Identity $site.Url -Owners $owners

    # Checking if AAD group is assigned
    $tsite = Get-PnPTenantSite -Connection $adminCon -Identity $site.Url -Detailed
    $aadGroup = $tsite.GroupId

    # Checking site owner
    $siteCon = LoginTo-PnP -Url $site.Url
    $pweb = Get-PnPWeb -Connection $siteCon
    $owner = $null
    try {
        if ($aadGroup.Guid -eq [Guid]::Empty.Guid)
        {
            try {
                $site.Context.Load($site.Owner)
                Invoke-PnPQuery -Connection $siteCon
                $owner = $site.Owner
            }
            catch {
                $tuser = $pweb.EnsureUser("c:0t.c|tenant|"+$tsite.Owner)
                $tuser.Context.Load($tuser)
                Invoke-PnPQuery -Connection $siteCon
                $owner = $tuser
            }
        }

        # Getting role groups for actual site
        $gauser = $pweb.EnsureUser($gauserLoginName)
        $gauser.Context.Load($gauser)
        Invoke-PnPQuery -Connection $siteCon

        if ($null -ne $sauserLoginName)
        {
            $sauser = $pweb.EnsureUser($spAdminRoleName)
            $sauser.Context.Load($sauser)
            Invoke-PnPQuery -Connection $siteCon
        }

        # Getting admins
        $admins = @()
        foreach($scAdmin in $AlyaSharePointNewSiteCollectionAdmins)
        {
            if (-Not [string]::IsNullOrEmpty($scAdmin) -and $scAdmin -ne "PleaseSpecify" -and $scAdmin -ne "Please Specify")
            {
                $user = $pweb.EnsureUser($scAdmin)
                $user.Context.Load($user)
                Invoke-PnPQuery -Connection $siteCon
                $admins += $user
            }
        }
        if ($null -ne $sauserLoginName) { $admins += $sauser }

        try {
            if ($owner.LoginName -ne $gauser.LoginName -and $aadGroup.Guid -eq [Guid]::Empty.Guid) {
                $admins += $owner
                $null = Add-PnPSiteCollectionAdmin -Connection $siteCon -PrimarySiteCollectionAdmin $gauser -Owners $admins
            }
            $null = Add-PnPSiteCollectionAdmin -Connection $siteCon -Owners $admins
        }
        catch {
            Write-Error $_.Exception -ErrorAction Continue
            Write-Warning "Do you have the correct rights?"
            pause
        }
    }
    catch {
        Write-Error $_.Exception -ErrorAction Continue
    }
}

# Stopping Transscript
Stop-Transcript
