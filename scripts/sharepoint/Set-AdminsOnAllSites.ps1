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
$siteCon = LoginTo-PnP -Url $AlyaSharePointUrl
$web = Get-PnPWeb -Connection $siteCon

$gauser = $web.EnsureUser("Company Administrator")
$gauser.Context.Load($gauser)
Invoke-PnPQuery -Connection $siteCon
$gauserLoginName = $gauser.LoginName

$spAdminRoleName = "SharePoint Service Administrator"
try {
    $sauser = $web.EnsureUser($spAdminRoleName)
    $sauser.Context.Load($sauser)
    Invoke-PnPQuery -Connection $siteCon
    $sauserLoginName = $sauser.LoginName
}
catch {
    $spAdminRoleName = "SharePoint Administrator"
    $sauser = $web.EnsureUser($spAdminRoleName)
    $sauser.Context.Load($sauser)
    Invoke-PnPQuery -Connection $siteCon
    $sauserLoginName = $sauser.LoginName
}

# Setting site admins
Write-Host "Setting site admins" -ForegroundColor $CommandInfo
foreach ($site in $sitesToProcess)
{
    if ($site.Template -like "Redirect*") { continue }
    if (-Not $site.Url.Contains("/sites/") -And $site.Url.TrimEnd("/") -ne $AlyaSharePointUrl.TrimEnd("/")) { continue }

    # Checking site owner
    Set-PnPTenantSite -Connection $adminCon -Identity $site.Url -Owners @($gauserLoginName,$sauserLoginName)

    # Checking site owner
    $siteCon = LoginTo-PnP -Url $site.Url
    $web = Get-PnPWeb -Connection $siteCon
    $site = Get-PnPSite -Connection $siteCon
    $site.Context.Load($site.Owner)
    Invoke-PnPQuery -Connection $siteCon

    # Getting role groups for actual site
    $gauser = $web.EnsureUser("Company Administrator")
    $gauser.Context.Load($gauser)
    Invoke-PnPQuery -Connection $siteCon

    $sauser = $web.EnsureUser($spAdminRoleName)
    $sauser.Context.Load($sauser)
    Invoke-PnPQuery -Connection $siteCon

    # Getting admins
    $admins = @()
    foreach($scAdmin in $AlyaSharePointNewSiteCollectionAdmins)
    {
        if (-Not [string]::IsNullOrEmpty($scAdmin) -and $scAdmin -ne "PleaseSpecify" -and $scAdmin -ne "Please Specify")
        {
            $user = $web.EnsureUser($scAdmin)
            $user.Context.Load($user)
            Invoke-PnPQuery -Connection $siteCon
            $admins += $user
        }
    }
    $admins += $sauser

    try {
        if ($site.Owner.LoginName -ne $gauser.LoginName) {
            $admins += $site.Owner
            $null = Add-PnPSiteCollectionAdmin -Connection $siteCon -PrimarySiteCollectionAdmin $gauser
        }
        $null = Add-PnPSiteCollectionAdmin -Connection $siteCon -Owners $admins
    }
    catch {
        Write-Error $_.Exception -ErrorAction Continue
        Write-Warning "Do you have the correct rights?"
        pause
    }
}

# Stopping Transscript
Stop-Transcript
