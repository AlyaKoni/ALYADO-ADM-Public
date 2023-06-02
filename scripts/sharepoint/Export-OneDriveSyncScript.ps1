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
    10.04.2023 Konrad Brunner       Initial Version
    19.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules, TODO test with UseAppAuthentication = true

#>

[CmdletBinding()]
Param(
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Export-OneDriveSyncScript-$($AlyaTimeString).log" | Out-Null

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

# Starting script creation
Write-Host "Starting script creation" -ForegroundColor $CommandInfo
$scriptPath = "$($AlyaData)\sharepoint\Sync-SharePointSites.ps1"
@"
Add-Type -AssemblyName System.Web

`$root = `$null
`$mail = `$null

foreach(`$par in (Get-ChildItem HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts))
{
	`$tenant = Get-ItemPropertyValue -Path `$par.PSPath -Name "ConfiguredTenantId" -ErrorAction SilentlyContinue
	if (`$tenant -eq "5757de31-29c4-4f39-9bd1-478cec348035")
	{
		`$mail = Get-ItemPropertyValue -Path `$par.PSPath -Name "UserEmail"
		`$bname = `$par.PSChildName
		`$tname = Get-ItemPropertyValue -Path `$par.PSPath -Name "DisplayName" -ErrorAction SilentlyContinue
		break
	}
}
if (-Not `$mail)
{
    Write-Error "Kann OneDrive nicht finden! Bitte installiere OneDrive und starte die Synchronisation."
    pause
    exit
}
`$mail = [System.Web.HttpUtility]::UrlEncode(`$mail)

`$syncs = @(
"@ | Set-Content -Path $scriptPath -Encoding utf8 -Force

# OneDrive Sync Url
Write-Host "Getting OneDrive Sync Urls" -ForegroundColor $CommandInfo
$endLine = ","
foreach ($site in $sitesToProcess)
{
    if ($site.Url -notlike "*/sites/*SP-*") { continue }
    if ($site.Template -like "Redirect*") { continue }
    if ($site.Url -eq $sitesToProcess[$sitesToProcess.Length - 1].Url) { $endLine = "" }

    # Login
    Write-Host "$($site.Url)"
    $siteCon = LoginTo-PnP -Url $site.Url

    # Creating ODFB link
    $psite = Get-PnPSite -Connection $siteCon -Includes "ID"
    $pweb = Get-PnPWeb -Connection $siteCon -Includes "ID","Title"
    $plist = Get-PnPList -Connection $siteCon | Where-Object { $_.Title -eq "Dokumente" -or $_.Title -eq "Freigegebene Dokumente" -or $_.Title -eq "Documents" -or $_.Title -eq "Shared Documents" }
    $WebURL = [System.Web.HttpUtility]::UrlEncode("$($psite.Url)")
    $SiteID = [System.Web.HttpUtility]::UrlEncode("{$($psite.Id.Guid)}")
    $WebID = [System.Web.HttpUtility]::UrlEncode("{$($pweb.Id.Guid)}")
    $ListID = [System.Web.HttpUtility]::UrlEncode("{$($plist.Id.Guid)}")
    $WebTitle = [System.Web.HttpUtility]::UrlEncode($pweb.Title)
    $ListTitle = [System.Web.HttpUtility]::UrlEncode($plist.Title)
    $UserName = "`$mail"
    "`t#$($pweb.Title) - $($pweb.ServerRelativeUrl)" `
        | Add-Content -Path $scriptPath -Encoding utf8 -Force
    "`t`"odopen://sync?siteId=$SiteID&webId=$WebID&listId=$ListID&userEmail=$UserName&webUrl=$WebURL&webTitle=$WebTitle&listTitle=$ListTitle&scope=OPENLIST`"$endLine" `
        | Add-Content -Path $scriptPath -Encoding utf8 -Force
}
"`t`"`"" | Add-Content -Path $scriptPath -Encoding utf8 -Force

# Closing script creation
Write-Host "Closing script creation" -ForegroundColor $CommandInfo
@"
)

`$prop = Get-ItemProperty HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\`$bname\Tenants\`$tname -ErrorAction SilentlyContinue
if (`$prop)
{
	`$props = `$prop.PSObject.Properties
	foreach(`$prop in `$props)
	{
		if (-Not `$prop.Name.StartsWith("PS"))
		{
			`$root = Split-Path `$prop.Name -Parent
			break
		}
	}
}
if (-Not `$root)
{
    Write-Warning "Es wurde noch nie eine SahrePoint Seite synchronisiert. Synchronisiere nun erste Seite."
	`$sync = `$syncs[0]
    `$wTitle = `$sync.Substring(`$sync.IndexOf("webTitle=") + 9)
    `$wTitle = `$wTitle.Substring(0, `$wTitle.IndexOf("&"))
    Write-Host "Synchronisiere `$wTitle"
	Start-Process `$sync
	do
	{
		Start-Sleep -Seconds 10
		`$prop = Get-ItemProperty HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\`$bname\Tenants\`$tname -ErrorAction SilentlyContinue
		if (`$prop)
		{
			`$props = `$prop.PSObject.Properties
			foreach(`$prop in `$props)
			{
				if (-Not `$prop.Name.StartsWith("PS"))
				{
					`$root = Split-Path `$prop.Name -Parent
					break
				}
			}
		}
	} while (-Not `$root)
}

foreach(`$sync in `$syncs)
{
    if ([string]::IsNullOrEmpty(`$sync)) { continue }
    `$wTitle = `$sync.Substring(`$sync.IndexOf("webTitle=") + 9)
    `$wTitle = `$wTitle.Substring(0, `$wTitle.IndexOf("&"))
    Write-Host "Synchronisiere `$wTitle"
    `$syncDir = `$root + "\" + `$wTitle + " - Dokumente"
    if (-Not (Test-Path `$syncDir))
    {
        Start-Process `$sync
        do
        {
            Start-Sleep -Seconds 10
        } while (-Not (Test-Path `$syncDir))
    }
	Start-Sleep -Seconds 10
}
"@ | Add-Content -Path $scriptPath -Encoding utf8 -Force

# Done
Write-Host "Script is ready: $scriptPath" -ForegroundColor $CommandSuccess

# Stopping Transscript
Stop-Transcript
