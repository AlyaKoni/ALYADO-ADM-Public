#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2022

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
    11.07.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$sharePointDomain,
    [Parameter(Mandatory=$true)]
    [string]$userUpn,
    [Parameter(Mandatory=$true)]
    [string]$centralSite,
    [Parameter(Mandatory=$true)]
    [string[]]$sateliteSites
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\onedrive\Move-UserOneDriveToMultiGeoLocation-$($AlyaTimeString).log" | Out-Null

# Constants
$allSites = $sateliteSites.ToUpper()
$allSites += $centralSite.ToUpper()

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "Microsoft.Online.Sharepoint.PowerShell"
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logging in
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad
LoginTo-SPO

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "OneDrive | Move-UserOneDriveToMultiGeoLocation | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting users prefered data location
Write-Host "Getting users prefered data location" -ForegroundColor $CommandInfo
$res = Invoke-AzRestMethod -Method Get -Uri "https://graph.microsoft.com/beta/users/$($userUpn)?`$select=preferredDataLocation"
$resObj = $res.Content | ConvertFrom-Json
$preferredDatalocation = $resObj.preferredDatalocation
if ($resObj.error)
{
    throw $res.Content
}
if ([string]::IsNullOrEmpty($preferredDatalocation))
{
    throw "User $userUpn does not have a preferredDatalocation set!"
}
if ($preferredDatalocation -notin $allSites)
{
    throw "Users preferredDatalocation $preferredDatalocation is not supported!"
}
$preferredDatalocation = $preferredDatalocation.ToUpper()
Write-Host "Users preferredDatalocation is $preferredDatalocation"

Write-Warning "Please wait at least 24h after changing the prefferedDataLocation attribute until you use this script!"
pause

# Getting users actual onedrive location
Write-Host "Getting users actual onedrive location" -ForegroundColor $CommandInfo
$mySite = null
foreach($site in $allSites)
{
    $adminUrl = $AlyaSharePointAdminUrl
    if ($site -ne $centralSite.ToUpper())
    {
        $adminUrl = $AlyaSharePointAdminUrl.Replace("-admin", $site+"-admin")
    }
    $con = LoginTo-PnP -Url $AlyaSharePointAdminUrl
    $mySiteTst = (Get-PnPUserProfileProperty -Connection $con -Account $userUpn).PersonalUrl
    if ($mySiteTst -like "*/personal/*")
    {
        $mySite = $mySiteTst
    }
}
if (-Not $mySite)
{
    throw "Looks like the user does not have a OneDrive site!"
}
Write-Host "Users mySite is $mySite"
if ($preferredDatalocation -in $sateliteSites -and $mySite.IndexOf($preferredDatalocation.ToLower()+"-my.sharepoint.com") -gt -1)
{
    Write-Host "Users OneDrive location is already in the right location!"
    exit 0
}
if ($preferredDatalocation -eq $centralSite.ToUpper() -and $mySite.IndexOf($sharePointDomain.ToLower()+"-my.sharepoint.com") -gt -1)
{
    Write-Host "Users OneDrive location is already in the right location!"
    exit 0
}

# Getting multi geo status
Write-Host "Getting multi geo status" -ForegroundColor $CommandInfo
$status = Get-SPOGeoMoveCrossCompatibilityStatus | where { $_.DestinationDataLocation -eq $preferredDatalocation -and $_.CompatibilityStatus -ne "Compatible" }
if ($status)
{
    $status
    pause
    throw "Multi Geo not ready for $preferredDatalocation. Please wait or contact an administrator!"
}

# Validating content move
Write-Host "Validating content move" -ForegroundColor $CommandInfo
$validation = Start-SPOUserAndContentMove -UserPrincipalName $userUpn -DestinationDataLocation $preferredDatalocation -ValidationOnly
if ($validation.ValidationState -ne "Success")
{
    throw "Users OneDrive location can't be moved! Does there any subsite exit or is a retention label applied?"
}

# Starting content move
Write-Host "Starting content move" -ForegroundColor $CommandInfo
Start-SPOUserAndContentMove -UserPrincipalName $userUpn -DestinationDataLocation $preferredDatalocation

# Checking content move status
Write-Host "Checking content move status" -ForegroundColor $CommandInfo
$lastState = $null
do
{
    $state = Get-SPOUserAndContentMoveState -UserPrincipalName $userUpn
    if ($state.MoveState -ne $lastState)
    {
        Write-Host "Status: $($state.MoveState)"
    }
    $lastState = $state.MoveState
    Start-Sleep -Seconds 10
} while (-Not ($state.MoveState -eq "Success" -or $state.MoveState -eq "Failed"))
$state = Get-SPOUserAndContentMoveState -UserPrincipalName $userUpn
Write-Host "Final state: $($state.MoveState)"

#Stopping Transscript
Stop-Transcript