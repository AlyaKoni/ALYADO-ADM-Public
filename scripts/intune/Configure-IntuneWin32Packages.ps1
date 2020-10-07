#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2019, 2020

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
    04.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$ConfigureOnlyAppWithName = $null,
    [string]$ContinueAtAppWithName = $null
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-IntuneWin32Packages-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$AppPrefix = "Win10"
$DataRoot = Join-Path (Join-Path $AlyaData "intune") "Win32Apps"
if (-Not (Test-Path $DataRoot))
{
    $tmp = New-Item -Path $DataRoot -ItemType Directory -Force
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# Getting context and token
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}
$token = Get-AdalAccessToken

# Main
$packages = Get-ChildItem -Path $DataRoot -Directory
$continue = $true
foreach($packageDir in $packages)
{
    if ($ContinueAtAppWithName -and $packageDir.Name -eq $ContinueAtAppWithName) { $continue = $false }
    if ($ContinueAtAppWithName -and $continue) { continue }
    if ($ConfigureOnlyAppWithName -and $packageDir.Name -ne $ConfigureOnlyAppWithName) { continue }
    if ($packageDir.Name -like "*unused*" -or $packageDir.Name -like "*donotuse*") { continue }

    Write-Host "Configuring package $($packageDir.Name)" -ForegroundColor $CommandInfo

    $packagePath = Join-Path $packageDir.FullName "Package"
    $configPath = Join-Path $packageDir.FullName "config.json"
    $categoryPath = Join-Path $packageDir.FullName "category.json"
    $assignmentsPath = Join-Path $packageDir.FullName "assignments.json"

    $config = $null
    $category = $null
    $assignments = $null

    $config = Get-Content -Path $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $category = Get-Content -Path $categoryPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue | ConvertFrom-Json
    $assignments = Get-Content -Path $assignmentsPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue | ConvertFrom-Json

    # Checking if app exists
    Write-Host "  Checking if app exists" -ForegroundColor $CommandInfo
    $searchValue = [System.Web.HttpUtility]::UrlEncode($config.displayName)
    $uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$searchValue'"
    $app = (Get-MsGraphObject -AccessToken $token -Uri $uri).value
    if (-Not $app.id)
    {
        Write-Error "The app with name $($config.displayName) does not exist. Please create it first." -ErrorAction Continue
        continue
    }
    $appId = $app.id
    Write-Host "    appId: $appId"

    # Configuring category
    Write-Host "  Configuring category" -ForegroundColor $CommandInfo
    if ($category)
    {
        # Checking if category exists
        Write-Host "    Checking if category exists"
	    $caturi = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileAppCategories/$($category.id)"
	    $defCategory = Get-MsGraphObject -AccessToken $token -Uri $caturi
        if (-Not $defCategory)
        {
            Write-Error "Can't find the category $($category.displayName)." -ErrorAction Continue
            continue
        }

        # Getting existing categories
        Write-Host "    Getting existing categories"
	    $uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps/$appId/categories"
	    $actCategories = Get-MsGraphCollection -AccessToken $token -Uri $uri
        $isPresent = $actCategories | where { $_.id -eq $category.id }
        if (-Not $isPresent)
        {
            # Adding category
            Write-Host "    Adding category $($defCategory.displayName)"
	        $uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps/$appId/categories/`$ref"
            $body = "{ `"@odata.id`": `"$caturi`" }"
	        $appCat = Post-MsGraph -AccessToken $token -Uri $uri -Body $body
        }
        else
        {
            Write-Host "    Category $($defCategory.displayName) already exists"
        }
    }

    # Configuring assignments
    Write-Host "  Configuring assignments" -ForegroundColor $CommandInfo

    # Getting existing assignments
    Write-Host "    Getting existing assignments"
	$uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps/$appId/assignments"
	$actAssignments = Get-MsGraphCollection -AccessToken $token -Uri $uri
    $cnt = 0
    foreach ($assignment in $assignments)
    {
        $cnt++
        Write-Host "      Assignment $cnt with target $($assignment.target)"
        $fnd = $null
        foreach ($actAssignment in $actAssignments)
        {
            #TODO better handling here
            if ($actAssignment.target."@odata.type" -eq $assignment.target."@odata.type")
            {
                $fnd = $actAssignment
                break
            }
        }
        if (-Not $fnd)
        {
            Write-Host "      Assignment not found. Creating"
            # Adding assignment
            Write-Host "        Adding assignment $($assignment.target."@odata.type")"
	        $uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps/$appId/assignments"
            $body = $assignment | ConvertTo-Json -Depth 50
	        $appCat = Post-MsGraph -AccessToken $token -Uri $uri -Body $body
        }
        else
        {
            Write-Host "      Found existing assignment"
        }
        #TODO Update
    }
}

#Stopping Transscript
Stop-Transcript