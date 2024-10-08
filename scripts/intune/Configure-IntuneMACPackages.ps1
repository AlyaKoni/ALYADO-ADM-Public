﻿#Requires -Version 2.0

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
    28.03.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$ConfigureOnlyAppWithName = $null,
    [string]$ContinueAtAppWithName = $null,
    [string]$AppsPath = "MACApps"
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-IntuneMACPackages-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$DataRoot = Join-Path (Join-Path $AlyaData "intune") $AppsPath
if (-Not (Test-Path $DataRoot))
{
    $null = New-Item -Path $DataRoot -ItemType Directory -Force
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "Directory.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementApps.ReadWrite.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Configure-IntuneMACPackages | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking dependencies
Write-Host "Checking dependencies" -ForegroundColor $MenuColor
$packages = Get-ChildItem -Path $DataRoot -Directory
$continue = $true
foreach($packageDir in $packages)
{
    if ($ContinueAtAppWithName -and $packageDir.Name -eq $ContinueAtAppWithName) { $continue = $false }
    if ($ContinueAtAppWithName -and $continue) { continue }
    if ($ConfigureOnlyAppWithName -and $packageDir.Name -ne $ConfigureOnlyAppWithName) { continue }
    if ($packageDir.Name -like "*unused*" -or $packageDir.Name -like "*donotuse*") { continue }

    $dependenciesPath = Join-Path $packageDir.FullName "dependencies.json"

    if ((Test-Path $dependenciesPath))
    {

        Write-Host "Dependencies for package $($packageDir.Name)" -ForegroundColor $CommandInfo

        $configPath = Join-Path $packageDir.FullName "config.json"
        $config = Get-Content -Path $configPath -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json

        # Checking if app exists
        Write-Host "  Checking if app exists" -ForegroundColor $CommandInfo
        $uri = "/beta/deviceAppManagement/mobileApps"
        $allApps = Get-MsGraphCollection -Uri $uri
        $app = $allApps | where { $_.displayName -eq $config.displayName }
        if (-Not $app.id)
        {
            throw "The app with name $($config.displayName) does not exist. Please create it first."
        }
        $appId = $app.id
        Write-Host "    appId: $appId"

        $dependencies = $null
        $dependencies = Get-Content -Path $dependenciesPath -Raw -Encoding $AlyaUtf8Encoding -ErrorAction SilentlyContinue | ConvertFrom-Json

        Write-Host "  Checking dependencies"
        foreach ($dependency in $dependencies)
        {
            $depPath = Join-Path $DataRoot $dependency.app
            $configPath = Join-Path $depPath "config.json"
            $config = Get-Content -Path $configPath -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json

            # Checking if app exists
            Write-Host "  Checking if app $($config.displayName) exists"
            Add-Member -InputObject $dependency -MemberType NoteProperty -Name "appName" -Value $config.displayName
            $uri = "/beta/deviceAppManagement/mobileApps"
            $allApps = Get-MsGraphCollection -Uri $uri
            $app = $allApps | where { $_.displayName -eq $config.displayName }
                if (-Not $app.id)
            {
                throw "The app with name $($dependency.appName) does not exist. Dependency to $($packageDir.Name) can't be built. Please create it first."
            }
            Add-Member -InputObject $dependency -MemberType NoteProperty -Name "appId" -Value $app.id
        }

        Write-Host "  Getting existing dependencies"
	    $uri = "/beta/deviceAppManagement/mobileApps/$appId/relationships"
	    $actDependencies = (Get-MsGraphObject -Uri $uri).value
        $newDependencies = @()
        if ($actDependencies -and $actDependencies.Count -gt 0)
        {
            foreach ($actDependency in $actDependencies)
            {
                $newDependency = @{ "@odata.type" = "#Microsoft.Graph.mobileAppDependency" }
                $newDependency.targetId = $actDependency.targetId
                $newDependency.dependencyType = $actDependency.dependencyType
                $newDependencies += $newDependency
            }
        }
        foreach ($dependency in $dependencies)
        {
            $fnd = $false
            foreach ($actDependency in $actDependencies)
            {
                if ($actDependency.targetId -eq $dependency.appId)
                {
                    $fnd = $true
                    break
                }
            }
            if (-Not $fnd)
            {
                $newDependency = @{ "@odata.type" = "#Microsoft.Graph.mobileAppDependency" }
                $newDependency.targetId = $dependency.appId
                if ($dependency.autoInstall)
                {
                    $newDependency.dependencyType = "autoInstall"
                }
                else
                {
                    $newDependency.dependencyType = "detect"
                }
                $newDependencies += $newDependency
            }
        }
        $uri = "/beta/deviceAppManagement/mobileApps/$appId/updateRelationships"
        $body = @{}
        $body.relationships = $newDependencies
        $appCat = Post-MsGraph -Uri $uri -Body ($body | ConvertTo-Json -Depth 50)
    }
}

# Configuring other stuff
Write-Host "Configuring other stuff" -ForegroundColor $MenuColor
$packages = Get-ChildItem -Path $DataRoot -Directory
$continue = $true
foreach($packageDir in $packages)
{
    if ($ContinueAtAppWithName -and $packageDir.Name -eq $ContinueAtAppWithName) { $continue = $false }
    if ($ContinueAtAppWithName -and $continue) { continue }
    if ($ConfigureOnlyAppWithName -and $packageDir.Name -ne $ConfigureOnlyAppWithName) { continue }
    if ($packageDir.Name -like "*unused*" -or $packageDir.Name -like "*donotuse*") { continue }

    Write-Host "Configuring package $($packageDir.Name)" -ForegroundColor $CommandInfo

    $configPath = Join-Path $packageDir.FullName "config.json"
    $categoryPath = Join-Path $packageDir.FullName "category.json"
    $assignmentsPath = Join-Path $packageDir.FullName "assignments.json"

    $config = $null
    $category = $null
    $assignments = $null

    $config = Get-Content -Path $configPath -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json
    $category = Get-Content -Path $categoryPath -Raw -Encoding $AlyaUtf8Encoding -ErrorAction SilentlyContinue | ConvertFrom-Json
    $assignments = Get-Content -Path $assignmentsPath -Raw -Encoding $AlyaUtf8Encoding -ErrorAction SilentlyContinue | ConvertFrom-Json

    # Checking if app exists
    Write-Host "  Checking if app exists" -ForegroundColor $CommandInfo
    $uri = "/beta/deviceAppManagement/mobileApps"
    $allApps = Get-MsGraphCollection -Uri $uri
    $app = $allApps | where { $_.displayName -eq $config.displayName }
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
	    $caturi = "/beta/deviceAppManagement/mobileAppCategories/$($category.id)"
	    $defCategory = Get-MsGraphObject -Uri $caturi
        if (-Not $defCategory)
        {
            Write-Error "Can't find the category $($category.displayName)." -ErrorAction Continue
            continue
        }

        # Getting existing categories
        Write-Host "    Getting existing categories"
	    $uri = "/beta/deviceAppManagement/mobileApps/$appId/categories"
	    $actCategories = Get-MsGraphCollection -Uri $uri
        $isPresent = $actCategories | Where-Object { $_.id -eq $category.id }
        if (-Not $isPresent)
        {
            # Adding category
            Write-Host "    Adding category $($defCategory.displayName)"
	        $uri = "/beta/deviceAppManagement/mobileApps/$appId/categories/`$ref"
            $body = "{ `"@odata.id`": `"$AlyaGraphEndpoint$caturi`" }"
	        $appCat = Post-MsGraph -Uri $uri -Body $body
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
	$uri = "/beta/deviceAppManagement/mobileApps/$appId/assignments"
	$actAssignments = Get-MsGraphCollection -Uri $uri
    $cnt = 0
    foreach ($assignment in $assignments)
    {
        $cnt++
        Write-Host "      Assignment $cnt with target $($assignment.target)"
        $fnd = $null
        foreach ($actAssignment in $actAssignments)
        {
            #TODO better handling here
            if ($actAssignment.intent -eq $assignment.intent -and $actAssignment.target."@odata.type" -eq $assignment.target."@odata.type")
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
	        $uri = "/beta/deviceAppManagement/mobileApps/$appId/assignments"
            $body = $assignment | ConvertTo-Json -Depth 50
	        $appCat = Post-MsGraph -Uri $uri -Body $body
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
