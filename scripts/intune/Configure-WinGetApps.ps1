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
    26.05.2023 Konrad Brunner       Initial Version
    12.12.2023 Konrad Brunner       Removed $filter odata query, was throwing bad request

#>

[CmdletBinding()]
Param(
    [string]$WinGetAppsFile = $null #defaults to $($AlyaData)\intune\appsWinGet.json
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-WinGetApps-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
if (-Not [string]::IsNullOrEmpty($AlyaAppPrefix)) {
    $AppPrefix = "$AlyaAppPrefix "
}
else {
    $AppPrefix = "WIN "
}
if (-Not $WinGetAppsFile)
{
    $WinGetAppsFile = "$($AlyaData)\intune\appsWinGet.json"
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
Write-Host "Intune | Configure-WinGetApps | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$winGetApps = Get-Content -Path $WinGetAppsFile -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json

# Defining bodies
$assBody = @"
[
    {
        "@odata.type": "#Microsoft.Graph.mobileAppAssignment",
        "intent": "available",
        "source": "direct",
        "sourceId": null,
        "target": {
            "@odata.type": "#Microsoft.Graph.allLicensedUsersAssignmentTarget",
            "deviceAndAppManagementAssignmentFilterId": null,
            "deviceAndAppManagementAssignmentFilterType": "none"
        }
    }
]
"@
$assignments = $assBody | ConvertFrom-Json
$assBodyReq = @"
[
    {
        "@odata.type": "#Microsoft.Graph.mobileAppAssignment",
        "intent": "required",
        "source": "direct",
        "sourceId": null,
        "target": {
            "@odata.type": "#Microsoft.Graph.allLicensedUsersAssignmentTarget",
            "deviceAndAppManagementAssignmentFilterId": null,
            "deviceAndAppManagementAssignmentFilterType": "none"
        }
    }
]
"@
$assignmentsReq = $assBodyReq | ConvertFrom-Json
$catBody = @"
{
    "@odata.type": "#Microsoft.Graph.mobileAppCategory",
    "id": "ed899483-3019-425e-a470-28e901b9790e",
    "displayName": "Productivity"
}
"@
$category = $catBody | ConvertFrom-Json

# Getting all apps
$uri = "/beta/deviceAppManagement/mobileApps"
$allApps = Get-MsGraphCollection -Uri $uri

# Processing defined winGetApps
$hadError = $false
foreach($winGetApp in $winGetApps)
{
    if ($winGetApp.Comment1 -and $winGetApp.Comment2 -and $winGetApp.Comment3) { continue }
    if ($winGetApp.displayName.EndsWith("_unused")) { continue }
    Write-Host "Configuring winGetApp '$($winGetApp.displayName)'" -ForegroundColor $CommandInfo
    
    try {
        
        # Checking if app exists
        Write-Host "  Checking if app exists" -ForegroundColor $CommandInfo
        if (!$AppPrefix.StartsWith("WIN "))
        {   
            $winGetApp.displayName = $winGetApp.displayName.Replace("WIN ", $AppPrefix)
        }
        $app = $allApps | where { $_.displayName -eq $winGetApp.displayName -and $_."@odata.type" -eq "#microsoft.graph.winGetApp"}
        if (-Not $app.id)
        {
            Write-Error "The app with name $($winGetApp.displayName) does not exist. Please create it first." -ErrorAction Continue
            $hadError = $true
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
                $hadError = $true
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

        $asses = $assignments
        if ($winGetApp.displayName -like "*Company Portal*") {
            $asses = $assignmentsReq
        }

        foreach ($assignment in $asses)
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
    catch {
        Write-Error $_.Exception -ErrorAction Continue
        $hadError = $true
    }

}
if ($hadError)
{
    Write-Host "There was an error. Please see above." -ForegroundColor $CommandError
}

#Stopping Transscript
Stop-Transcript
