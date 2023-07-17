#Requires -Version 2.0

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
    21.10.2020 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
    [string]$BuiltInAppsFile = $null #defaults to $($AlyaData)\intune\appsBuiltIn.json
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-BuiltInApps-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
if (-Not [string]::IsNullOrEmpty($AlyaAppPrefix)) {
    $AppPrefix = "$AlyaAppPrefix "
}
else {
    $AppPrefix = "WIN "
}
if (-Not $BuiltInAppsFile)
{
    $BuiltInAppsFile = "$($AlyaData)\intune\appsBuiltIn.json"
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
Write-Host "Intune | Configure-BuiltInApps | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$builtInApps = Get-Content -Path $BuiltInAppsFile -Raw -Encoding UTF8 | ConvertFrom-Json

# Defining bodies
$assBody = @"
[
    {
        "@odata.type": "#Microsoft.Graph.Beta.mobileAppAssignment",
        "intent": "available",
        "source": "direct",
        "sourceId": null,
        "target": {
            "@odata.type": "#Microsoft.Graph.Beta.allLicensedUsersAssignmentTarget",
            "deviceAndAppManagementAssignmentFilterId": null,
            "deviceAndAppManagementAssignmentFilterType": "none"
        }
    }
]
"@
$assignments = $assBody | ConvertFrom-Json
$catBody = @"
{
    "@odata.type": "#Microsoft.Graph.Beta.mobileAppCategory",
    "id": "ed899483-3019-425e-a470-28e901b9790e",
    "displayName": "Productivity"
}
"@
$category = $catBody | ConvertFrom-Json

# Processing defined builtInApps
$hadError = $false
foreach($builtInApp in $builtInApps)
{
    if ($builtInApp.Comment1 -and $builtInApp.Comment2 -and $builtInApp.Comment3) { continue }
    if ($builtInApp.displayName.EndsWith("_unused")) { continue }
    Write-Host "Configuring builtInApp '$($builtInApp.displayName)'" -ForegroundColor $CommandInfo
    
    try {
        
        # Checking if app exists
        Write-Host "  Checking if app exists" -ForegroundColor $CommandInfo
        if (!$AppPrefix.StartsWith("WIN "))
        {   
            $winGetApp.displayName = $winGetApp.displayName.Replace("WIN ", $AppPrefix)
        }
        $searchValue = [System.Web.HttpUtility]::UrlEncode($builtInApp.displayName)
        $uri = "/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$searchValue'"
        $app = (Get-MsGraphObject -Uri $uri).value
        if (-Not $app.id)
        {
            Write-Error "The app with name $($builtInApp.displayName) does not exist. Please create it first." -ErrorAction Continue
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
                $body = "{ `"@odata.id`": `"https://graph.microsoft.com$caturi`" }"
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
        $hadError = $true
    }

}
if ($hadError)
{
    Write-Host "There was an error. Please see above." -ForegroundColor $CommandError
}

#Stopping Transscript
Stop-Transcript
