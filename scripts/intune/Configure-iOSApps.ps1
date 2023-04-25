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
    27.10.2020 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
    [string]$IOSAppsFile = $null #defaults to $($AlyaData)\intune\appsIOS.json
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-iOSApps-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
if (-Not $IOSAppsFile)
{
    $IOSAppsFile = "$($AlyaData)\intune\appsIOS.json"
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
Write-Host "Intune | Configure-iOSApps | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$iosApps = Get-Content -Path $IOSAppsFile -Raw -Encoding UTF8 | ConvertFrom-Json

# Defining bodies
$assBody = @"
[
    {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "intent": "available",
        "source": "direct",
        "sourceId": null,
        "target": {
            
            "@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget",
            "deviceAndAppManagementAssignmentFilterId": null,
            "deviceAndAppManagementAssignmentFilterType": "none"
        }
    }
]
"@
$assignments = $assBody | ConvertFrom-Json

# Processing defined iosApps
$hadError = $false
foreach($iosApp in $iosApps)
{
    if ($iosApp.displayName.EndsWith("_unused")) { continue }
    Write-Host "Configuring iosApp $($iosApp.displayName)" -ForegroundColor $CommandInfo
    
    try {
        
        # Checking if app exists
        Write-Host "  Checking if app exists" -ForegroundColor $CommandInfo
        $searchValue = [System.Web.HttpUtility]::UrlEncode($iosApp.displayName)
        $uri = "/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$searchValue'"
        $app = (Get-MsGraphObject -Uri $uri).value
        if (-Not $app.id)
        {
            Write-Error "The app with name $($iosApp.displayName) does not exist. Please create it first." -ErrorAction Continue
            $hadError = $true
            continue
        }
        $appId = $app.id
        Write-Host "    appId: $appId"

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
                try
                {
                    $appCat = Post-MsGraph -Uri $uri -Body $body
                }
                catch
                {
                    $hadError = $true
                    try { Write-Host $_.Exception -ForegroundColor $CommandError } catch {}
                    continue
                }
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
