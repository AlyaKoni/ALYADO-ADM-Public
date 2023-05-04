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
    20.10.2020 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
    [string]$ScriptDir = $null #defaults to $($AlyaData)\intune\Scripts
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-IntuneDeviceScripts-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
if (-Not $ScriptDir)
{
    $ScriptDir = "$($AlyaData)\intune\Scripts"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "DeviceManagementServiceConfig.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.Read.All",
    "Directory.Read.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Configure-IntuneDeviceScripts | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$scripts = Get-ChildItem -Path $ScriptDir -Filter "*.ps1"

# Processing scripts
$hadError = $false
foreach($script in $scripts)
{
    if ($script.Name.IndexOf("_unused") -gt -1) { continue }
    Write-Host "Configuring script '$($script.Name)'" -ForegroundColor $CommandInfo

    try {
        
        # Loading script
        Write-Host "  Loading script"
        $scriptResponse = [System.IO.File]::ReadAllBytes("$($brandingLogoLight)")
        $base64script = [System.Convert]::ToBase64String($scriptResponse)
        #TODO Description out of the script?
        $scriptName = "WIN $($script.BaseName)"
        $body = @"
{
    "@odata.type": "#microsoft.graph.deviceManagementScript",
    "displayName": "$scriptName",
    "description": "",
    "runSchedule": {
        "@odata.type": "microsoft.graph.runSchedule"
    },
    "scriptContent": "$base64script",
    "runAsAccount": "system",
    "enforceSignatureCheck": "false",
    "fileName": "$($script.Name)"
}
"@

        # Checking if script exists
        Write-Host "  Checking if script exists"
        $uri = "/beta/deviceManagement/deviceManagementScripts"
        $actScript = (Get-MsGraphObject -Uri $uri).value | Where-Object { $_.displayName -eq $scriptName}
        if (-Not $actScript.id)
        {
            # Creating the script
            Write-Host "    Script does not exist, creating"
            $uri = "/beta/deviceManagement/deviceManagementScripts"
            $actScript = Post-MsGraph -Uri $uri -Body $body
        }

        # Updating the script
        Write-Host "    Updating the script"
        $uri = "/beta/deviceManagement/deviceManagementScripts/$($actScript.id)"
        $actScript = Patch-MsGraph -Uri $uri -Body $body
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
