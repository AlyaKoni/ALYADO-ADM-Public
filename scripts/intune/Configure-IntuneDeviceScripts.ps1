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
    20.10.2020 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph
    05.09.2023 Konrad Brunner       Added assignment
    27.03.2024 Konrad Brunner       Added MAC scripts
    19.06.2024 Konrad Brunner       Fixed MAC line endings

#>

[CmdletBinding()]
Param(
    [string]$ScriptDir = $null, #defaults to $($AlyaData)\intune\Scripts,
    [bool]$OnlyProcessShellScripts = $false
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-IntuneDeviceScripts-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$AppPrefix = "WIN "
$AppPrefixMac = "MAC "
if (-Not [string]::IsNullOrEmpty($AlyaAppPrefix)) {
    $AppPrefix = "$AlyaAppPrefix "
}
if (-Not $ScriptDir)
{
    $ScriptDir = "$($AlyaData)\intune\Scripts"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"

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
$scripts = Get-ChildItem -File -Path $ScriptDir -Filter "*.ps1"
$scripts += Get-ChildItem -File -Path $ScriptDir -Filter "*.sh" | Where-Object { $_.name -notlike "*.customattribute.*" }

# Processing scripts
$hadError = $false
foreach($script in $scripts)
{
    if ($script.Name.IndexOf("_unused") -gt -1) { continue }
    Write-Host "Configuring script '$($script.Name)'" -ForegroundColor $CommandInfo

    try {
        
        if ($script.Name.EndsWith("ps1"))
        {
            if ($OnlyProcessShellScripts) { continue }

            # Loading script
            Write-Host "  Loading script"
            $scriptResponse = [System.IO.File]::ReadAllBytes($script)
            $base64script = [System.Convert]::ToBase64String($scriptResponse)
            #TODO Description out of the script?

            $scriptName = "$AppPrefix$($script.BaseName)"
            #"@odata.type": "#Microsoft.Graph.deviceManagementScript",
            $body = @"
{
    "displayName": "$scriptName",
    "description": "",
    "runSchedule": {
        "@odata.type": "Microsoft.Graph.Beta.runSchedule"
    },
    "scriptContent": "$base64script",
    "runAsAccount": "system",
    "runAs32Bit": false,
    "enforceSignatureCheck": false,
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
        else
        {

            # Loading script
            Write-Host "  Loading script"
            $scriptContent = Get-Content -Path $script -Raw
            $scriptContent = $scriptContent.Replace("`r`n","`n")
            $scriptBytes = [System.Text.Encoding]::UTF8.GetBytes($scriptContent)
            $base64script = [System.Convert]::ToBase64String($scriptBytes)
            #TODO Description out of the script?

            $scriptName = "$AppPrefixMac$($script.BaseName)"
            #"@odata.type": "#Microsoft.Graph.deviceShellScript",
            $body = @"
{
    "displayName": "$scriptName",
    "description": "",
    "executionFrequency": "P7D",
    "scriptContent": "$base64script",
    "runAsAccount": "system",
    "retryCount": 3,
    "blockExecutionNotifications": true,
    "fileName": "$($script.Name)"
}
"@

            # Checking if script exists
            Write-Host "  Checking if script exists"
            $uri = "/beta/deviceManagement/deviceShellScripts"
            $actScript = (Get-MsGraphObject -Uri $uri).value | Where-Object { $_.displayName -eq $scriptName}
            if (-Not $actScript.id)
            {
                # Creating the script
                Write-Host "    Script does not exist, creating"
                $uri = "/beta/deviceManagement/deviceShellScripts"
                $actScript = Post-MsGraph -Uri $uri -Body $body
            }

            # Updating the script
            Write-Host "    Updating the script"
            $uri = "/beta/deviceManagement/deviceShellScripts/$($actScript.id)"
            $actScript = Patch-MsGraph -Uri $uri -Body $body

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

# Assigning defined profiles
$sGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-WINMDM'"
$sGroup365 = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-WIN365MDM'"
$sGroupMac = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-MACMDM'"
foreach($script in $scripts)
{
    if ($script.Name.IndexOf("_unused") -gt -1) { continue }
    Write-Host "Assigning script '$($script.Name)'" -ForegroundColor $CommandInfo

    try {
        
        if ($script.Name.EndsWith("ps1"))
        {
            if ($OnlyProcessShellScripts) { continue }

            # Checking if script exists
            Write-Host "  Checking script"
            $scriptName = "$AppPrefix$($script.BaseName)"
            $uri = "/beta/deviceManagement/deviceManagementScripts"
            $actScript = (Get-MsGraphObject -Uri $uri).value | Where-Object { $_.displayName -eq $scriptName}
            if ($actScript.id)
            {
                $tGroups = @()
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-WINMDM not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
                if (-Not $sGroup365) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-WINMDM not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup365
                }
                if ($tGroups.Count -gt 0) { 
                    $uri = "/beta/deviceManagement/deviceManagementScripts/$($actScript.id)/groupAssignments"
                    $asses = (Get-MsGraphObject -Uri $uri).value
                    $Targets = @()
                    foreach($tGroup in $tGroups) {
                        $GroupAssignment = New-Object -TypeName PSObject -Property @{
                            "@odata.type" = "#Microsoft.Graph.deviceManagementScriptGroupAssignment"
                            "targetGroupId" = $tGroup.Id
                            "id" = $actScript.id
                        }
                        $Targets += $GroupAssignment
                    }
                    foreach($ass in $asses) {
                        if ($ass.targetGroupId -notin $tGroups.Id)
                        {
                            $Targets += $ass.target
                        }
                    }
                    $Assignment = New-Object -TypeName PSObject -Property @{
                        "deviceManagementScriptGroupAssignments" = $Targets
                    }
                    $body = ConvertTo-Json -InputObject $Assignment -Depth 10
                    $uri = "/beta/deviceManagement/deviceManagementScripts/$($actScript.id)/assign"
                    Post-MsGraph -Uri $uri -Body $body
                }
            } else {
                Write-Host "Not found!" -ForegroundColor $CommandError
            }

        }
        else
        {

            # Checking if script exists
            Write-Host "  Checking script"
            $scriptName = "$AppPrefixMac$($script.BaseName)"
            $uri = "/beta/deviceManagement/deviceShellScripts"
            $actScript = (Get-MsGraphObject -Uri $uri).value | Where-Object { $_.displayName -eq $scriptName}
            if ($actScript.id)
            {
                if (-Not $sGroupMac) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-MACMDM not found. Can't create assignment."
                } else {
                    $uri = "/beta/deviceManagement/deviceShellScripts/$($actScript.id)/groupAssignments"
                    $asses = (Get-MsGraphObject -Uri $uri).value
                    $ass = $asses | Where-Object { $_.target.groupId -eq $sGroupMac.Id }
                    if (-Not $ass) {
                        $GroupAssignment = New-Object -TypeName PSObject -Property @{
                            "@odata.type" = "#Microsoft.Graph.deviceManagementScriptGroupAssignment"
                            "targetGroupId" = $sGroupMac.Id
                            "id" = $actScript.id
                        }
                        $Assignment = New-Object -TypeName PSObject -Property @{
                            "deviceManagementScriptGroupAssignments" = @($GroupAssignment)
                        }
                        $body = ConvertTo-Json -InputObject $Assignment -Depth 10
                        $uri = "/beta/deviceManagement/deviceShellScripts/$($actScript.id)/assign"
                        Post-MsGraph -Uri $uri -Body $body
                    }
                }
            } else {
                Write-Host "Not found!" -ForegroundColor $CommandError
            }

        }
    }
    catch {
        Write-Error $_.Exception -ErrorAction Continue
        $hadError = $true
    }

}

#Stopping Transscript
Stop-Transcript
