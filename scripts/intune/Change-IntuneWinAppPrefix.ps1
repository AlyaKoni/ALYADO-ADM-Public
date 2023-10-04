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
    21.09.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Change-IntuneWinAppPrefix-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$renamers = @(
    @{
        "B" = "Win10"
        "A" = "WIN"
    },
    @{
        "B" = "Android"
        "A" = "AND"
    },
    @{
        "B" = "Mac"
        "A" = "MAC"
    },
    @{
        "B" = "iOS"
        "A" = "IOS"
    }
)


$ActAppPrefix = "Win10 "
if (-Not [string]::IsNullOrEmpty($AlyaAppPrefix)) {
    $ActAppPrefix = "$AlyaAppPrefix "
}
$NewAppPrefix = "WIN "

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "Directory.ReadWrite.All",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "DeviceManagementServiceConfig.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementApps.ReadWrite.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Change-IntuneWinAppPrefix | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting list of all apps
Write-Host "Getting list of all apps" -ForegroundColor $CommandInfo
$uri = "/beta/deviceAppManagement/mobileApps"
$apps = (Get-MsGraphCollection -Uri $uri)
if (-Not $apps -or $apps.Count -eq 0)
{
    throw "No apps found!."
}

# Renaming apps
Write-Host "Renaming apps" -ForegroundColor $CommandInfo
foreach($app in $apps)
{
    $dirty = $false
    foreach($renamer in $renamers)
    {
        if ($app.displayName.StartsWith($renamer.B+" "))
        {
            $newName = $renamer.A + $app.displayName.Substring($renamer.B.Length)
            $dirty = $true
        }
    }
    if ($dirty -and $app.displayName -eq $newName)
    {
        $dirty = $false
    }
    if ($dirty)
    {
        Write-Host "Renaming app '$($app.displayName)' to '$($newName)'"
        $body = @"
{
    "@odata.type": "$($app."@odata.type")",
    "displayName": "$($newName)"
}
"@
        $uri = "/beta/deviceAppManagement/mobileApps/$appId"
        $null = Patch-MsGraph -Uri $uri -Body $body
    }
}

# Getting list of all configuration profiles
Write-Host "Getting list of all configuration profiles" -ForegroundColor $CommandInfo
$uri = "/beta/deviceManagement/deviceConfigurations"
$profs = (Get-MsGraphCollection -Uri $uri)
if (-Not $profs -or $profs.Count -eq 0)
{
    throw "No profiles found!."
}

# Renaming configuration profiles
Write-Host "Renaming profiles" -ForegroundColor $CommandInfo
foreach($prof in $profs)
{
    $dirty = $false
    foreach($renamer in $renamers)
    {
        if ($prof.displayName.StartsWith($renamer.B+" "))
        {
            $newName = $renamer.A + $prof.displayName.Substring($renamer.B.Length)
            $dirty = $true
        }
    }
    if ($dirty)
    {
        Write-Host "Renaming profile '$($prof.displayName)' to '$($newName)'"
        $prof.displayName = $newName
        $prof."@odata.type"
        $profId = $prof.id
        $body = @"
{
    "@odata.type": "$($prof."@odata.type")",
    "displayName": "$($newName)"
}
"@
        $uri = "/beta/deviceManagement/deviceConfigurations/$profId"
        $null = Patch-MsGraph -Uri $uri -Body $body
    }
}

# Getting list of all policy configurations
Write-Host "Getting list of all policy configurations" -ForegroundColor $CommandInfo
$uri = "/beta/deviceManagement/groupPolicyConfigurations"
$profs = (Get-MsGraphCollection -Uri $uri)
if (-Not $profs -or $profs.Count -eq 0)
{
    throw "No profiles found!."
}

# Renaming policy configurations
Write-Host "Renaming policy configurations" -ForegroundColor $CommandInfo
foreach($prof in $profs)
{
    $dirty = $false
    foreach($renamer in $renamers)
    {
        if ($prof.displayName.StartsWith($renamer.B+" "))
        {
            $newName = $renamer.A + $prof.displayName.Substring($renamer.B.Length)
            $dirty = $true
        }
    }
    if ($dirty)
    {
        Write-Host "Renaming policy configuration '$($prof.displayName)' to '$($newName)'"
        $prof.displayName = $newName
        $prof."@odata.type"
        $profId = $prof.id
        $body = @"
{
    "displayName": "$($newName)"
}
"@
        $uri = "/beta/deviceManagement/groupPolicyConfigurations/$profId"
        $null = Patch-MsGraph -Uri $uri -Body $body
    }
}

# Getting list of all quality update profiles
Write-Host "Getting list of all quality update profiles" -ForegroundColor $CommandInfo
$uri = "/beta/deviceManagement/windowsQualityUpdateProfiles"
$profs = (Get-MsGraphCollection -Uri $uri)
if (-Not $profs -or $profs.Count -eq 0)
{
    throw "No profiles found!."
}

# Renaming quality update profiles
Write-Host "Renaming quality update profiles" -ForegroundColor $CommandInfo
foreach($prof in $profs)
{
    $dirty = $false
    foreach($renamer in $renamers)
    {
        if ($prof.displayName.StartsWith($renamer.B+" "))
        {
            $newName = $renamer.A + $prof.displayName.Substring($renamer.B.Length)
            $dirty = $true
        }
    }
    if ($dirty)
    {
        Write-Host "Renaming quality update profile '$($prof.displayName)' to '$($newName)'"
        $prof.displayName = $newName
        $prof."@odata.type"
        $profId = $prof.id
        $body = @"
{
    "displayName": "$($newName)",
}
"@
        $uri = "/beta/deviceManagement/windowsQualityUpdateProfiles/$profId"
        $null = Patch-MsGraph -Uri $uri -Body $body
    }
}

# Getting list of all compliance policies
Write-Host "Getting list of all compliance policies" -ForegroundColor $CommandInfo
$uri = "/beta/deviceManagement/deviceCompliancePolicies"
$profs = (Get-MsGraphCollection -Uri $uri)
if (-Not $profs -or $profs.Count -eq 0)
{
    throw "No profiles found!."
}

# Renaming compliance policies
Write-Host "Renaming compliance policies" -ForegroundColor $CommandInfo
foreach($prof in $profs)
{
    $dirty = $false
    foreach($renamer in $renamers)
    {
        if ($prof.displayName.StartsWith($renamer.B+" "))
        {
            $newName = $renamer.A + $prof.displayName.Substring($renamer.B.Length)
            $dirty = $true
        }
    }
    if ($dirty)
    {
        Write-Host "Renaming compliance policy '$($prof.displayName)' to '$($newName)'"
        $prof.displayName = $newName
        $prof.PSObject.Properties.Remove("localActions")
        $prof.PSObject.Properties.Remove("scheduledActionsForRule")
        $prof."@odata.type"
        $profId = $prof.id
        $uri = "/beta/deviceManagement/deviceCompliancePolicies/$profId"
        $null = Patch-MsGraph -Uri $uri -Body ($prof | ConvertTo-Json -Depth 50)
    }
}

# Getting list of all device scripts
Write-Host "Getting list of all device scripts" -ForegroundColor $CommandInfo
$uri = "/beta/deviceManagement/deviceManagementScripts"
$profs = (Get-MsGraphCollection -Uri $uri)
if (-Not $profs -or $profs.Count -eq 0)
{
    throw "No profiles found!."
}

# Renaming device scripts
Write-Host "Renaming device scripts" -ForegroundColor $CommandInfo
foreach($prof in $profs)
{
    $dirty = $false
    foreach($renamer in $renamers)
    {
        if ($prof.displayName.StartsWith($renamer.B+" "))
        {
            $newName = $renamer.A + $prof.displayName.Substring($renamer.B.Length)
            $dirty = $true
        }
    }
    if ($dirty)
    {
        Write-Host "Renaming device script '$($prof.displayName)' to '$($newName)'"
        $prof.displayName = $newName
        $prof.PSObject.Properties.Remove("localActions")
        $prof.PSObject.Properties.Remove("scheduledActionsForRule")
        $prof."@odata.type"
        $profId = $prof.id
        $body = @"
{
    "displayName": "$($newName)",
}
"@
        $uri = "/beta/deviceManagement/deviceManagementScripts/$profId"
        $null = Patch-MsGraph -Uri $uri -Body $body
    }
}

if ($AlyaAppPrefix -ne "WIN")
{
    Write-Warning "Please change `$AlyaAppPrefix to WIN in $($AlyaData)\ConfigureEnv.ps1"
}

#Stopping Transscript
Stop-Transcript
