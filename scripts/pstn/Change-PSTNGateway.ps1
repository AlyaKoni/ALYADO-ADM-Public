#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    28.09.2026 Konrad Brunner       Initial Version

#>

<#
.SYNOPSIS
Migrates the Microsoft Teams PSTN connectivity from an old SBC (Session Border Controller) gateway to a new one.

.DESCRIPTION
The Change-PSTNGateway.ps1 script switches the tenant PSTN configuration from an existing gateway FQDN to a new
gateway FQDN (e.g. when moving to a new PSTN provider). It verifies that the new FQDN resolves via DNS and is
properly registered and enabled in the tenant verified domains list, reads the settings of the old gateway
(SIP signaling port, max concurrent sessions, ForwardPai, ForwardCallHistory and trunk translation rules),
creates or updates the new gateway with these settings, migrates all trunk translation rules, re-points all
voice routes referencing the old gateway to the new gateway and finally disables (or optionally removes) the
old gateway. As the last step it updates the $AlyaPstnGateway (and optionally $AlyaPstnPort) entry in the
data\ConfigureEnv.ps1 configuration file, so that all other PSTN scripts automatically use the new gateway.

.INPUTS
None.

.OUTPUTS
The script writes status and progress information to the console and a log file. It does not return any objects.

.PARAMETER OldGatewayFqdn
The FQDN of the existing (old) PSTN gateway, e.g. "t619904.sip4teams.ch".

.PARAMETER NewGatewayFqdn
The FQDN of the new PSTN gateway provided by the new provider.

.PARAMETER NewSipSignalingPort
Optional. The SIP signaling port of the new gateway. If not specified, the port of the old gateway is reused,
or the configured $AlyaPstnPort value, if the old gateway does not exist. If specified and different from the
configured value, the $AlyaPstnPort entry in data\ConfigureEnv.ps1 is updated as well.

.PARAMETER RemoveOldGateway
Optional. If set to $true, the old gateway is removed from the tenant instead of only being disabled.
Defaults to $false (disable only, so a rollback stays possible).

.EXAMPLE
PS> .\Change-PSTNGateway.ps1 -OldGatewayFqdn "t619904.sip4teams.ch" -NewGatewayFqdn "sbc.newprovider.ch"
Verifies and registers the new gateway, migrates translation rules and voice routes, disables the old gateway
and updates data\ConfigureEnv.ps1.

.EXAMPLE
PS> .\Change-PSTNGateway.ps1 -OldGatewayFqdn "t619904.sip4teams.ch" -NewGatewayFqdn "sbc.newprovider.ch" -NewSipSignalingPort 5061 -RemoveOldGateway:$true
Same as above, but uses SIP signaling port 5061 for the new gateway and removes the old gateway afterwards.

.NOTES
Copyright          : (c) Alya Consulting, 2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$OldGatewayFqdn,

    [Parameter(Mandatory = $true)]
    [string]$NewGatewayFqdn,

    [Parameter()]
    [int]$NewSipSignalingPort = 0,

    [Parameter()]
    [bool]$RemoveOldGateway = $false
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\pstn\Change-PSTNGateway-$($AlyaTimeString).log" | Out-Null

# Checking input
$OldGatewayFqdn = $OldGatewayFqdn.Trim().ToLowerInvariant()
$NewGatewayFqdn = $NewGatewayFqdn.Trim().ToLowerInvariant()
if ($OldGatewayFqdn -eq $NewGatewayFqdn)
{
    Write-Host "Old and new gateway FQDN are identical ($OldGatewayFqdn). Nothing to do." -ForegroundColor Red
    Stop-Transcript
    exit 1
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MicrosoftTeams"

# Logins
LoginTo-Teams

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "PSTN | Change-PSTNGateway | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
Write-Host "Changing PSTN gateway from $OldGatewayFqdn to $NewGatewayFqdn" -ForegroundColor $CommandInfo
if ($AlyaPstnGateway -ne $OldGatewayFqdn)
{
    Write-Warning "The configured `$AlyaPstnGateway ($AlyaPstnGateway) does not match the given old gateway FQDN ($OldGatewayFqdn)."
    Write-Warning "Please double check your input. The configuration file will be updated to the new gateway FQDN anyway."
}

# Check, that the new FQDN resolves
Write-Host "Checking DNS resolution of the new gateway $NewGatewayFqdn" -ForegroundColor $CommandInfo
try
{
    $newGatewayAddresses = [System.Net.Dns]::GetHostAddresses($NewGatewayFqdn)
    if (-Not $newGatewayAddresses -or $newGatewayAddresses.Count -lt 1)
    {
        Write-Host "The new gateway FQDN $NewGatewayFqdn does not resolve to any IP address" -ForegroundColor Red
        Write-Host "Please check the DNS entry of your new provider before running this script again" -ForegroundColor Red
        Stop-Transcript
        exit 2
    }
    foreach ($newGatewayAddress in $newGatewayAddresses)
    {
        Write-Host "  Resolved to $($newGatewayAddress.ToString())"
    }
}
catch
{
    Write-Host "The new gateway FQDN $NewGatewayFqdn cannot be resolved: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please check the DNS entry of your new provider before running this script again" -ForegroundColor Red
    Stop-Transcript
    exit 2
}

# Check, that the new FQDN is registered and enabled in the tenant
Write-Host "Checking PSTN domain $NewGatewayFqdn" -ForegroundColor $CommandInfo
$csTenant = Get-CsTenant
if ($csTenant.VerifiedDomains.Name -notcontains $NewGatewayFqdn)
{
    Write-Host "$NewGatewayFqdn is not yet in the VerifiedDomains list" -ForegroundColor Red
    Write-Host "Please create a user in this domain, assign a O365E1 license and wait up to some hours or days" -ForegroundColor Red
    Write-Host "Scripts: Prepare-PSTNDomainUserCreate.ps1 and Prepare-PSTNDomainUserDelete.ps1" -ForegroundColor Red
    Stop-Transcript
    exit 3
}
$newDomainStatus = ($csTenant.VerifiedDomains | Where-Object { $_.Name -eq $NewGatewayFqdn }).Status
if ($newDomainStatus -ne "Enabled")
{
    Write-Host "$NewGatewayFqdn is not yet enabled (status: $newDomainStatus)" -ForegroundColor Red
    Write-Host "Please enable the domain $NewGatewayFqdn" -ForegroundColor Red
    Stop-Transcript
    exit 4
}
Write-Host "Domain $NewGatewayFqdn is verified and enabled" -ForegroundColor Green

# Read the old gateway settings, so they can be reused for the new gateway
Write-Host "Reading old PSTN gateway $OldGatewayFqdn" -ForegroundColor $CommandInfo
$oldPSTNGateway = $null
try {
    $oldPSTNGateway = Get-CsOnlinePSTNGateway -Identity $OldGatewayFqdn -ErrorAction SilentlyContinue
} catch { }
if (-Not $oldPSTNGateway)
{
    Write-Warning "The old gateway $OldGatewayFqdn does not exist in the tenant. Nothing to migrate from it."
    Write-Warning "The new gateway is created with the configured default values."
}

# Determine the settings for the new gateway
$newSipSignalingPort = $NewSipSignalingPort
if ($newSipSignalingPort -le 0)
{
    if ($oldPSTNGateway -and $oldPSTNGateway.SipSignalingPort)
    {
        $newSipSignalingPort = $oldPSTNGateway.SipSignalingPort
    }
    else
    {
        $newSipSignalingPort = [int]$AlyaPstnPort
    }
}
$newMaxConcurrentSessions = 100
if ($oldPSTNGateway -and $oldPSTNGateway.MaxConcurrentSessions)
{
    $newMaxConcurrentSessions = $oldPSTNGateway.MaxConcurrentSessions
}
$newForwardPai = $true
if ($oldPSTNGateway -and $null -ne $oldPSTNGateway.ForwardPai)
{
    $newForwardPai = $oldPSTNGateway.ForwardPai
}
$newForwardCallHistory = $true
if ($oldPSTNGateway -and $null -ne $oldPSTNGateway.ForwardCallHistory)
{
    $newForwardCallHistory = $oldPSTNGateway.ForwardCallHistory
}

# Create or update the new gateway
Write-Host "Checking new PSTN gateway $NewGatewayFqdn" -ForegroundColor $CommandInfo
$newPSTNGateway = $null
try {
    $newPSTNGateway = Get-CsOnlinePSTNGateway -Identity $NewGatewayFqdn -ErrorAction SilentlyContinue
} catch { }
if (-Not $newPSTNGateway)
{
    Write-Host "Creating new PSTN gateway $NewGatewayFqdn with port $newSipSignalingPort" -ForegroundColor $CommandInfo
    try {
        $newPSTNGateway = New-CsOnlinePSTNGateway -Fqdn $NewGatewayFqdn -SipSignalingPort $newSipSignalingPort -MaxConcurrentSessions $newMaxConcurrentSessions -Enabled $true -ForwardPai $newForwardPai -ForwardCallHistory $newForwardCallHistory
    } catch {
        Write-Error $_.Exception
        Write-Warning "Possibly your domain is not ready. To fix this, please add a user in this domain and assign an exchange license to him."
        Write-Warning "Scripts: Prepare-PSTNDomainUserCreate.ps1 and Prepare-PSTNDomainUserDelete.ps1"
        Stop-Transcript
        exit 5
    }
}
else
{
    Write-Host "New PSTN gateway $NewGatewayFqdn already exists. Updating settings." -ForegroundColor $CommandInfo
    Set-CsOnlinePSTNGateway -Identity $NewGatewayFqdn -SipSignalingPort $newSipSignalingPort -MaxConcurrentSessions $newMaxConcurrentSessions -Enabled $true -ForwardPai $newForwardPai -ForwardCallHistory $newForwardCallHistory
    $newPSTNGateway = Get-CsOnlinePSTNGateway -Identity $NewGatewayFqdn -ErrorAction SilentlyContinue
}

# Migrate the trunk translation rules from the old to the new gateway
if ($oldPSTNGateway)
{
    foreach ($translationRuleProperty in @("InboundPstnNumberTranslationRules", "InboundTeamsNumberTranslationRules", "OutboundPstnNumberTranslationRules", "OutboundTeamsNumberTranslationRules"))
    {
        $oldTranslationRules = @($oldPSTNGateway.$translationRuleProperty | Where-Object { -Not [string]::IsNullOrEmpty($_) })
        if ($oldTranslationRules.Count -gt 0)
        {
            Write-Host "Migrating $($oldTranslationRules.Count) $translationRuleProperty from $OldGatewayFqdn to $($NewGatewayFqdn): $($oldTranslationRules -join ", ")" -ForegroundColor $CommandInfo
            $translationRuleParams = @{
                Identity = $NewGatewayFqdn
                $translationRuleProperty = $oldTranslationRules
            }
            Set-CsOnlinePSTNGateway @translationRuleParams
        }
    }
}

# Re-point all voice routes from the old to the new gateway
Write-Host "Checking voice routes for gateway $OldGatewayFqdn" -ForegroundColor $CommandInfo
$voiceRoutes = @(Get-CsOnlineVoiceRoute)
$updatedVoiceRoutes = 0
foreach ($voiceRoute in $voiceRoutes)
{
    $routeGateways = @($voiceRoute.OnlinePstnGatewayList)
    if ($routeGateways -contains $OldGatewayFqdn)
    {
        $newRouteGateways = @($routeGateways | Where-Object { $_ -ne $OldGatewayFqdn })
        $newRouteGateways += $NewGatewayFqdn
        Write-Host "Updating voice route $($voiceRoute.Identity): gateway list is now $($newRouteGateways -join ", ")" -ForegroundColor $CommandInfo
        Set-CsOnlineVoiceRoute -Identity $voiceRoute.Identity -OnlinePstnGatewayList $newRouteGateways
        $updatedVoiceRoutes++
    }
}
if ($updatedVoiceRoutes -eq 0)
{
    Write-Warning "No voice route referencing the old gateway $OldGatewayFqdn was found."
    Write-Warning "Please check your voice routing configuration manually (Set-VoiceRouting.ps1)."
}

# Disable or remove the old gateway
if ($oldPSTNGateway)
{
    if ($RemoveOldGateway)
    {
        Write-Host "Removing old PSTN gateway $OldGatewayFqdn" -ForegroundColor $CommandInfo
        Remove-CsOnlinePSTNGateway -Identity $OldGatewayFqdn
    }
    else
    {
        Write-Host "Disabling old PSTN gateway $OldGatewayFqdn" -ForegroundColor $CommandInfo
        Set-CsOnlinePSTNGateway -Identity $OldGatewayFqdn -Enabled $false
        Write-Host "The old gateway was only disabled. You can remove it later, after verifying the new provider works." -ForegroundColor Green
    }
}

# Update the configuration file
$configFilePath = "$AlyaData\ConfigureEnv.ps1"
Write-Host "Updating `$AlyaPstnGateway in $configFilePath" -ForegroundColor $CommandInfo
if (-Not (Test-Path $configFilePath))
{
    Write-Host "Configuration file $configFilePath not found. Please update `$AlyaPstnGateway manually." -ForegroundColor Red
    Stop-Transcript
    exit 6
}
$configContent = Get-Content -Path $configFilePath -Raw -Encoding $AlyaUtf8Encoding
$configContentNew = $configContent -replace '(\$AlyaPstnGateway\s*=\s*)"[^"]*"', ('$1"' + $NewGatewayFqdn + '"')
if ($configContentNew -eq $configContent)
{
    Write-Host "The entry `$AlyaPstnGateway was not found in $configFilePath. Please update it manually." -ForegroundColor Red
    Stop-Transcript
    exit 7
}
if ($NewSipSignalingPort -gt 0)
{
    $configContentBeforePort = $configContentNew
    $configContentNew = $configContentNew -replace '(\$AlyaPstnPort\s*=\s*)"[^"]*"', ('$1"' + $newSipSignalingPort + '"')
    if ($configContentNew -eq $configContentBeforePort)
    {
        Write-Warning "The entry `$AlyaPstnPort was not found in $configFilePath. Please update it manually to $newSipSignalingPort."
    }
}
Set-Content -Path $configFilePath -Value $configContentNew -Encoding $AlyaUtf8Encoding -NoNewline
Write-Host "`$AlyaPstnGateway is now set to $NewGatewayFqdn" -ForegroundColor Green

Write-Host "`nPlease verify the new provider setup with a test call." -ForegroundColor Green
Write-Host "If the old provider used its own domain user (pstndeleteme@$OldGatewayFqdn), you may delete it now (Prepare-PSTNDomainUserDelete.ps1)." -ForegroundColor Green
Write-Host "Do not forget to commit the changed ConfigureEnv.ps1." -ForegroundColor Green

# Stopping Transcript
Stop-Transcript
