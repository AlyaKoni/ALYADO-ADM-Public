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
    10.05.2022 Konrad Brunner       Initial Version


    Source from: https://github.com/ucgeek/ManageTeamsTrunkTranslations/blob/master/Manage-TeamsTranslationRules.Ps1

#>

[CmdletBinding()]
Param(
    [parameter(Mandatory=$false)]
    $Gateway = $null,
    [parameter(Mandatory=$true)]
    [ValidateSet('InboundCallerNumber','InboundPstnNumberTranslationRules','InboundCalledNumber', 'InboundTeamsNumberTranslationRules', 'OutboundCalledNumber', 'OutboundPstnNumberTranslationRules', 'OutboundCallerNumber', 'OutboundTeamsNumberTranslationRules')]
    $Type,
    [parameter(Mandatory=$true)]
    $Pattern,
    [parameter(Mandatory=$true)]
    $Translation
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\pstn\Create-TeamsTrunkTranslationRule-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MicrosoftTeams"

# Logins
LoginTo-Teams

# =============================================================
# O365 stuff
# =============================================================

function Get-Type ($type) {
    switch($type) {
        'InboundCallerNumber' {'InboundPstnNumberTranslationRules'} 
        'InboundCalledNumber' {'InboundTeamsNumberTranslationRules'} 
        'OutboundCalledNumber' {'OutboundPstnNumberTranslationRules'} 
        'OutboundCallerNumber' {'OutboundTeamsNumberTranslationRules'} 
        default {$type}
    }
}

function CsOnlinePSTNGatewayParamBuilder ($gw, $type, $translationList) {
    $typeConverted = Get-Type $type
    
    $cmdParamBuilder = @{            
        Identity = $gw        
    }
    if($typeConverted -eq 'InboundPstnNumberTranslationRules') {                 
        $cmdParamBuilder.add('InboundPstnNumberTranslationRules', $translationList)
        return $cmdParamBuilder            
    } 
    elseif($typeConverted -eq 'InboundTeamsNumberTranslationRules') {                 
        $cmdParamBuilder.add('InboundTeamsNumberTranslationRules', $translationList)  
        return $cmdParamBuilder            
    } 
    elseif($typeConverted -eq 'OutboundPstnNumberTranslationRules') {                 
        $cmdParamBuilder.add('OutboundPstnNumberTranslationRules', $translationList)  
        return $cmdParamBuilder            
    }
    elseif($typeConverted -eq 'OutboundTeamsNumberTranslationRules') {                 
        $cmdParamBuilder.add('OutboundTeamsNumberTranslationRules', $translationList)
        return $cmdParamBuilder              
    }
    else {
        return $null
    } 
}

$typeConverted = Get-Type $type
if (-Not $Gateway)
{
    $Gateway = (Get-CsOnlinePSTNGateway)[0].Identity
}
$existingTrunkTranslations = (Get-CsOnlinePSTNGateway -Identity $Gateway).($typeConverted)
$existingTrunkTranslationsCount = $existingTrunkTranslations.count
$existingTentantTranslations = Get-CsTeamsTranslationRule
$existingTentantTranslationsCount = $existingTentantTranslations.count

$Name = $type + "_" + ($Pattern -ireplace "[^\x30-\x39,\x41-\x5A]", "") + "_to_" + ($Translation -ireplace "[^\x30-\x39,\x41-\x5A]", "")
$Description = "Translates $type from '$Pattern' to '$Translation'"

if ($existingTentantTranslationsCount -gt 0 -and $existingTentantTranslations.Identity -contains $Name) {
    Write-Host "Skipping - $Name already exists"
} else {
    Write-Host "Creating Translation - $Name"
    New-CsTeamsTranslationRule -Identity $Name -Pattern $Pattern -Translation $Translation -Description $Description
}

Write-Host "Adding translation to gateway $name"
if ($existingTrunkTranslationsCount -gt 0) {
    if ($existingTrunkTranslations -Contains $name) {
        Write-Host "  Already exists"
    } else {
            $null = $existingTrunkTranslations.Add($name)
            $params = CsOnlinePSTNGatewayParamBuilder -gw $Gateway -type $typeConverted -translationList $existingTrunkTranslations
            Set-CsOnlinePSTNGateway @params
    }
} else {
    $newTranslationList = New-Object 'System.Collections.Generic.List[string]'
    $null = $newTranslationList.Add($name)
    $params = CsOnlinePSTNGatewayParamBuilder -gw $Gateway -type $typeConverted -translationList $newTranslationList
    Set-CsOnlinePSTNGateway @params
}

#Stopping Transscript
Stop-Transcript
