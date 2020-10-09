#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting: 2020

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
    11.03.2020 Konrad Brunner       Initial Version

#>

#    ╔═════════════╦═════════════╦═══════════════════════════════╦════════════════════════╦══════════════════╦═══════════════════════╦═════════════╦═════════════╗
#    ║             ║ folder only ║ folder, sub-folders and files ║ folder and sub-folders ║ folder and files ║ sub-folders and files ║ sub-folders ║    files    ║
#    ╠═════════════╬═════════════╬═══════════════════════════════╬════════════════════════╬══════════════════╬═══════════════════════╬═════════════╬═════════════╣
#    ║ Propagation ║ none        ║ none                          ║ none                   ║ none             ║ InheritOnly           ║ InheritOnly ║ InheritOnly ║
#    ║ Inheritance ║ none        ║ Container|Object              ║ Container              ║ Object           ║ Container|Object      ║ Container   ║ Object      ║
#    ╚═════════════╩═════════════╩═══════════════════════════════╩════════════════════════╩══════════════════╩═══════════════════════╩═════════════╩═════════════╝

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$hostpoolShareDir,
    [Parameter(Mandatory=$true)]
    [string]$hostpoolShareName
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019prod\06_prepareShare-$($AlyaTimeString).log" | Out-Null

# Creating share directory for hostpool
Write-Host "Creating share directory for hostpool" -ForegroundColor $CommandInfo
Write-Host "hostpoolShareDir: $hostpoolShareDir"
Write-Host "hostpoolShareName: $hostpoolShareName"
if (!(Test-Path $hostpoolShareDir))
{
    New-Item -Path "$hostpoolShareDir" -ItemType Directory -Force | Out-Null

    $InheritanceFlagContainerAndObject = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlagInheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $PropagationFlagNone = [System.Security.AccessControl.PropagationFlags]::None
    $AccessTypeAllow = [System.Security.AccessControl.AccessControlType]::Allow 
    $AccessFullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
    $AccessReadExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $AccessModify = [System.Security.AccessControl.FileSystemRights]::CreateDirectories -bor [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor [System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::WriteData


    $AdminGroupName = "Domain Admins"
    $UserGroupName = "Domain Users"
    $acl = Get-Acl "$hostpoolShareDir"
    try
    {
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$AlyaLocalDomainName\$AdminGroupName", $AccessReadExecute, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
        $acl.SetAccessRule($accessRule)
    } 
    catch
    {
        $AdminGroupName = "Domänen-Admins"
        $UserGroupName = "Domänen-Benutzer"
    }

    $BuiltinUsersSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-545'
    $BuiltinAdminSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    $AuthSystemSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
    $CreatorOwnerSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-3-0'
    #$BuiltinUsersSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-3-0'
    #$BuiltinUsersGroup = $BuiltinUsersSID.Translate([System.Security.Principal.NTAccount])
    #$BuiltinUsersGroup.Value

    $acl = Get-Acl "$hostpoolShareDir"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$AlyaLocalDomainName\$UserGroupName", $AccessReadExecute, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
    $acl.SetAccessRule($accessRule)
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$AlyaLocalDomainName\$AdminGroupName", $AccessFullControl, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
    $acl.SetAccessRule($accessRule)
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($AuthSystemSID, $AccessFullControl, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
    $acl.SetAccessRule($accessRule)
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinAdminSID, $AccessFullControl, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
    $acl.SetAccessRule($accessRule)
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinUsersSID, $AccessReadExecute, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
    $acl.SetAccessRule($accessRule)
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($CreatorOwnerSID, $AccessFullControl, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
    $acl.SetAccessRule($accessRule)
    Set-Acl $hostpoolShareDir $acl
    
    $acl = Get-Acl "$hostpoolShareDir"
    $acl.SetAccessRuleProtection($true,$false)
    Set-Acl $hostpoolShareDir $acl

    New-Item -Path "$hostpoolShareDir\Profiles" -ItemType Directory -Force | Out-Null
    $acl = Get-Acl "$hostpoolShareDir\Profiles"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$AlyaLocalDomainName\$UserGroupName", $AccessModify, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
    $acl.SetAccessRule($accessRule)
    Set-Acl "$hostpoolShareDir\Profiles" $acl

    New-Item -Path "$hostpoolShareDir\Containers" -ItemType Directory -Force | Out-Null
    $acl = Get-Acl "$hostpoolShareDir\Containers"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$AlyaLocalDomainName\$UserGroupName", $AccessModify, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
    $acl.SetAccessRule($accessRule)
    Set-Acl "$hostpoolShareDir\Containers" $acl
}

# Creating share for hostpool
Write-Host "Creating share for hostpool" -ForegroundColor $CommandInfo
$ShareServer = $env:COMPUTERNAME.ToLower()
$hostpoolSharePath = "\\$($ShareServer)\$hostpoolShareName"
if (-Not (Test-Path $hostpoolSharePath))
{
    New-SMBShare –Name $hostpoolShareName –Path $hostpoolShareDir –FullAccess "$AlyaLocalDomainName\$AdminGroupName", "$AlyaLocalDomainName\$UserGroupName"
}

#Stopping Transscript
Stop-Transcript