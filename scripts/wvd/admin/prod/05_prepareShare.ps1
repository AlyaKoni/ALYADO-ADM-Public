#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting: 2020

    This unpublished material is proprietary to Alya Consulting.
    All rights reserved. The methods and techniques described
    herein are considered trade secrets and/or confidential. 
    Reproduction or distribution, in whole or in part, is 
    forbidden except by express written permission of Alya Consulting.

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
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\prod\06_prepareShare-$($AlyaTimeString).log" | Out-Null

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