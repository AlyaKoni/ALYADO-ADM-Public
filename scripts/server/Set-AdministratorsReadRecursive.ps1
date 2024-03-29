﻿#Requires -Version 2.0
#Requires -RunAsAdministrator

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
    09.04.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    $path = "C:\Temp"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\server\Set-AdministratorsReadRecursive-$($AlyaTimeString).log" | Out-Null

#Main
$BuiltinAdminSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
$BuiltinAdminName = $BuiltinAdminSID.Translate([System.Security.Principal.NTAccount])

#Setting owner
$acl = Get-Acl $path
$actOwner = $acl.GetOwner([System.Security.Principal.NTAccount])
if ($actOwner.Value -ne $BuiltinAdminName)
{
    Write-Host "actOwner: $($actOwner.Value)"
    Write-Host "newOwner: $($BuiltinAdminName)"
    $owner = New-Object System.Security.Principal.NTAccount($BuiltinAdminName)
    $acl.SetOwner($owner)
}
Set-Acl $path $acl

#Setting read access for Administrators
$InheritanceFlagContainerAndObject = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$PropagationFlagNone = [System.Security.AccessControl.PropagationFlags]::None
$AccessTypeAllow = [System.Security.AccessControl.AccessControlType]::Allow 
$AccessReadExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinAdminName, $AccessReadExecute, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
Write-Host "Setting access rule:"
$accessRule
$acl.SetAccessRule($accessRule)
Set-Acl $path $acl

#Restoring owner
if ($actOwner.Value -ne $BuiltinAdminName)
{
    Write-Host "actOwner: $($BuiltinAdminName)"
    Write-Host "newOwner: $($actOwner.Value)"
    $acl.SetOwner($actOwner)
    Set-Acl $path $acl
}

#Stopping Transscript
Stop-Transcript
