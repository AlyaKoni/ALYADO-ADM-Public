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
    08.03.2020 Konrad Brunner       Initial Version


IMPORTANT: 
IMPORTANT: This script expects the directory names are equal to user names
IMPORTANT: 
#>

[CmdletBinding()]
Param(
    $AdminGroupName = "Domänen-Admins",
    $UserHomePath = "\\server\e$\userHomes"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\filesync\Set-UserHomeAccess-$($AlyaTimeString).log" | Out-Null

# Constants
$InheritanceFlagContainerAndObject = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$PropagationFlagInheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly
$PropagationFlagNone = [System.Security.AccessControl.PropagationFlags]::None
$AccessTypeAllow = [System.Security.AccessControl.AccessControlType]::Allow 
$AccessFullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
$AccessReadExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
$AccessModify = [System.Security.AccessControl.FileSystemRights]::CreateDirectories -bor [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor [System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::WriteData
$BuiltinUsersSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-545'
$BuiltinAdminSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
$AuthSystemSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
$CreatorOwnerSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-3-0'

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "FileSync | Set-UserHomeAccess | LOCAL" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$dirs = Get-ChildItem -Path "$UserHomePath"
foreach($dir in $dirs)
{
    #$dir=$dirs[0]
    #if (-Not ($dir.Name -eq "administrator")) {continue}
    Write-Host "Dir: $($dir.FullName)" -ForegroundColor Cyan
    $acl = Get-Acl $dir.FullName
    $userFnd = $false
    foreach($acc in $acl.Access)
    {
        if ($acc.IdentityReference -like "*$($dir.Name)*") {
            $userFnd = $true
            break
        }
    }
    $adminFnd = $false
    foreach($acc in $acl.Access)
    {
        if ($acc.IdentityReference -like "*$($AdminGroupName)*") {
            $adminFnd = $true
            break
        }
    }
    if (-Not $userFnd -Or -Not $adminFnd)
    {
        Write-Host "  - User not found, adding"
        $tmp = $acl.SetAccessRuleProtection($true, $false)
        foreach($acc in $acl.Access)
        {
            $tmp = $acl.RemoveAccessRule($acc)
        }
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($AuthSystemSID, $AccessFullControl, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
        $acl.SetAccessRule($accessRule)
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$AlyaLocalDomainName\$AdminGroupName", $AccessFullControl, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
        $acl.SetAccessRule($accessRule)
        try
        {
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$AlyaLocalDomainName\$($dir.Name)", $AccessFullControl, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
            $acl.SetAccessRule($accessRule)
        } catch {
            Write-Host "    + error: " + $_.Exception.Message -ForegroundColor Red
        }
        Set-Acl $dir.FullName $acl
    }
}

#Stopping Transscript
Stop-Transcript
