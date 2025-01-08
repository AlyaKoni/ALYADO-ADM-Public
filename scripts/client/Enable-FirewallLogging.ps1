#Requires -Version 2
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


#>

$LogPath = Join-Path -path $env:windir -ChildPath "System32\LogFiles\Firewall"
# if (-Not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath }
# (Get-ACL -Path $LogPath).Access | Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -AutoSize

# $LogPath = Join-Path -path $env:windir -ChildPath "System32\LogFiles\Firewall"
# $NewAcl = Get-Acl -Path $LogPath

# $identity = "NT SERVICE\mpssvc"
# $fileSystemRights = "FullControl"
# $inheritanceFlags = "ContainerInherit,ObjectInherit"
# $propagationFlags = "None"
# $type = "Allow"

# $fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, $inheritanceFlags, $propagationFlags, $type
# $fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList

# $NewAcl.SetAccessRule($fileSystemAccessRule)
# Set-Acl -Path $LogPath -AclObject $NewAcl

Set-NetFireWallProfile -Profile Domain -LogAllowed True -LogBlocked True -LogIgnored True -LogMaxSizeKilobytes (1024*30) -LogFileName "$LogPath\pfirewall_domain.log"
Set-NetFireWallProfile -Profile Private -LogAllowed True -LogBlocked True -LogIgnored True -LogMaxSizeKilobytes (1024*30) -LogFileName "$LogPath\pfirewall_private.log"
Set-NetFireWallProfile -Profile Public -LogAllowed True -LogBlocked True -LogIgnored True -LogMaxSizeKilobytes (1024*30) -LogFileName "$LogPath\pfirewall_public.log"

