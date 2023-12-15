#Requires -Version 2

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

Get-ADDomain
Set-ADAccountPassword -Identity cloud.test -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "XXXX" -Force)
Get-ADGroup  -Filter "samAccountName -like '*XXXXX*'" -Properties *
(Get-ADGroup XXXX -Properties *).Members
Get-ADUser  -Filter "samAccountName -eq 'XXXXX'" -Properties *
Get-ADUser  -Filter "samAccountName -like '*XXXXX*'" -Properties *
Get-ADUser -Filter { UserPrincipalName -like '*' -and ObjectClass -eq "user" -and Enabled -eq $true }
(Get-ADUser -Filter "samAccountName -like '*XXXXX*'" -Properties *).UserPrincipalName
Set-ADUser -Identity $user.samAccountName -UserPrincipalName 'first.last@alyaconsulting.ch'
Start-ADSyncSyncCycle -PolicyType Delta
(Get-ADRootDSE ).namingContexts
