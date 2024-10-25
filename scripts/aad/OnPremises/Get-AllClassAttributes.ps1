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
    01.10.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$ClassName,
    [bool]$removeAttributesBASEONLY = $true
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\onprem\Get-AllClassAttributes-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Check-Module "ActiveDirectory"

# =============================================================
# AD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AD | Get-AllClassAttributes | ONPREMISES" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
$Loop = $True
$ClassArray = [System.Collections.ArrayList]@()
$ClassAttributes = [System.Collections.ArrayList]@()
# Retrieve the User class and any parent classes
While ($Loop) {
  $Class = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter { ldapDisplayName -Like $ClassName } -Properties AuxiliaryClass, SystemAuxiliaryClass, mayContain, mustContain, systemMayContain, systemMustContain, subClassOf, ldapDisplayName
  If ($Class.ldapDisplayName -eq $Class.subClassOf) {
    $Loop = $False
  }
  $ClassArray.Add($Class)
  $ClassName = $Class.subClassOf
}
# Loop through all the classes and get all auxiliary class attributes and direct attributes
$ClassArray | % {
  # Get Auxiliary class attributes
  $Aux = $_.AuxiliaryClass | % { Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter { ldapDisplayName -like $_ } -Properties mayContain, mustContain, systemMayContain, systemMustContain } |
  Select-Object @{n = "Attributes"; e = { $_.mayContain + $_.mustContain + $_.systemMaycontain + $_.systemMustContain } } |
  Select-Object -ExpandProperty Attributes
  # Get SystemAuxiliary class attributes
  $SysAux = $_.SystemAuxiliaryClass | % { Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter { ldapDisplayName -like $_ } -Properties MayContain, SystemMayContain, systemMustContain } |
  Select-Object @{n = "Attributes"; e = { $_.maycontain + $_.systemmaycontain + $_.systemMustContain } } |
  Select-Object -ExpandProperty Attributes
  # Get direct attributes
  $ClassAttributes += $Aux + $SysAux + $_.mayContain + $_.mustContain + $_.systemMayContain + $_.systemMustContain
}

if ($removeAttributesBASEONLY)
{
    $baseOnlyAttrs = (Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -LDAPFilter '(searchFlags:1.2.840.113556.1.4.803:=2048)' -Properties ldapDisplayName).ldapDisplayName
    $ClassAttributes | Sort-Object | Get-Unique | Where-Object { $_ -notin $baseOnlyAttrs }
}
else
{
    $ClassAttributes | Sort-Object | Get-Unique
}

#Stopping Transscript
Stop-Transcript
