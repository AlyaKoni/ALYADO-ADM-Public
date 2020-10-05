#Requires -Version 2.0

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
    04.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$inputFile = $null #Defaults to "$AlyaData\aad\Lizenzen.xlsx"
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\onprem\Configure-Licenses-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $inputFile)
{
    $inputFile = "$AlyaData\aad\Lizenzen.xlsx"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Check-Module ActiveDirectory
#Import-Module "ActiveDirectory" -ErrorAction Stop
Install-ModuleIfNotInstalled "ImportExcel"

# =============================================================
# AD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Licenses | ONPREMISES" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Reading input file
Write-Host "Reading input file from '$inputFile'" -ForegroundColor $CommandInfo
if (-Not (Test-Path $inputFile))
{
    throw "Input file not found!"
}
$licDefs = Import-Excel $inputFile -ErrorAction Stop

# Configured licenses
Write-Host "Configured licenses:" -ForegroundColor $CommandInfo
$licNames = $null
$licDefs | foreach {
    $licDef = $_
    if ($licDef.Name -like "User*")
    {
        $licNames = $licDef
    }
    if ($licDef.Name -like "*@*")
    {
        $outStr = " - $($licDef.Name): "
        for ($i = 1; $i -le 20; $i++)
        {
            $propName = "Lic"+$i
            if ($licDef.$propName -eq 1)
            {
                $outStr += "$($licNames.$propName),"
            }
        }
        Write-Host $outStr.TrimEnd(",")
    }
}

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Licenses | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Reading users from AD and setting license
Write-Host "Reading users from AD and setting license" -ForegroundColor $CommandInfo
$adUsers = Get-ADUser -Filter {UserPrincipalName -like '*'} -Properties UserPrincipalName,extensionAttribute1
$adUsers | foreach {
    
    $adUser = $_

    $licDef = $licDefs | where {$_.Name.ToLower() -eq $adUser.UserPrincipalName.ToLower()}
    if (-Not $licDef)
    {
        if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute1))
        {
            Write-Host "Checking license from '$($adUser.UserPrincipalName)'"
            Write-Host " - In AD was the license '$($adUser.extensionAttribute1)' configured, removed"
            Set-ADUser –Identity $adUser -Clear "extensionAttribute1"
        }
    }
    else
    {
        Write-Host "Checking license from '$($adUser.UserPrincipalName)'"
        $outStr = ""
        for ($i = 1; $i -le 20; $i++)
        {
            $propName = "Lic"+$i
            if ($licDef.$propName -eq 1)
            {
                $outStr += "LIC$($licNames.$propName),"
            }
        }
        $licStr = $outStr.TrimEnd(",")
        Write-Host " - Configuring: $($licStr)"
        if ($adUser.extensionAttribute1 -eq $licStr)
        {
            Write-Host " - was already correctly configured"
        }
        else
        {
            Write-Host " - Setting extensionAttribute1"
            if ([string]::IsNullOrEmpty($licStr))
            {
                Set-ADObject $adUser -Clear extensionAttribute1
            }
            else
            {
                Set-ADObject $adUser -Replace @{extensionAttribute1 = "$($licStr)"}
            }
        }
    }
}

#Stopping Transscript
Stop-Transcript