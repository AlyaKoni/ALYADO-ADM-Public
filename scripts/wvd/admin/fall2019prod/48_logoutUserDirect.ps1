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
    02.04.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$serverName = "hostname-0",
    [Parameter(Mandatory=$false)]
    [string]$userName = "first.last"
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019prod\48_logoutUserDirect-$($AlyaTimeString).log" | Out-Null

# Constants
$ErrorActionPreference = "Stop"

# =============================================================
# Windows stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 48_logoutUserDirect | Windows" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
Write-Host "Actual logged in users" -ForegroundColor $CommandInfo
$res = Invoke-Command -ComputerName $serverName -ScriptBlock { quser }
$res
$fnd = $false
foreach($re in $res)
{
    $user = ($re.Split() | ? {$_})[0]
    $session = ($re.Split() | ? {$_})[1].Trim()
    if ([string]::IsNullOrEmpty($session))
    {
        $id = ($re.Split() | ? {$_})[1]
    }
    else
    {
        $id = ($re.Split() | ? {$_})[2]
    }
    if ($user -eq $userName)
    {
        Write-Host "Found user on id $($id), loging him out" -ForegroundColor Magenta
        Invoke-Command -ComputerName $serverName -ScriptBlock { logoff $id }
        $fnd = $true
    }
}

if (-Not $fnd)
{
    Write-Host "Can't find user session on server" -ForegroundColor $CommandInfo
}
else
{
    Write-Host "New situation" -ForegroundColor $CommandInfo
    Invoke-Command -ComputerName $serverName -ScriptBlock { quser }
}

#Stopping Transscript
Stop-Transcript
