﻿#Requires -Version 2.0

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
    24.04.2023 Konrad Brunner       Initial Creation
    03.06.2024 Konrad Brunner       Added try catch
    16.08.2024 Konrad Brunner       ignoreDomains
    20.11.2024 Konrad Brunner       Better error handling

#>

[CmdletBinding()]
Param(
    [int]$keySize = 1024,
    [string[]]$ignoreDomains = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Rotate-DKIMDomainKeys-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "EXCHANGE | Rotate-DKIMDomainKeys | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$domains = @()

$domains += $AlyaDomainName
foreach ($dom in $AlyaAdditionalDomainNames)
{
    if ($ignoreDomains -and $dom -in $ignoreDomains) { continue }
    $domains += $dom
}

try
{
    LoginTo-EXO
    foreach ($dom in $domains)
    {
        try {
            Write-Host "Checking domain $dom"
            $conf = Get-DkimSigningConfig -Identity $dom -ErrorAction SilentlyContinue
            if (-Not $conf) {
                Write-Warning "No DKIM config found to rotate in domain $dom"
            }
            else {
                if ($conf.RotateOnDate -ge (Get-Date)) {
                    Write-Warning "A rotation is already planned!"
                    continue
                }
                if (-Not (Get-Command "Rotate-DkimSigningConfig")) {
                    throw "Command Rotate-DkimSigningConfig not found! Do you have the right access active?"
                }
                Write-Warning "Rotating domain key."
                Rotate-DkimSigningConfig -KeySize $keySize -Identity $dom
            }
        }
        catch {
            if ($conf)
            {
                $conf | Format-List | Out-String
            }
            Write-Error $_.Exception -ErrorAction Continue
        }
    }
}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}
finally
{
    DisconnectFrom-EXOandIPPS
}

#Stopping Transscript
Stop-Transcript
