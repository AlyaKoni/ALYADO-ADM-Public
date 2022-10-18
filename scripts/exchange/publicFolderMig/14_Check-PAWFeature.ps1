#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2021

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
    24.10.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

Connect-ExchangeOnline -ShowProgress $true

$migConfig = Get-MigrationConfig
if ($migConfig.Features.IndexOf("PAW") -eq -1)
{
    Write-Warning "PAW feature is NOT available!"
    Write-Warning "If PAW is not yet enabled for your tenant, it could be because you have some existing migration batches, either public folder batches or user batches. These batches could be in any state, including Completed. If this is the case, please complete and remove any existing migration batches until no records are returned when you run Get-MigrationBatch. Once all existing batches are removed, PAW should get enabled automatically. Note that the change may not reflect in Get-MigrationConfig immediately, which is okay. Once this step is completed, you can continue creating new batches of user migrations."
}
else
{
    Write-Host "PAW feature is available"
}

Disconnect-ExchangeOnline -Confirm:$false
