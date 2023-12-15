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

$apps = (Get-Content -Path "$PsScriptRoot\Configuration\Applications\intuneApplications.json" -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json).value
$apps = $apps | Where-Object { $_.isAssigned -eq $true }
$apps | Foreach-Object { 
    $_.PSObject.Properties.Remove("id")
    $_.PSObject.Properties.Remove("createdDateTime")
    $_.PSObject.Properties.Remove("lastModifiedDateTime")
    $_.PSObject.Properties.Remove("isAssigned")
    $_.PSObject.Properties.Remove("dependentAppCount")
    $_.PSObject.Properties.Remove("supersedingAppCount")
    $_.PSObject.Properties.Remove("supersededAppCount")
    $_.PSObject.Properties.Remove("usedLicenseCount")
    $_.PSObject.Properties.Remove("totalLicenseCount")
    $_.PSObject.Properties.Remove("isPrivate")
    $_.PSObject.Properties.Remove("isSystemApp")
    $_.PSObject.Properties.Remove("supportsOemConfig")
    $_.PSObject.Properties.Remove("appAvailability")
    $_.PSObject.Properties.Remove("version")
    $_.PSObject.Properties.Remove("publishingState")
    $_.PSObject.Properties.Remove("committedContentVersion")
    $_.PSObject.Properties.Remove("uploadState")
}
$apps | Where-Object { $_."@odata.type" -eq "#Microsoft.Graph.androidManagedStoreApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-androidManagedStoreApps.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#Microsoft.Graph.managedAndroidStoreApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-managedAndroidStoreApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#Microsoft.Graph.managedIOSStoreApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-managedIOSStoreApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#Microsoft.Graph.iosStoreApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-iosStoreApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#Microsoft.Graph.microsoftStoreForBusinessApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-microsoftStoreForBusinessApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#Microsoft.Graph.macOSMdatpApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-macOSMdatpApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#Microsoft.Graph.macOSOfficeSuiteApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-macOSOfficeSuiteApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#Microsoft.Graph.macOSMicrosoftEdgeApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-macOSMicrosoftEdgeApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#Microsoft.Graph.webApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-webApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#Microsoft.Graph.win32LobApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-win32LobApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#Microsoft.Graph.officeSuiteApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-officeSuiteApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#Microsoft.Graph.windowsMicrosoftEdgeApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-windowsMicrosoftEdgeApp.json" -encoding UTF8 -Force
