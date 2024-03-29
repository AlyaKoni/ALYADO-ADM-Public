﻿#Requires -Version 7.0

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
    03.10.2021 Konrad Brunner       Initial Version
    25.03.2023 Konrad Brunner       Fixed issues with parameters, just trying for now different once, TODO
    19.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules, TODO test with UseAppAuthentication = true

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$SiteUrl
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Export-PnPTemplate-$($AlyaTimeString).log" | Out-Null

# Checking modules
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logging in
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl
$siteCon = LoginTo-PnP -Url $SiteUrl

# Export site template
Write-Host "Exporting site template" -ForegroundColor $CommandInfo
$outfile = "$AlyaData\sharepoint\PnPTemplate_" + $SiteUrl.Replace("https://", "").Replace("/", "_") + ".xml"
try
{
    Get-PnPSiteTemplate -Connection $adminCon -Out $outfile -IncludeAllTermGroups -IncludeSiteCollectionTermGroup -IncludeSiteGroups `
        -IncludeTermGroupsSecurity -IncludeSearchConfiguration -IncludeNativePublishingFiles -IncludeHiddenLists -IncludeAllPages `
        -PersistBrandingFiles -PersistPublishingFiles -PersistMultiLanguageResources -Encoding ([System.Text.Encoding]::UTF8) -Force
}
catch
{
    try
    {
        Get-PnPSiteTemplate -Connection $siteCon -Out $outfile -IncludeAllTermGroups -IncludeSiteCollectionTermGroup -IncludeSiteGroups `
            -IncludeTermGroupsSecurity -IncludeSearchConfiguration -IncludeNativePublishingFiles -IncludeHiddenLists -IncludeAllPages `
            -PersistBrandingFiles -PersistPublishingFiles -PersistMultiLanguageResources -Encoding ([System.Text.Encoding]::UTF8) -Force
    }
    catch
    {
        try
        {
            Get-PnPSiteTemplate -Connection $siteCon -Out $outfile -IncludeSiteGroups `
                -IncludeSearchConfiguration -IncludeNativePublishingFiles -IncludeHiddenLists -IncludeAllPages `
                -PersistBrandingFiles -PersistPublishingFiles -PersistMultiLanguageResources -Encoding ([System.Text.Encoding]::UTF8) -Force
        }
        catch
        {
            Get-PnPSiteTemplate -Connection $siteCon -Out $outfile -IncludeAllPages -Encoding ([System.Text.Encoding]::UTF8) -Force
        }
    }
}

Write-Host "Template exported to $outfile" -ForegroundColor $CommandSuccess

#Stopping Transscript
Stop-Transcript
