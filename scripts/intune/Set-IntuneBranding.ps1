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
    06.10.2020 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Set-IntuneBranding-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$brandingJson = "$($AlyaData)\intune\branding.json"
$brandingLogoLight = "$($AlyaData)\intune\brandingLogoLight.png"
$brandingLogoDark = "$($AlyaData)\intune\brandingLogoDark.png"
$brandingLogoLandingPage = "$($AlyaData)\intune\brandingLogoLandingPage.png"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "Organization.ReadWrite.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Set-IntuneBranding | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Reading branding configuration
Write-Host "Reading branding configuration" -ForegroundColor $CommandInfo
Write-Host "  from $brandingJson"
$brandingConfig = Get-Content -Path $brandingJson -Raw -Encoding UTF8
$brandingConfig = $brandingConfig.Replace("##AlyaCompanyNameFull##", $AlyaCompanyNameFull)
$brandingConfig = $brandingConfig.Replace("##AlyaSupportTitle##", $AlyaSupportTitle)
$brandingConfig = $brandingConfig.Replace("##AlyaSupportTel##", $AlyaSupportTel)
$brandingConfig = $brandingConfig.Replace("##AlyaSupportMail##", $AlyaSupportMail)
$brandingConfig = $brandingConfig.Replace("##AlyaSupportUrl##", $AlyaSupportUrl)
$brandingConfig = $brandingConfig.Replace("##AlyaPrivacyUrl##", $AlyaPrivacyUrl)
$brandingConfig = $brandingConfig | ConvertFrom-Json

Add-Type -AssemblyName System.Drawing

# Reading light logo
Write-Host "Reading light logo" -ForegroundColor $CommandInfo
Write-Host "  from $brandingLogoLight"
$logo = Get-Item -Path $brandingLogoLight -ErrorAction SilentlyContinue
if ($logo)
{
    if ($logo.Length -gt 750KB)
    {
        Write-Error "brandingLogoLight supports a max size of 1125x1125" -ErrorAction Continue
    }
    else
    {
        $image = [System.Drawing.Image]::FromFile($brandingLogoLight)
        if ($image.Width -gt 400 -or $image.height -gt 400)
        {
            Write-Error "brandingLogoLight supports a max size of 400x400" -ErrorAction Continue
        }
        else
        {
            $iconResponse = [System.IO.File]::ReadAllBytes("$($brandingLogoLight)")
            $base64icon = [System.Convert]::ToBase64String($iconResponse)
            $iconExt = ([System.IO.Path]::GetExtension($brandingLogoLight)).replace(".","")
            $iconType = "image/$iconExt"
            $brandingConfig.intuneBrand.lightBackgroundLogo = @{ "@odata.type" = "#microsoft.graph.mimeContent" }
            $brandingConfig.intuneBrand.lightBackgroundLogo.type = "$iconType"
            $brandingConfig.intuneBrand.lightBackgroundLogo.value = "$base64icon"
        }
        $image.Dispose()
    }
}
else
{
    Write-Warning "  Logo not found"
}

# Reading dark logo
Write-Host "Reading dark logo" -ForegroundColor $CommandInfo
Write-Host "  from $brandingLogoDark"
$logo = Get-Item -Path $brandingLogoDark -ErrorAction SilentlyContinue
if ($logo)
{
    if ($logo.Length -gt 750KB)
    {
        Write-Error "brandingLogoDark supports a max size of 1125x1125" -ErrorAction Continue
    }
    else
    {
        $image = [System.Drawing.Image]::FromFile($brandingLogoDark)
        if ($image.Width -gt 400 -or $image.height -gt 400)
        {
            Write-Error "brandingLogoDark supports a max size of 400x400" -ErrorAction Continue
        }
        else
        {
            $iconResponse = [System.IO.File]::ReadAllBytes("$($brandingLogoDark)")
            $base64icon = [System.Convert]::ToBase64String($iconResponse)
            $iconExt = ([System.IO.Path]::GetExtension($brandingLogoDark)).replace(".","")
            $iconType = "image/$iconExt"
            $brandingConfig.intuneBrand.darkBackgroundLogo = @{ "@odata.type" = "#microsoft.graph.mimeContent" }
            $brandingConfig.intuneBrand.darkBackgroundLogo.type = "$iconType"
            $brandingConfig.intuneBrand.darkBackgroundLogo.value = "$base64icon"
        }
        $image.Dispose()
    }
}
else
{
    Write-Warning "  Logo not found"
}

# Reading landing page logo
Write-Host "Reading landing page logo" -ForegroundColor $CommandInfo
Write-Host "  from $brandingLogoLandingPage"
$logo = Get-Item -Path $brandingLogoLandingPage -ErrorAction SilentlyContinue
if ($logo)
{
    if ($logo.Length -gt 1.3MB)
    {
        Write-Error "brandingLogoLandingPage supports a max size of 1125x1125" -ErrorAction Continue
    }
    else
    {
        $image = [System.Drawing.Image]::FromFile($brandingLogoLandingPage)
        if ($image.Width -gt 1125 -or $image.height -gt 1125)
        {
            Write-Error "brandingLogoLandingPage supports a max size of 1125x1125" -ErrorAction Continue
        }
        else
        {
            $iconResponse = [System.IO.File]::ReadAllBytes("$($brandingLogoLandingPage)")
            $base64icon = [System.Convert]::ToBase64String($iconResponse)
            $iconExt = ([System.IO.Path]::GetExtension($brandingLogoLandingPage)).replace(".","")
            $iconType = "image/$iconExt"
            $brandingConfig.intuneBrand.landingPageCustomizedImage = @{ "@odata.type" = "#microsoft.graph.mimeContent" }
            $brandingConfig.intuneBrand.landingPageCustomizedImage.type = "$iconType"
            $brandingConfig.intuneBrand.landingPageCustomizedImage.value = "$base64icon"
        }
        $image.Dispose()
    }
}
else
{
    Write-Warning "  Logo not found"
}

Write-Host "Configuring branding" -ForegroundColor $CommandInfo
$uri = "/beta/deviceManagement"
$intuneBrand = Patch-MsGraph -Uri $uri -Body ($brandingConfig | ConvertTo-Json -Depth 50)

#Stopping Transscript
Stop-Transcript
