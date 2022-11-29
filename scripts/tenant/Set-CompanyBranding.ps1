#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2022

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
    25.11.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-CompanyBranding-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Identity.DirectoryManagement"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MgGraph -Scopes @("Organization.ReadWrite.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-CompanyBranding | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting organisation
Write-Host "Getting organisation" -ForegroundColor $CommandInfo
$org = Get-MgOrganization -OrganizationId $AlyaTenantId
$org | fl

# Getting act azure branding
Write-Host "Getting act branding" -ForegroundColor $CommandInfo
$branding = Get-MgOrganizationBranding -OrganizationId $AlyaTenantId
$branding | fl

# Setting organisation info
Write-Host "Setting organisation info" -ForegroundColor $CommandInfo
Update-MgOrganization -OrganizationId $AlyaTenantId `
    -MarketingNotificationEmails @($AlyaGeneralInformEmail) `
    -PrivacyProfile @{
        contactEmail = $AlyaPrivacyEmail
        statementUrl = $AlyaPrivacyUrl
    } `
    -SecurityComplianceNotificationMails @($AlyaSecurityEmail) `
    -TechnicalNotificationMails @($AlyaSupportEmail)

# Setting azure branding
Write-Host "Setting branding" -ForegroundColor $CommandInfo
Update-MgOrganizationBranding -OrganizationId $AlyaTenantId `
      -BackgroundColor $AlyaAzureBrandingBackgroundColor `
      -SignInPageText $AlyaAzureBrandingSignInPageTextDefault `
      -UsernameHintText $AlyaAzureBrandingUsernameHintTextDefault

$locs = Get-MgOrganizationBrandingLocalization -OrganizationId $AlyaTenantId
$locDef = $locs | where { $_.Id -eq 0 }
$locEn = $locs | where { $_.Id -eq "en-US" }
$locDe = $locs | where { $_.Id -eq "de-de" }
$locFr = $locs | where { $_.Id -eq "fr-FR" }
$locIt = $locs | where { $_.Id -eq "it-IT" }
if ($locEn)
{
    Update-MgOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -OrganizationalBrandingLocalizationId "en-US" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextEn `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextEn
}
else
{
    New-MgOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -Id "en-US" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextEn `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextEn
}
if ($locDe)
{
    Update-MgOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -OrganizationalBrandingLocalizationId "de-de" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextDe `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextDe
}
else
{
    New-MgOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -Id "de-de" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextDe `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextDe
}
if ($locFr)
{
    Update-MgOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -OrganizationalBrandingLocalizationId "fr-FR" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextFr `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextFr
}
else
{
    New-MgOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -Id "fr-FR" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextFr `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextFr
}
if ($locIt)
{
    Update-MgOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -OrganizationalBrandingLocalizationId "it-IT" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextIt `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextIt
}
else
{
    New-MgOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -Id "it-IT" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextIt `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextIt
}

# Setting branding backgroundImage
Write-Host "Setting branding backgroundImage" -ForegroundColor $CommandInfo
if ([string]::IsNullOrEmpty($AlyaAzureBrandingBackgroundImage) -or $AlyaAzureBrandingBackgroundImage -eq "PleaseSpecify")
{
    Write-Host "No branding backgroundImage specified"
}
else
{
    $uplFile = $AlyaAzureBrandingBackgroundImage
    if ($AlyaAzureBrandingBackgroundImage.StartsWith("http"))
    {
        $fileName = Split-Path -Path $AlyaAzureBrandingBackgroundImage -Leaf
        $uplFile = Join-Path $env:TEMP $fileName
        if (Test-Path $uplFile) { Remove-Item -Path $uplFile -Force -ErrorAction SilentlyContinue }
        Invoke-WebRequest -Uri $AlyaAzureBrandingBackgroundImage -OutFile $uplFile
    }
    try
    {
        Update-MgOrganizationBranding -OrganizationId $AlyaTenantId -BackgroundImageInputFile $uplFile
    }
    catch
    {
        Write-Warning "Update-MgOrganizationBranding still not working, please update backgroundImage by hand"
    }
    if ($uplFile -ne $AlyaAzureBrandingBackgroundImage) { Remove-Item -Path $uplFile -Force -ErrorAction SilentlyContinue }
}

# Setting branding squareLogo
Write-Host "Setting branding squareLogo" -ForegroundColor $CommandInfo
if ([string]::IsNullOrEmpty($AlyaAzureBrandingSquareLogo) -or $AlyaAzureBrandingSquareLogo -eq "PleaseSpecify")
{
    Write-Host "No branding squareLogo specified"
}
else
{
    $uplFile = $AlyaAzureBrandingSquareLogo
    if ($AlyaAzureBrandingSquareLogo.StartsWith("http"))
    {
        $fileName = Split-Path -Path $AlyaAzureBrandingSquareLogo -Leaf
        $uplFile = Join-Path $env:TEMP $fileName
        if (Test-Path $uplFile) { Remove-Item -Path $uplFile -Force -ErrorAction SilentlyContinue }
        Invoke-WebRequest -Uri $AlyaAzureBrandingSquareLogo -OutFile $uplFile
    }
    try
    {
        Update-MgOrganizationBranding -OrganizationId $AlyaTenantId -SquareLogoInputFile $uplFile
    }
    catch
    {
        Write-Warning "Update-MgOrganizationBranding still not working, please update squareLogo by hand"
    }
    if ($uplFile -ne $AlyaAzureBrandingSquareLogo) { Remove-Item -Path $uplFile -Force -ErrorAction SilentlyContinue }
}

# Setting branding squareLogoDark
Write-Host "Setting branding squareLogoDark" -ForegroundColor $CommandInfo
if ([string]::IsNullOrEmpty($AlyaAzureBrandingSquareLogoDark) -or $AlyaAzureBrandingSquareLogoDark -eq "PleaseSpecify")
{
    Write-Host "No branding squareLogoDark specified"
}
else
{
    $uplFile = $AlyaAzureBrandingSquareLogoDark
    if ($AlyaAzureBrandingSquareLogoDark.StartsWith("http"))
    {
        $fileName = Split-Path -Path $AlyaAzureBrandingSquareLogoDark -Leaf
        $uplFile = Join-Path $env:TEMP $fileName
        if (Test-Path $uplFile) { Remove-Item -Path $uplFile -Force -ErrorAction SilentlyContinue }
        Invoke-WebRequest -Uri $AlyaAzureBrandingSquareLogoDark -OutFile $uplFile
    }
    try
    {
        Update-MgOrganizationBranding -OrganizationId $AlyaTenantId -SquareLogoDarkInputFile $uplFile
    }
    catch
    {
        Write-Warning "Update-MgOrganizationBranding still not working, please update squareLogoDark by hand"
    }
    if ($uplFile -ne $AlyaAzureBrandingSquareLogoDark) { Remove-Item -Path $uplFile -Force -ErrorAction SilentlyContinue }
}

# Setting branding bannerLogo
Write-Host "Setting branding bannerLogo" -ForegroundColor $CommandInfo
if ([string]::IsNullOrEmpty($AlyaAzureBrandingBannerLogo) -or $AlyaAzureBrandingBannerLogo -eq "PleaseSpecify")
{
    Write-Host "No branding bannerLogo specified"
}
else
{
    $uplFile = $AlyaAzureBrandingBannerLogo
    if ($AlyaAzureBrandingBannerLogo.StartsWith("http"))
    {
        $fileName = Split-Path -Path $AlyaAzureBrandingBannerLogo -Leaf
        $uplFile = Join-Path $env:TEMP $fileName
        if (Test-Path $uplFile) { Remove-Item -Path $uplFile -Force -ErrorAction SilentlyContinue }
        Invoke-WebRequest -Uri $AlyaAzureBrandingBannerLogo -OutFile $uplFile
    }
    #$stream = [System.IO.File]::Open($uplFile,[System.IO.FileMode]::Open)
    #Set-MgOrganizationBrandingBannerLogo -OrganizationId $AlyaTenantId -InFile $uplFile
    #$stream.Close()
    #Get-MgOrganizationBrandingBannerLogo -OrganizationId $AlyaTenantId -OutFile $uplFile
    try
    {
        Update-MgOrganizationBranding -OrganizationId $AlyaTenantId -BannerLogoInputFile $uplFile
    }
    catch
    {
        Write-Warning "Update-MgOrganizationBranding still not working, please update bannerLogo by hand"
    }
    if ($uplFile -ne $AlyaAzureBrandingBannerLogo) { Remove-Item -Path $uplFile -Force -ErrorAction SilentlyContinue }
}

# Setting branding favicon
Write-Host "Setting branding favicon" -ForegroundColor $CommandInfo
if ([string]::IsNullOrEmpty($AlyaAzureBrandingFavicon) -or $AlyaAzureBrandingFavicon -eq "PleaseSpecify")
{
    Write-Host "No branding favicon specified"
}
else
{
    $uplFile = $AlyaAzureBrandingFavicon
    if ($AlyaAzureBrandingFavicon.StartsWith("http"))
    {
        $fileName = Split-Path -Path $AlyaAzureBrandingFavicon -Leaf
        $uplFile = Join-Path $env:TEMP $fileName
        if (Test-Path $uplFile) { Remove-Item -Path $uplFile -Force -ErrorAction SilentlyContinue }
        Invoke-WebRequest -Uri $AlyaAzureBrandingFavicon -OutFile $uplFile
    }
    try
    {
        Update-MgOrganizationBranding -OrganizationId $AlyaTenantId -FaviconInputFile $uplFile
    }
    catch
    {
        Write-Warning "Update-MgOrganizationBranding still not working, please update favicon by hand"
    }
    if ($uplFile -ne $AlyaAzureBrandingFavicon) { Remove-Item -Path $uplFile -Force -ErrorAction SilentlyContinue }
}

Write-Host "Finish configuration of CI/CD: O365Admin->Settings->Organisation"
Write-Host $AlyaLogoUrlLong
start "https://admin.microsoft.com/Adminportal/Home?source=applauncher#/Settings/OrganizationProfile/:/Settings/L1/CustomThemes"
pause

Write-Host "Finish configuration of CI/CD: Azure->AAD->CompanyBranding"
start "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
pause

#Stopping Transscript
Stop-Transcript
