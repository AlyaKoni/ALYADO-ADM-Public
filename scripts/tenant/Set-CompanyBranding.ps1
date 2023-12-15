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
    25.11.2022 Konrad Brunner       Initial Version
    25.04.2023 Konrad Brunner       Switched to Graph
    04.08.2023 Konrad Brunner       Browser parameter

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
	[object]$browser
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-CompanyBranding-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"

# Logins
LoginTo-MgGraph -Scopes @("Organization.ReadWrite.All")

# =============================================================
# Azure stuff
# =============================================================

if (-Not $browser) {
    if ($Global:AlyaSeleniumBrowser) {
        $browser = $Global:AlyaSeleniumBrowser
    }
}

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-CompanyBranding | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting organisation
Write-Host "Getting organisation" -ForegroundColor $CommandInfo
$org = Get-MgBetaOrganization -OrganizationId $AlyaTenantId
$org | Format-List

# Setting organisation info
Write-Host "Setting organisation info" -ForegroundColor $CommandInfo
Update-MgBetaOrganization -OrganizationId $AlyaTenantId `
    -MarketingNotificationEmails @($AlyaGeneralInformEmail) `
    -PrivacyProfile @{
        contactEmail = $AlyaPrivacyEmail
        statementUrl = $AlyaPrivacyUrl
    } `
    -TechnicalNotificationMails @($AlyaSupportEmail)

# Getting act azure branding
Write-Host "Getting act branding" -ForegroundColor $CommandInfo
$branding = $null
try
{
    $branding = Get-MgBetaOrganizationBranding -OrganizationId $AlyaTenantId
} catch
{
    #TODO fix this
    Write-Warning "Branding does not exists, creating"
    Write-Warning "Please create default branding on the following page"
    Write-Warning "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
    if (-Not $browser) {
        Start-Process "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
    } else {
        $browser.Url =  "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
    }
    pause
    $branding = Get-MgBetaOrganizationBranding -OrganizationId $AlyaTenantId
}

# Setting azure branding
Write-Host "Setting branding" -ForegroundColor $CommandInfo
Update-MgBetaOrganizationBranding -OrganizationId $AlyaTenantId `
      -BackgroundColor $AlyaAzureBrandingBackgroundColor `
      -SignInPageText $AlyaAzureBrandingSignInPageTextDefault `
      -UsernameHintText $AlyaAzureBrandingUsernameHintTextDefault

$locs = Get-MgBetaOrganizationBrandingLocalization -OrganizationId $AlyaTenantId
$locDef = $locs | Where-Object { $_.Id -eq 0 }
$locEn = $locs | Where-Object { $_.Id -eq "en-US" }
$locDe = $locs | Where-Object { $_.Id -eq "de-de" }
$locFr = $locs | Where-Object { $_.Id -eq "fr-FR" }
$locIt = $locs | Where-Object { $_.Id -eq "it-IT" }
if ($locEn)
{
    Update-MgBetaOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -OrganizationalBrandingLocalizationId "en-US" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextEn `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextEn
}
else
{
    New-MgBetaOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -Id "en-US" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextEn `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextEn
}
if ($locDe)
{
    Update-MgBetaOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -OrganizationalBrandingLocalizationId "de-de" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextDe `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextDe
}
else
{
    New-MgBetaOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -Id "de-de" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextDe `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextDe
}
if ($locFr)
{
    Update-MgBetaOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -OrganizationalBrandingLocalizationId "fr-FR" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextFr `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextFr
}
else
{
    New-MgBetaOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -Id "fr-FR" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextFr `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextFr
}
if ($locIt)
{
    Update-MgBetaOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -OrganizationalBrandingLocalizationId "it-IT" `
        -BackgroundColor $AlyaAzureBrandingBackgroundColor `
        -SignInPageText $AlyaAzureBrandingSignInPageTextIt `
        -UsernameHintText $AlyaAzureBrandingUsernameHintTextIt
}
else
{
    New-MgBetaOrganizationBrandingLocalization -OrganizationId $AlyaTenantId -Id "it-IT" `
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
        Invoke-WebRequestIndep -Uri $AlyaAzureBrandingBackgroundImage -OutFile $uplFile
    }
    try
    {
        $params = @{  
            BackgroundImageInputFile = $uplFile
        }  
        Update-MgBetaOrganizationBranding -OrganizationId $AlyaTenantId -BodyParameter $params
    }
    catch
    {
        Write-Warning "Update-MgBetaOrganizationBranding still not working, please update backgroundImage by hand"
        Write-Warning "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        if (-Not $browser) {
            Start-Process "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        } else {
            $browser.Url =  "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        }
        pause
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
        Invoke-WebRequestIndep -Uri $AlyaAzureBrandingSquareLogo -OutFile $uplFile
    }
    try
    {
        $params = @{  
            SquareLogoInputFile = $uplFile
        }  
        Update-MgBetaOrganizationBranding -OrganizationId $AlyaTenantId -BodyParameter $params
    }
    catch
    {
        Write-Warning "Update-MgBetaOrganizationBranding still not working, please update squareLogo by hand"
        Write-Warning "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        if (-Not $browser) {
            Start-Process "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        } else {
            $browser.Url =  "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        }
        pause
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
        Invoke-WebRequestIndep -Uri $AlyaAzureBrandingSquareLogoDark -OutFile $uplFile
    }
    try
    {
        $params = @{  
            SquareLogoInputFile = $uplFile
        }  
        Update-MgBetaOrganizationBranding -OrganizationId $AlyaTenantId -BodyParameter $params
    }
    catch
    {
        Write-Warning "Update-MgBetaOrganizationBranding still not working, please update squareLogoDark by hand"
        Write-Warning "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        if (-Not $browser) {
            Start-Process "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        } else {
            $browser.Url =  "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        }
        pause
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
        Invoke-WebRequestIndep -Uri $AlyaAzureBrandingBannerLogo -OutFile $uplFile
    }
    #$stream = [System.IO.File]::Open($uplFile,[System.IO.FileMode]::Open)
    #Set-MgBetaOrganizationBrandingBannerLogo -OrganizationId $AlyaTenantId -InFile $uplFile
    #$stream.Close()
    #Get-MgBetaOrganizationBrandingBannerLogo -OrganizationId $AlyaTenantId -OutFile $uplFile
    try
    {
        $params = @{  
            BannerLogoInputFile = $uplFile
        }  
        Update-MgBetaOrganizationBranding -OrganizationId $AlyaTenantId -BodyParameter $params
    }
    catch
    {
        Write-Warning "Update-MgBetaOrganizationBranding still not working, please update bannerLogo by hand"
        Write-Warning "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        if (-Not $browser) {
            Start-Process "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        } else {
            $browser.Url =  "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        }
        pause
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
        Invoke-WebRequestIndep -Uri $AlyaAzureBrandingFavicon -OutFile $uplFile
    }
    try
    {
        $params = @{  
            FaviconInputFile = $uplFile
        }  
        Update-MgBetaOrganizationBranding -OrganizationId $AlyaTenantId -BodyParameter $params
    }
    catch
    {
        Write-Warning "Update-MgBetaOrganizationBranding still not working, please update favicon by hand"
        Write-Warning "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        if (-Not $browser) {
            Start-Process "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        } else {
            $browser.Url =  "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/LoginTenantBranding"
        }
        pause
    }
    if ($uplFile -ne $AlyaAzureBrandingFavicon) { Remove-Item -Path $uplFile -Force -ErrorAction SilentlyContinue }
}

Write-Host "Finish configuration of CI/CD: O365Admin->Settings->Organisation"
Write-Host "Logo: $AlyaLogoUrlLong"
Write-Host "Color Akcent: $($AlyaSpThemeDef.themePrimary)"
Write-Host "Color Nav: $($AlyaSpThemeDef.white)"
Write-Host "Color Text: $($AlyaSpThemeDef.neutralPrimary)"
Write-Host "Click Url: https://portal.office.com"
Write-Host "https://admin.microsoft.com/Adminportal/Home?source=applauncher#/Settings/OrganizationProfile/:/Settings/L1/CustomThemes"
if (-Not $browser) {
    Start-Process "https://admin.microsoft.com/Adminportal/Home?source=applauncher#/Settings/OrganizationProfile/:/Settings/L1/CustomThemes"
} else {
    $browser.Url =  "https://admin.microsoft.com/Adminportal/Home?source=applauncher#/Settings/OrganizationProfile/:/Settings/L1/CustomThemes"
}
pause

#Stopping Transscript
Stop-Transcript
