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
    16.11.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\prod\image\Create-ComputeGallery-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdImageResGrp)"
$GalleryName = "$($AlyaNamingPrefix)imgg$($AlyaResIdAvdImageResGrp)"
$VmToImage = "$($AlyaNamingPrefix)avdi$($AlyaResIdAvdImageClient)"
$ImageName = "$($VmToImage)_ImageClient"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "ImageHost | Create-ComputeGallery | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ResourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $ResourceGroupName -Location $AlyaLocation -Tag @{displayName="AVD Image";ownerEmail=$Context.Account.Id}
}

# Checking compute gallery
Write-Host "Checking compute gallery" -ForegroundColor $CommandInfo
$ImgGallery = Get-AzGallery -ResourceGroupName $ResourceGroupName -GalleryName $GalleryName -ErrorAction SilentlyContinue
if (-Not $ImgGallery)
{
    Write-Warning "Compute gallery not found. Creating the compute gallery $GalleryName"
    $ImgGallery = New-AzGallery -ResourceGroupName $ResourceGroupName -GalleryName $GalleryName -Location $AlyaLocation -Description "AVD Compute Gallery" -Tag @{displayName="AVD Compute Gallery";ownerEmail=$Context.Account.Id}
}

# Checking image definition
Write-Host "Checking image definition" -ForegroundColor $CommandInfo
$ImgDefinition = Get-AzGalleryImageDefinition -ResourceGroupName $ResourceGroupName -GalleryName $GalleryName -Name $ImageName -ErrorAction SilentlyContinue
if (-Not $ImgDefinition)
{
    Write-Warning "Image definition not found. Creating the image definition $ImageName"
    $sku = (Get-AzVMImageSku -Location $AlyaLocation -PublisherName "MicrosoftWindowsDesktop" -Offer "office-365" | Where-Object { $_.Skus -like "win10*avd*" } | Select-Object -Last 1).Skus
    if ($AlyaAvdHypervisorVersion -eq "V1")
    {
        $sku = (Get-AzVMImageSku -Location $AlyaLocation -PublisherName "MicrosoftWindowsDesktop" -Offer "office-365" | Where-Object { $_.Skus -like "win10*avd*" -and $_.Skus -notlike "*-g2" } | Select-Object -Last 1).Skus
    }
    $ImgDefinition = New-AzGalleryImageDefinition -ResourceGroupName $ResourceGroupName -GalleryName $GalleryName -Name $ImageName -Location $AlyaLocation `
                       -OsState "Generalized" -OsType "Windows" -Publisher "MicrosoftWindowsDesktop" -Offer "office-365" -Sku $sku `
                       -HyperVGeneration $AlyaAvdHypervisorVersion -Tag @{displayName="AVD Client Image";ownerEmail=$Context.Account.Id}
}

# Checking vm image
Write-Host "Checking vm image" -ForegroundColor $CommandInfo
$image = Get-AzImage -ResourceGroupName $ResourceGroupName -ImageName $ImageName -ErrorAction SilentlyContinue
if (-Not $image)
{
    throw "VM image $ImageName not found. Please create it with the script Prepare-ImageClient"
}

# Checking image version
Write-Host "Checking image version" -ForegroundColor $CommandInfo
$ImgVersion = Get-AzGalleryImageVersion -ResourceGroupName $ResourceGroupName -GalleryName $GalleryName -GalleryImageDefinitionName $ImageName -ErrorAction SilentlyContinue
if (-Not $ImgVersion)
{
    $versionString = (Get-Date).ToString("yyyy.MMdd.HHmm")
    Write-Warning "Image version not found. Creating the image version $versionString"
    if ($AlyaLocation -eq $AlyaAvdSessionHostLocation)
    {
        $region1 = @{Name=$AlyaLocation;ReplicaCount=1}
        $targetRegions = @($region1)
    }
    else
    {
        $region1 = @{Name=$AlyaLocation;ReplicaCount=1}
        $region2 = @{Name=$AlyaAvdSessionHostLocation;ReplicaCount=1}
        $targetRegions = @($region1,$region2)
    }
    $ImgVersion = New-AzGalleryImageVersion -ResourceGroupName $ResourceGroupName -GalleryName $GalleryName `
                    -GalleryImageDefinitionName $ImageName -Location $AlyaLocation `
                    -GalleryImageVersionName $versionString -TargetRegion $targetRegions -SourceImageId $image.Id.ToString() `
                    -PublishingProfileEndOfLifeDate '2099-12-31' -Tag @{displayName="AVD Client Image Version";ownerEmail=$Context.Account.Id}
}
else
{
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Creates a new image version from the existing image"
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","Does not create a new image version."
    #$cancel = New-Object System.Management.Automation.Host.ChoiceDescription "&Cancel","Description."
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $title = "Compute Gallery"
    $message = "Create a new image version?"
    $result = $host.ui.PromptForChoice($title, $message, $options, 1)
    switch ($result) {
      0{
            $versionString = (Get-Date).ToString("yyyy.MMdd.HHmm")
            Write-Warning "Creating new image version $versionString"
            if ($AlyaLocation -eq $AlyaAvdSessionHostLocation)
            {
                $region1 = @{Name=$AlyaLocation;ReplicaCount=1}
                $targetRegions = @($region1)
            }
            else
            {
                $region1 = @{Name=$AlyaLocation;ReplicaCount=1}
                $region2 = @{Name=$AlyaAvdSessionHostLocation;ReplicaCount=1}
                $targetRegions = @($region1,$region2)
            }
            $ImgVersion = New-AzGalleryImageVersion -ResourceGroupName $ResourceGroupName -GalleryName $GalleryName `
                            -GalleryImageDefinitionName $ImageName -Location $AlyaLocation `
                            -GalleryImageVersionName $versionString -TargetRegion $targetRegions -SourceImageId $image.Id.ToString() `
                            -PublishingProfileEndOfLifeDate '2099-12-31' -Tag @{displayName="AVD Client Image Version";ownerEmail=$Context.Account.Id}
      }
    }
}

#Stopping Transscript
Stop-Transcript
