#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2021

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
    Date       Author     Description
    ---------- -------------------- ----------------------------
    13.03.2019 Konrad Brunner       Initial Version



Picture sizes:
    AD   96*96
    SP-S 48*48
    SP-M 72*72
    SP-L 200*200


#>

# Parameters
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string]$upn,
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string]$image
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\onprem\Set-O365ProfilePic-$($AlyaTimeString).log" | Out-Null

#Checking modules
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

#Main
Write-Host "Setting profile picture in O365 for user $($upn) to $($image)" -ForegroundColor $CommandInfo

#Checking configuration
Write-Host "  Checking configuration"
if (-Not (Test-Path "$PSScriptRoot\configuration.xml"))
{
    Write-Host "    Creating configuration.xml"
    $config = [XML]@"
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <tenantName>$AlyaTenantName</tenantName>
  <pictureSourceCsv>userlist.csv</pictureSourceCsv>
  <targetLibraryPath>/User Photos/Profile Pictures</targetLibraryPath>
  <thumbs upload3Thumbs="true" createSMLThumbs="true"/> 
  <additionalProfileProperties>
    <property name="SPS-PictureExchangeSyncState" value="0"/>
  </additionalProfileProperties>
  <logFile path="log.txt" enableLogging="true" loggingLevel="verbose" />
  <uploadDelay>500</uploadDelay>
</configuration>
"@
    $config | Set-Content -Path "$PSScriptRoot\configuration.xml" -Force -Encoding UTF8
}

#Setting exchange photo
Write-Host "Setting Exchange photo" -ForegroundColor $CommandInfo
LoginTo-IPPS
if ((Get-User -Identity $upn))
{
    $photo = Get-UserPhoto -Identity $upn -ErrorAction SilentlyContinue
    if ($photo)
    {
        #TODO Backup existing
    }
    Set-UserPhoto -Identity $upn -PictureData ([System.IO.File]::ReadAllBytes($image)) -Confirm:$false -ErrorAction Continue
}
else
{
    Write-Host "  User does not exist in O365"
}
DisconnectFrom-EXOandIPPS

#Setting SharePoint photo
Write-Host "Setting SharePoint photo" -ForegroundColor $CommandInfo
if (-not $global:credAzAD) { $global:credAzAD = Get-Credential -Message "Enter SharePoint Online user and password:" }
Push-Location $actPath
"UPN,Image`n$($upn),$($image)" | Set-Content -Path userlist.csv -Force -Confirm:$false
.\ProfilePictureUploader\ProfilePictureUploader.exe -SPOAdmin $global:credAzAD.UserName -SPOAdminPassword ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($global:credAzAD.Password))) -Configuration ..\configuration.xml
Pop-Location

#Stopping Transscript
Stop-Transcript