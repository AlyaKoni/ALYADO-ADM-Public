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
    22.04.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()] 
Param  
(
    [Parameter(Mandatory=$false)]
    [string]$SharePointUrl = "https://alyaconsulting031.sharepoint.com",
    [Parameter(Mandatory=$false)]
    [string]$DriveLetter = "S",
    [Parameter(Mandatory=$false)]
    [bool]$Persitent = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Map-SharePointSiteAsDrive-$($AlyaTimeString).log" | Out-Null

# Functions
function AuthenticateSharePoint
{
    $retries = 60*2
    try
    {
        $shell = New-Object -ComObject "Shell.Application"
        $ie = New-Object -ComObject "InternetExplorer.Application"
    }
    catch
    {
        Write-Host "Was not able to create ie process" -ForegroundColor Red
        return $false
    }
    $hwnd = $ie.hwnd
    $ie.Navigate2($SharePointUrl)
    while ($true)
    {
        Start-Sleep -Milliseconds 500
        $result = $shell.windows() | where { $_.HWND -eq $hwnd }
        if (-Not $result)
        {
            Write-Host "Was not able to launch ie" -ForegroundColor Red
            return $false
        }
        if ($result.Busy -eq $false -and $result.LocationURL -like "$SharePointUrl*")
        {
            $result.Quit()
            return $true
        }
        $retries--
        if ($retries -lt 0)
        {
            Write-Host "Login was not working" -ForegroundColor Red
            return $false
        }
    }
}

# Main
$SharePointUri = [System.Uri]$SharePointUrl
$SharePointUrl = $SharePointUri.Scheme+"://"+$SharePointUri.Host+$SharePointUri.AbsolutePath

$drive = Get-PSDrive -Name $DriveLetter -ErrorAction SilentlyContinue
if ($drive)
{
    Write-Host "Drive $drive already mapped" -ErrorAction SilentlyContinue -ForegroundColor Green
}
else
{
    # Checking WebClient Service
    $webClientService = Get-Service -Name "WebClient"
    if ($webClientService.Status -ne "Running")
    {
        Write-Host "WebClient service not running. Please contact your administrator" -ForegroundColor Red
        pause
        exit
    }

    # Checking trusted sites
    $uriFoundInZone = $false
    foreach ($keyPath in @(
        "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey"))
    {
        $regKey = Get-Item $keyPath -ErrorAction SilentlyContinue
        if ($regKey)
        {
            Foreach($regVal in $regKey.Property)
            {
                if ($SharePointUrl.ToLower().StartsWith($regVal.ToLower()))
                {
                    $Value = ($regKey | Get-ItemProperty).$($regVal)
                    if ($Value -ne 2 -and $Value -ne 1)
                    {
                        Write-Host "$uri is in the wrong zone" -ForegroundColor Red
                        pause
                        exit
                    }
                    $uriFoundInZone = $true
                }
            }
        }
    }
    foreach ($keyPath in @(
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains"))
    {
        $regKey = Get-Item $keyPath -ErrorAction SilentlyContinue
        if ($regKey)
        {
            foreach($domKeyName in $regKey.GetSubKeyNames())
            {
                $parentKeyPath = $regKey.PSPath+"\"+$domKeyName
                $parentKey = Get-Item $parentKeyPath
                foreach($siteKeyName in $parentKey.GetSubKeyNames())
                {
                    $uri = $siteKeyName+"."+$domKeyName
                    $siteKeyPath = $parentKey.PSPath+"\"+$siteKeyName
                    $siteKey = Get-Item $siteKeyPath
                    $httpsZone = $siteKey.GetValue("https")
                    $httpZone = $siteKey.GetValue("http")
                    if ($httpZone)
                    {
                        $uri = "http://"+$uri
                        if ($SharePointUrl.ToLower().StartsWith($uri.ToLower()))
                        {
                            if ($httpZone -ne 2 -and $httpZone -ne 1)
                            {
                                Write-Host "$uri is in the wrong zone" -ForegroundColor Red
                                pause
                                exit
                            }
                            $uriFoundInZone = $true
                        }
                    }
                    if ($httpsZone)
                    {
                        $uri = "https://"+$uri
                        if ($SharePointUrl.ToLower().StartsWith($uri.ToLower()))
                        {
                            if ($httpsZone -ne 2 -and $httpsZone -ne 1)
                            {
                                Write-Host "$uri is in the wrong zone" -ForegroundColor Red
                                pause
                                exit
                            }
                            $uriFoundInZone = $true
                        }
                    }
                }
            }
        }
    }
    if (-Not $uriFoundInZone)
    {
        $checkUri = [System.Uri]$SharePointUrl
        $checkUri = $checkUri.Scheme+"://"+$checkUri.Host
        Write-Host "$checkUri not found in your internet trusted sites. Please contact your administrator" -ForegroundColor Red
        pause
        exit
    }

    # Map Path as Network Drive
    $retries = 3
    do
    {
        try
        {
            $Network = New-Object -ComObject WScript.Network
            $Network.MapNetworkDrive("$($DriveLetter):",$SharePointUrl,$Persitent)
            break
        }
        catch
        {
            try { $Network.RemoveNetworkDrive("$($DriveLetter):") } catch { }
            AuthenticateSharePoint
            $retries--
            if ($retries -lt 0)
            {
                Write-Host "Not able to connect the drive" -ForegroundColor Red
                pause
                exit
            }
        }
    }
    while ($true)
}

try
{
    $itms = Get-ChildItem -Path "$($DriveLetter):\" -Force -ErrorAction Stop
}
catch
{
    Write-Host "Access not given. We have to reauthenticate" -ForegroundColor Red
    AuthenticateSharePoint
}

#Stopping Transscript
Stop-Transcript
