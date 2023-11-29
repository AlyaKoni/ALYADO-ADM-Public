#Requires -Version 2

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


#>

#
# Downloading Setup Exe
#

$setupDownloadUrl = "https://www.barco.com/en/support/software/r3306194"

Write-Host "`n`n"
Write-Host "ClickShare download"
Write-Host "====================="
Write-Host "We launch now a browser with the ClickShare setup download page."
Write-Host "Please click 'Download'"
Write-Host "`n"
pause
Write-Host "`n"

$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $null = New-Item -Path $contentRoot -ItemType Directory -Force
}
$profile = [Environment]::GetFolderPath("UserProfile")
$downloads = $profile+"\downloads"
$lastfilename = $null
$file = Get-ChildItem -path $downloads | sort LastWriteTime | Select-Object -last 1
if ($file)
{
    $lastfilename = $file.Name
}
$filename = $null
$attempts = 10
while ($attempts -ge 0)
{
    Write-Host "Downloading setup file from $setupDownloadUrl"
    Write-Warning "Please don't start any other download!"
    try {
        Start-Process "$setupDownloadUrl"
        do
        {
            Start-Sleep -Seconds 10
            $file = Get-ChildItem -path $downloads | sort LastWriteTime | Select-Object -last 1
            if ($file)
            {
                $filename = $file.Name
                if ($filename.Contains(".crdownload")) { $filename = $lastfilename }
                if ($filename.Contains(".partial")) { $filename = $lastfilename }
                if ($filename.Contains(".tmp")) { $filename = $lastfilename }
            }
        } while ($lastfilename -eq $filename)
        $attempts = -1
    } catch {
        Write-Host "Catched exception $($_.Exception.Message)"
        Write-Host "Retrying $attempts times"
        $attempts--
        if ($attempts -lt 0) { throw }
        Start-Sleep -Seconds 10
    }
}
Start-Sleep -Seconds 3
if ($filename)
{
    $sourcePath = $downloads+"\"+$filename
    $tmpPath = (Join-Path $contentRoot "Tmp")
    if (-Not (Test-Path $tmpPath))
    {
        New-Item -Path $tmpPath -ItemType "Directory" -Force
    }
	$cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
	if ($cmdTst)
	{
		Expand-Archive -Path $sourcePath -DestinationPath $tmpPath -Force #AlyaAutofixed
	}
	else
	{
		Expand-Archive -Path $sourcePath -OutputPath $tmpPath -Force #AlyaAutofixed
	}
    Move-Item -Path (Join-Path $tmpPath "ClickShare_Installer.msi") -Destination $contentRoot -Force
    Remove-Item -Path $tmpPath -Recurse -Force
    Remove-Item -Path $sourcePath -Force
}
else
{
    throw "We were not able to download the setup"
}
