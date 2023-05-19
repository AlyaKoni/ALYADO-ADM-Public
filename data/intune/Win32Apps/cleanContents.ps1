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

$rootDir = $PSScriptRoot

function Remove-OneDriveItemRecursive
{
    [cmdletbinding()]
    param(
        [string] $Path
    )
    if ($Path -and (Test-Path -LiteralPath $Path))
    {
        $Items = Get-ChildItem -LiteralPath $Path -File -Recurse
        foreach ($Item in $Items)
        {
            try
            {
                $Item.Delete()
            } catch
            {
                throw "Remove-OneDriveItemRecursive - Couldn't delete $($Item.FullName), error: $($_.Exception.Message)"
            }
        }
        $Items = Get-ChildItem -LiteralPath $Path -Directory -Recurse | Sort-object -Property { $_.FullName.Length } -Descending
        foreach ($Item in $Items)
        {
            try
            {
                $Item.Delete()
            } catch
            {
                throw "Remove-OneDriveItemRecursive - Couldn't delete $($Item.FullName), error: $($_.Exception.Message)"
            }
        }
        try
        {
            (Get-Item -LiteralPath $Path).Delete()
        } catch
        {
            throw "Remove-OneDriveItemRecursive - Couldn't delete $($Path), error: $($_.Exception.Message)"
        }
    } else
    {
        Write-Warning "Remove-OneDriveItemRecursive - Path $Path doesn't exists. Skipping. "
    }
}

$dirs = Get-ChildItem -Path $rootDir -Directory
foreach ($dir in $dirs)
{
    Write-Host "Cleaning $($dir.Name)"
    if ((Test-Path (Join-Path $dir.FullName "Content")) -or (Test-Path (Join-Path $dir.FullName "Content.deleteMe")))
    {
        $tmp = Remove-OneDriveItemRecursive -Path (Join-Path $dir.FullName "Content")
    }
    # Uncomment following block, if package directory should not be cleared
    if ((Test-Path (Join-Path $dir.FullName "Package")) -or (Test-Path (Join-Path $dir.FullName "Package.deleteMe")))
    {
        $tmp = Remove-OneDriveItemRecursive -Path (Join-Path $dir.FullName "Package")
    }
    <#if ($dir.Name -eq "LocalPrinters" -or $dir.Name -eq "LocalPrinters_unused")
    {
        $zipDir = Join-Path $dir.FullName "ContentZip"
        if ((Test-Path $zipDir))
        {
            $zdirs = Get-ChildItem -Path $zipDir -Directory
            foreach ($zdir in $zdirs)
            {
                $tmp = Remove-OneDriveItemRecursive -Path $zdir.FullName
            }
        }
    }#>
    if ($dir.Name -eq "AzInfoProtection")
    {
        $scriptDir = Join-Path $dir.FullName "Scripts"
        $todelPath = Join-Path $scriptDir "ServiceLocation.txt"
        $todelFile = Get-Item -Path $todelPath -ErrorAction SilentlyContinue
        if ($todelFile)
        {
            Remove-Item -Path $todelPath -Force
        }
    }
    if ($dir.Name -eq "AcroRdrDC")
    {
        $todelPath = Join-Path $dir.FullName "version.json"
        $todelFile = Get-Item -Path $todelPath -ErrorAction SilentlyContinue
        if ($todelFile)
        {
            Remove-Item -Path $todelPath -Force
        }
    }
}
