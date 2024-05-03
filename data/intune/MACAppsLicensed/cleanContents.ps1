#Requires -Version 2

<#
    Copyright (c) Alya Consulting, 2019-2024

    THIS FILE IS **NOT** PART OF THE ALYA BASE CONFIGURATION!	
    This unpublished material is proprietary to Alya Consulting.
    All rights reserved. The methods and techniques described
    herein are considered trade secrets and/or confidential. 
    Reproduction or distribution, in whole or in part, is 
    forbidden except by express written permission of Alya Consulting.

    DIESE DATEI IST **NICHT** BESTANDTEIL DER ALYA BASIS KONFIGURATION!
    Dieses unveröffentlichte Material ist Eigentum von Alya Consulting.
    Alle Rechte vorbehalten. Die beschriebenen Methoden und Techniken
    werden hierin als Geschäftsgeheimnisse und/oder vertraulich betrachtet. 
    Die Reproduktion oder Verteilung, ganz oder teilweise, ist 
    verboten, ausser mit ausdrücklicher schriftlicher Genehmigung von Alya Consulting.


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
    if ((Test-Path (Join-Path $dir.FullName "Content")))
    {
        $null = Remove-OneDriveItemRecursive -Path (Join-Path $dir.FullName "Content")
    }
    # Uncomment following block, if package directory should not be cleared
    if ((Test-Path (Join-Path $dir.FullName "Package")))
    {
        $null = Remove-OneDriveItemRecursive -Path (Join-Path $dir.FullName "Package")
    }
}
