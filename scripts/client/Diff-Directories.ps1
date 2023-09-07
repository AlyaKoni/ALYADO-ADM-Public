#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2023

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
    10.08.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$leftDirectory,
    [Parameter(Mandatory = $true)]
    [string]$rightDirectory
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\client\Diff-Directories-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ImportExcel"

# =============================================================
# Local stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "FileSystem | Diff-Directories | Local" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$onlyLeftFiles = [System.Collections.ArrayList]@()
$onlyRightFiles = [System.Collections.ArrayList]@()
$onlyLeftDirs = [System.Collections.ArrayList]@()
$onlyRightDirs = [System.Collections.ArrayList]@()
$errorsLeft = [System.Collections.ArrayList]@()
$errorsRight = [System.Collections.ArrayList]@()
$diffSize = [System.Collections.ArrayList]@()
$diffDate = [System.Collections.ArrayList]@()
$diffProps = [System.Collections.ArrayList]@()

function Traverse($left, $right)
{
    Write-Host "  $left"
    try
    {
        $leftDirNames = (Get-ChildItem -Path $left -Directory -Force -ErrorAction Stop).Name
        $leftFileNames = (Get-ChildItem -Path $left -File -Force -ErrorAction Stop).Name
    }
    catch
    {
        if (-Not $errorsLeft.Contains($left))
        {
            $errorsLeft.Add($left) | Out-Null
        }
        return
    }
    try
    {
        $rightDirNames = (Get-ChildItem -Path $right -Directory -Force -ErrorAction Stop).Name
        $rightFileNames = (Get-ChildItem -Path $right -File -Force -ErrorAction Stop).Name
    }
    catch
    {
        if (-Not $errorsRight.Contains($right))
        {
            $errorsRight.Add($right) | Out-Null
        }
        return
    }
    foreach($leftDirName in $leftDirNames)
    {
        if ($rightDirNames -notcontains $leftDirName)
        {
            $onlyLeftDirs.Add($left+"\"+$leftDirName) | Out-Null
        }
        else
        {
            Traverse -left ($left+"\"+$leftDirName) -right ($right+"\"+$leftDirName)
        }
    }
    foreach($rightDirName in $rightDirNames)
    {
        if ($leftDirNames -notcontains $rightDirName)
        {
            $onlyrightDirs.Add($right+"\"+$rightDirName) | Out-Null
        }
    }
    $objShell = New-Object -ComObject Shell.Application
    $objFolderLeft = $objShell.namespace($left)
    $objFolderRight = $objShell.namespace($right)
    foreach($leftFileName in $leftFileNames)
    {
        if ($rightFileNames -notcontains $leftFileName)
        {
            $onlyLeftFiles.Add($left+"\"+$leftFileName) | Out-Null
        }
        else
        {
            try
            {
                $leftItem = Get-Item ($left+"\"+$leftFileName) -Force
            }
            catch
            {
                if (-Not $errorsLeft.Contains($left+"\"+$leftFileName))
                {
                    $errorsLeft.Add($left+"\"+$leftFileName) | Out-Null
                }
                continue
            }
            try
            {
                $rightItem = Get-Item ($right+"\"+$leftFileName) -Force
            }
            catch
            {
                if (-Not $errorsLeft.Contains($right+"\"+$leftFileName))
                {
                    $errorsLeft.Add($right+"\"+$leftFileName) | Out-Null
                }
                continue
            }
            if ($leftItem.Length -ne $rightItem.Length)
            {
                $diffSize.Add([pscustomobject]@{
                    Left = $leftItem.Length
                    Right  = $rightItem.Length
                    Path = $left+"\"+$leftFileName
                }) | Out-Null
            }
            if ($leftItem.LastWriteTime -ne $rightItem.LastWriteTime)
            {
                $diffDate.Add([pscustomobject]@{
                    Left = $leftItem.LastWriteTime
                    Right  = $rightItem.LastWriteTime
                    Path = $left+"\"+$leftFileName
                }) | Out-Null
            }
            $objFolderFileLeft = $objFolderLeft.Items() | where { $_.Name -eq $leftFileName }
            $objFolderFileRight = $objFolderRight.Items() | where { $_.Name -eq $leftFileName }
            for ($a = 0 ; $a  -le 400; $a++)
            { 
                $NameLeft = $objFolderLeft.getDetailsOf($objFolderFileLeft.Path, $a)
                if ($NameLeft -in @("Ordnerpfad","Ordner","Pfad","Folderpath","Folder path","Folder","Path")) { continue }
                $ValueLeft = $objFolderLeft.getDetailsOf($objFolderFileLeft, $a)
                $ValueRight = $objFolderRight.getDetailsOf($objFolderFileRight, $a)
                if(($ValueLeft -or $ValueRight) -and ($ValueLeft -ne $ValueRight))
                {
                    $diffProps.Add([pscustomobject]@{
                        Name = $NameLeft
                        Left = $ValueLeft
                        Right = $ValueRight
                        Path = $leftItem.FullName
                    }) | Out-Null
                }
            }
        }
    }
    foreach($rightFileName in $rightFileNames)
    {
        if ($leftFileNames -notcontains $rightFileName)
        {
            $onlyrightFiles.Add($right+"\"+$rightFileName) | Out-Null
        }
    }
}

Write-Host "Left: $leftDirectory" -ForegroundColor $CommandInfo
Write-Host "Right: $rightDirectory" -ForegroundColor $CommandInfo
Write-Host "========================================================================`n" -ForegroundColor $CommandInfo
Traverse -left $leftDirectory -right $rightDirectory
Write-Host "`n`n========================================================================`n" -ForegroundColor $CommandInfo

Write-Host "`nErrors on left (access issue?)" -ForegroundColor $CommandInfo
Write-Host "------------------------------------------------------------------------" -ForegroundColor $CommandInfo
foreach($item in $errorsLeft)
{
    Write-Host $item
}

Write-Host "`nErrors on right (access issue?)" -ForegroundColor $CommandInfo
Write-Host "------------------------------------------------------------------------" -ForegroundColor $CommandInfo
foreach($item in $errorsRight)
{
    Write-Host $item
}

$outputFile = "$AlyaData\client\Diff-Directories-$($AlyaTimeString).xlsx"
$excel = $onlyLeftDirs | Export-Excel -Path $outputFile -WorksheetName "onlyLeftDirs" -AutoSize -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $onlyRightDirs | Export-Excel -Path $outputFile -WorksheetName "onlyRightDirs" -AutoSize -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $onlyLeftFiles | Export-Excel -Path $outputFile -WorksheetName "onlyLeftFiles" -AutoSize -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $onlyRightFiles | Export-Excel -Path $outputFile -WorksheetName "onlyRightFiles" -AutoSize -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $diffSize | Export-Excel -Path $outputFile -WorksheetName "diffSize" -TableName "diffSize" -AutoSize -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $diffDate | Export-Excel -Path $outputFile -WorksheetName "diffDate" -TableName "diffDate" -AutoSize -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $diffProps | Export-Excel -Path $outputFile -WorksheetName "diffProps" -TableName "diffProps" -AutoSize -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru
Close-ExcelPackage $excel -Show

Report stored in $outputFile

<#
$onlyLeftDirs | Out-GridView -Title "Directories only left"
$onlyRightDirs | Out-GridView -Title "Directories only right"
$onlyLeftFiles | Out-GridView -Title "Files only left"
$onlyRightFiles | Out-GridView -Title "Files only right"
$diffSize | Out-GridView -Title "Files with different size"
$diffDate | Out-GridView -Title "Files with different write date"
$diffProps | Out-GridView -Title "Files with different properties"
#>

#Stopping Transscript
Stop-Transcript
