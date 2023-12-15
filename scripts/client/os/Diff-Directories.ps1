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
    15.03.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$leftDirectory,
    [Parameter(Mandatory = $true)]
    [string]$rightDirectory
)

#Members
$CommandInfo = "Cyan"
$CommandSuccess = "Cyan"
Write-Host "Constants and Preparation" -ForegroundColor $CommandInfo
$Global:ErrorActionPreference = "Stop"
$Global:ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$AlyaDefaultModulePath = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "WindowsPowerShell\Modules"
if (-Not $AlyaModulePath)
{
    $AlyaModulePath = $AlyaDefaultModulePath
}
$paramSetName = $PSCmdlet.ParameterSetName
if ($AlyaModulePath -ne $AlyaDefaultModulePath)
{
    if (-Not (Test-Path $AlyaModulePath))
    {
        New-Item -Path $AlyaModulePath -ItemType Directory -Force
    }
    if (-Not $env:PSModulePath.StartsWith("$($AlyaModulePath)"))
    {
        $env:PSModulePath = "$($AlyaModulePath);"+$env:PSModulePath
    }
}

#Functions
function Is-InternetConnected()
{
    $ret = Test-NetConnection -ComputerName 8.8.8.8 -Port 443 -ErrorAction SilentlyContinue -InformationLevel Quiet
    if (-Not $ret)
    {
        $ret = Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -ErrorAction SilentlyContinue -InformationLevel Quiet
    }
    return $ret
}
function Get-PublishedModuleVersion(
    [string] [Parameter(Mandatory = $true)] $moduleName
)
{
   $url = "https://www.powershellgallery.com/packages/$moduleName/?dummy=$(Get-Random)"
   $request = [System.Net.WebRequest]::Create($url)
   $request.AllowAutoRedirect=$false
   try
   {
     $response = $request.GetResponse()
     $response.GetResponseHeader("Location").Split("/")[-1] -as [Version]
     $response.Close()
     $response.Dispose()
   }
   catch
   {
     Write-Warning $_.Exception.Message
   }
}
function Install-ModuleIfNotInstalled (
    [string] [Parameter(Mandatory = $true)] $moduleName,
    [Version] $minimalVersion = "0.0.0.0",
    [Version] $exactVersion = "0.0.0.0",
    [bool] $autoUpdate = $true
)
{
    if (-Not (Is-InternetConnected))
    {
        Write-Warning "No internet connection. Not able to check any module!"
        return
    }
    $gmCmd = Get-Command Get-Module
    if (-Not $gmCmd)
    {
        throw "Can't find cmdlt Get-Module"
    }
    $pkg = Get-Module -Name "PackageManagement" -ListAvailable | Sort-Object -Property Version | Select-Object -Last 1
    if ($moduleName -ne "PackageManagement" -and (-Not $pkg -or $pkg.Version -lt [Version]"1.4.7"))
    {
        Install-ModuleIfNotInstalled "PackageManagement"
        throw "PackageManagement updated! Please restart your powershell session"
    }
    $regRep = Get-PSRepository -Name "PSGallery" -ErrorAction SilentlyContinue
    if (-Not $regRep)
    {
        Register-PSRepository -Name "PSGallery" -SourceLocation "https://www.powershellgallery.com/api/v2/" -PublishLocation "https://www.powershellgallery.com/api/v2/package/" -ScriptSourceLocation "https://www.powershellgallery.com/api/v2/items/psscript/" -ScriptPublishLocation "https://www.powershellgallery.com/api/v2/package/" -InstallationPolicy Trusted -PackageManagementProvider NuGet
    }
    else
    {
        if ($regRep.InstallationPolicy -ne "Trusted")
        {
	        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
        }
    }
    $psg = Get-Module -Name PowerShellGet -ListAvailable | Sort-Object -Property Version | Select-Object -Last 1
    if ($moduleName -ne "PackageManagement" -and $moduleName -ne "PowerShellGet" -and (-Not $psg -or $psg.Version -lt [Version]"2.0.0.0"))
    {
        Install-ModuleIfNotInstalled "PowerShellGet"
        throw "PowerShellGet updated! Please restart your powershell session"
    }
    if ((Get-PackageProvider -Name NuGet -Force).Version -lt '2.8.5.201')
    {
        Write-Warning "Installing nuget"
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
    }
    $requestedVersion = $minimalVersion
    [Version] $newestVersion = Get-PublishedModuleVersion $moduleName
    if (-Not $newestVersion)
    {
        Write-Warning "Module '$moduleName' does not looks like a module from Powershell Gallery"
        return
    }
    if ($exactVersion -ne "0.0.0.0")
    {
        $module = Get-Module -Name $moduleName -ListAvailable |`
            Where-Object { $_.Version -eq $exactVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            try
            {
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                    Where-Object { $_.Version -eq $exactVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            catch
            {
                Import-Module -Name PowerShellGet
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                    Where-Object { $_.Version -eq $exactVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            if (-Not $module)
            {
                $module = Get-Module -FullyQualifiedName "$AlyaModulePath\$moduleName" -ListAvailable -ErrorAction SilentlyContinue | Sort-Object -Property Version | Select-Object -Last 1
            }
        }
        $autoUpdate = $false
        $requestedVersion = $exactVersion
    }
    else
    {
        $module = Get-Module -Name $moduleName -ListAvailable |`
            Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            try
            {
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                    Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            catch
            {
                Import-Module -Name PowerShellGet
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                    Where-Object { $_.Version -ge $minimalVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            if (-Not $module)
            {
                $module = Get-Module -FullyQualifiedName "$AlyaModulePath\$moduleName" -ListAvailable -ErrorAction SilentlyContinue | Sort-Object -Property Version | Select-Object -Last 1
            }
        }
        $requestedVersion = $newestVersion
    }
    if ($module)
    {
        Write-Host ('Module {0} is installed. Used:v{1} Requested:v{2}' -f $moduleName, $module.Version, $requestedVersion)
        if ((-Not $autoUpdate) -and ($newestVersion -gt $module.Version))
        {
            Write-Warning ("A newer version (v{0}) is available. Consider upgrading!" -f $newestVersion)
        }
        if ($newestVersion -eq $module.Version)
        {
            $autoUpdate = $false
        }
    }
    else
    {
        Write-Host ('Module {0} not found with requested version v{1}. Installing now...' -f $moduleName, $requestedVersion)
        $autoUpdate = $true
    }
    if ($autoUpdate)
    {
        $instCmd = Get-Command Install-Module
        if (-Not $instCmd)
        {
            throw "Please install the powershell package management"
        }
        $optionalArgs = New-Object -TypeName Hashtable
        $optionalArgs['RequiredVersion'] = $requestedVersion
        Write-Warning ('Installing/Updating module {0} to version [{1}] within scope of the current user.' -f $moduleName, $requestedVersion)
        #TODO Unload module
        $paramIM = (Get-Command Install-Module).ParameterSets | Select-Object -ExpandProperty Parameters | Where-Object { $_.Name -eq "AcceptLicense" }
        if ($paramIM)
        {
	        if ($AlyaModulePath -eq $AlyaDefaultModulePath)
	        {
	            Install-Module -Name $moduleName @optionalArgs -Scope CurrentUser -AllowClobber -Force -Verbose -AcceptLicense
	        }
	        else
	        {
                Save-Module -Name $moduleName -RequiredVersion $requestedVersion -Path $AlyaModulePath -Force -Verbose -AcceptLicense
	        }
        }
        else
        {
	        if ($AlyaModulePath -eq $AlyaDefaultModulePath)
	        {
	            Install-Module -Name $moduleName @optionalArgs -Scope CurrentUser -AllowClobber -Force -Verbose
	        }
	        else
	        {
                Save-Module -Name $moduleName -RequiredVersion $requestedVersion -Path $AlyaModulePath -Force -Verbose
	        }
        }
        $module = Get-Module -Name $moduleName -ListAvailable |`
            Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
        if (-Not $module)
        {
            try
            {
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                    Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            catch
            {
                Import-Module -Name PowerShellGet
                $module = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue |`
                    Where-Object { $_.Version -eq $requestedVersion } | Sort-Object -Property Version | Select-Object -Last 1
            }
            if (-Not $module)
            {
                $module = Get-Module -FullyQualifiedName "$AlyaModulePath\$moduleName" -ListAvailable -ErrorAction SilentlyContinue | Sort-Object -Property Version | Select-Object -Last 1
                if (-Not $module)
	            {
	                Write-Error "Not able to install the module!" -ErrorAction Continue
	                exit
	            }
	        }
	    }
    }
    if ($exactVersion -ne "0.0.0.0")
    {
        $module = Get-Module -Name $moduleName
        if ($module -and $module.Version -ne $exactVersion)
        {
            Remove-Module -Name $moduleName
        }
        Import-Module -Name $moduleName -RequiredVersion $exactVersion -DisableNameChecking
    }
}
function Wait-UntilProcessEnds(
    [string] [Parameter(Mandatory = $true)] $processName)
{
    $maxStartTries = 10
    $startTried = 0
    do
    {
        $prc = Get-Process -Name $processName -ErrorAction SilentlyContinue
        $startTried = $startTried + 1
        if ($startTried -gt $maxStartTries)
        {
            $prc = "Continue"
        }
    } while (-Not $prc)
    do
    {
        Start-Sleep -Seconds 5
        $prc = Get-Process -Name $processName -ErrorAction SilentlyContinue
    } while ($prc)
}
function Restart-Transscipt
{
    try
    {
        $oFile = New-Object System.IO.FileInfo $logPath
        $oStream = $oFile.Open([System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        if ($oStream) { $oStream.Close() }
        Start-Transcript -Path $logPath -Append -IncludeInvocationHeader:$false | Out-Null
    } catch { }
}

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
            $objFolderFileLeft = $objFolderLeft.Items() | Where-Object { $_.Name -eq $leftFileName }
            $objFolderFileRight = $objFolderRight.Items() | Where-Object { $_.Name -eq $leftFileName }
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

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ImportExcel"

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

$outputFile = "$PSScriptRoot\Diff-Directories.xlsx"
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

<#
$onlyLeftDirs | Out-GridView -Title "Directories only left"
$onlyRightDirs | Out-GridView -Title "Directories only right"
$onlyLeftFiles | Out-GridView -Title "Files only left"
$onlyRightFiles | Out-GridView -Title "Files only right"
$diffSize | Out-GridView -Title "Files with different size"
$diffDate | Out-GridView -Title "Files with different write date"
$diffProps | Out-GridView -Title "Files with different properties"
#>
