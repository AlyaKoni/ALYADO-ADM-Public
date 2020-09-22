#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting: 2019, 2020

    This file is part of the Alya Base Configuration.
    The Alya Base Configuration is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
	Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
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

#>

[CmdletBinding()] 
Param  
(
    [Parameter(Mandatory=$false)]
    [string] $SolutionPath = $null, #Defaults to "$($AlyaData)\sharepoint\Solutions"
    [Parameter(Mandatory=$false)]
    [string] $SolutionId = $null #Defaults to existing one or a dynamic selection
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\onprem\ReInstall-Solution-$($AlyaTimeString).log" | Out-Null

#Checking modules
Check-Module "Microsoft.SharePoint.PowerShell"
Add-PSSnapin "Microsoft.SharePoint.PowerShell" -ErrorAction Stop

# =============================================================
# SharePoint OnPrem stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | ReInstall-Solution | OnPrem" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
if (-Not $SolutionPath)
{
    $SolutionPath = "$($AlyaData)\sharepoint\Solutions"
}
if (-Not (Test-Path -Path $SolutionPath -PathType Container))
{
    New-Item -ItemType Directory -Force -Path $SolutionPath
}
$global:SolutionUrls = $null

#Getting solution to be installed
$solFiles = @(Get-ChildItem -Path $SolutionPath -Filter "*.wsp" -File)
if ((-Not $solFiles -or $solFiles.Length -eq 0) -or ($SolutionId -And -Not (Test-Path -Path (Join-Path -Path $SolutionPath -ChildPath $SolutionId) -PathType File)))
{
    Write-Host "Please place your solution files into the following directory:" -ForegroundColor $CommandInfo
    Write-Host "  $($SolutionPath)" -ForegroundColor $CommandInfo
    Write-Host "  and restart this script" -ForegroundColor $CommandInfo
    throw "No solution files found"
}
if (-Not $SolutionId)
{
    if ($solFiles.Length -eq 1)
    {
        Write-Host "There is only one solution file. Using: " -ForegroundColor $CommandInfo
        Write-Host "  $($SolutionPath)" -ForegroundColor $CommandInfo
        $SolutionId = $solFiles[0].Name
    }
    else
    {
        Add-Type -AssemblyName System.Windows.Forms
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog
        $FileBrowser.InitialDirectory = $SolutionPath
        $FileBrowser.Filter = 'Solution Files (*.wsp)|*.wsp'
        $fbRes = $FileBrowser.ShowDialog()
        if (-Not $FileBrowser.FileName -Or -Not $FileBrowser.FileName.Length -gt 3 -Or -Not (Test-Path -Path $FileBrowser.FileName -PathType Leaf))
        {
            throw "No solution file found"
        }
        $SolutionId = (Get-Item -Path $FileBrowser.FileName).Name
    }
}

#Functions
function WaitForSPSolutionJobToComplete([string]$solutionName)
{
    $solution = Get-SPSolution -Identity $solutionName -ErrorAction SilentlyContinue
 
    if ($solution)
    {
        if ($solution.JobExists)
        {
            Write-Host -NoNewLine "Waiting for timer job to complete for solution '$solutionName'."
        }
         
        # Check if there is a timer job still associated with this solution and wait until it has finished
        while ($solution.JobExists)
        {
            $jobStatus = $solution.JobStatus
             
            # If the timer job succeeded then proceed
            if ($jobStatus -eq [Microsoft.SharePoint.Administration.SPRunningJobStatus]::Succeeded)
            {
                Write-Host "Solution '$solutionName' timer job suceeded"
                return $true
            }
             
            # If the timer job failed or was aborted then fail
            if ($jobStatus -eq [Microsoft.SharePoint.Administration.SPRunningJobStatus]::Aborted -or
                $jobStatus -eq [Microsoft.SharePoint.Administration.SPRunningJobStatus]::Failed)
            {
                Write-Host "Solution '$solutionName' has timer job status '$jobStatus'."
                return $false
            }
             
            # Otherwise wait for the timer job to finish
            Write-Host -NoNewLine "."
            Start-Sleep -Seconds 5
        }
         
        # Write a new line to the end of the '.....'
        Write-Host
    }
     
    return $true
}

function Uninstall-SPSolution-IfExist([string]$solutionName)
{
    $solution = Get-SPSolution -Identity $solutionName -ErrorAction SilentlyContinue
    if ($solution -and $solution.Deployed)
    {
        if ($solution.DeployedWebApplications -and $solution.DeployedWebApplications.Count -gt 0)
        {
            $global:SolutionUrls = $solution.DeployedWebApplications.Url | Out-String
            Uninstall-SPSolution -Identity $solutionName -Confirm:$false -AllWebApplications
            $tmp = WaitForSPSolutionJobToComplete -solutionName $solutionName
        }
        else
        {
            $global:SolutionUrls = $null
		    Uninstall-SPSolution -Identity $solutionName -Confirm:$false
            $tmp = WaitForSPSolutionJobToComplete -solutionName $solutionName
        }
    }
    else
    {
        throw "This script is only able to reinstall existing solutions"
    }
}

function Remove-SPSolution-IfExist([string]$solutionName)
{
    $solution = Get-SPSolution -Identity $solutionName -ErrorAction SilentlyContinue
    if ($solution)
    {
        Remove-SPSolution -identity $solutionName -Confirm:$false
        do
        {
            Start-Sleep -Seconds 1
            $solution = Get-SPSolution -Identity $SolutionId -ErrorAction SilentlyContinue

        } while($solution)
    }
}

#uninstall
Write-Host "Uninstalling solution" -ForegroundColor $CommandInfo
Uninstall-SPSolution-IfExist -solutionName $SolutionId

# remove
Write-Host "Removing solution" -ForegroundColor $CommandInfo
Remove-SPSolution-IfExist -solutionName $SolutionId

# add
Write-Host "Adding solution" -ForegroundColor $CommandInfo
Add-SPSolution -LiteralPath (Join-Path -Path $SolutionPath -ChildPath $SolutionId) -Confirm:$false
Write-Host "Waiting to finish the add" -ForegroundColor $CommandInfo
do
{
    Start-Sleep -Seconds 1
    $solution = Get-SPSolution -Identity $SolutionId -ErrorAction SilentlyContinue

} while(-Not $solution)

# install 
Write-Host "Installing solution" -ForegroundColor $CommandInfo
if ($global:SolutionUrls)
{
    #TODO -FullTrustBinDeployment ??
    foreach($SolutionUrl in $SolutionUrls)
    {
        Install-SPSolution -Identity $SolutionId -Confirm:$false -AllWebApplications:$false -WebApplication $SolutionUrl -GACDeployment -Force
        $tmp = WaitForSPSolutionJobToComplete -solutionName $SolutionId
    }
}
else
{
    Install-SPSolution -Identity $SolutionId -Confirm:$false -GACDeployment -Force
    $tmp = WaitForSPSolutionJobToComplete -solutionName $SolutionId
}

# done 
Write-Host "Done" -ForegroundColor $CommandInfo

#Stopping Transscript
Stop-Transcript