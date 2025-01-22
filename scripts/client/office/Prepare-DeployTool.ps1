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
    06.11.2019 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\client\office\Prepare-DeployTool-$($AlyaTimeString).log" | Out-Null

Write-Host "Checking office deploy tool installation" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$AlyaDeployToolRoot"))
{
    try
    {
        $req = Invoke-WebRequestIndep -Uri $AlyaDeployToolDownload -UseBasicParsing -Method Get -UserAgent "Wget"
        [regex]$regex = "[^`"]*download/[^`"]*officedeploymenttool_[^`"]*.exe"
        $url = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
        if ([string]::IsNullOrEmpty($url))
        {
            [regex]$regexAzp = "`"url`"\s*:\s*`"([^`"]*officedeploymenttool_[^`"]*.exe)"
            $url = [regex]::Match($req.Content, $regexAzp, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Groups[1].Value
        }
        $req = Invoke-WebRequestIndep -Uri $url -Method Get -OutFile "$AlyaTemp\officedeploymenttool.exe"
        Write-Warning "Attention: UAC window!"
        cmd /c "$AlyaTemp\officedeploymenttool.exe" /extract:"$AlyaDeployToolRoot" /quiet
        do
        {
            Start-Sleep -Seconds 5
        } while (Get-Process -Name "officedeploymenttool" -ErrorAction SilentlyContinue)
        Remove-Item -Path "$AlyaTemp\officedeploymenttool.exe" -Force
    }
    catch
    {
        Write-Warning "Problems automatically downloading officedeploymenttool.exe. Please download manually"
        Write-Host "We launch now a browser with the officedeploymenttool.exe download page."
        Write-Host " - Select 'Download'"
        Write-Host "`n"
        pause
        
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
            Write-Host "Downloading officedeploymenttool.exe file from $AlyaDeployToolDownload"
            Write-Warning "Please don't start any other download!"
            try {
                Start-Process "$AlyaDeployToolDownload"
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
            Write-Warning "Attention: UAC window!"
            cmd /c "$sourcePath" /extract:"$AlyaDeployToolRoot" /quiet
            do
            {
                Start-Sleep -Seconds 5
            } while (Get-Process -Name "officedeploymenttool" -ErrorAction SilentlyContinue)
            Remove-Item -Path $sourcePath -Force
        }
        else
        {
            throw "We were not able to download officedeploymenttool.exe"
        }
    }
}

#Stopping Transscript
Stop-Transcript
