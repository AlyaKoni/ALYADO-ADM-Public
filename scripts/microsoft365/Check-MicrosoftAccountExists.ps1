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

[CmdletBinding()]
param(
    [string]$email = $null,
    [string[]]$emails = $null,
    [bool]$HideCommandPrompt = $true,
    [bool]$Headless = $true
)

if ($email -eq $null -and $emails -eq $null)
{
    throw "Please specify at least one parameter"
}

if (-Not $emails)
{
    $emails = @()
}
if ($email)
{
    $emails += $email
}

$OptionSettings =  @{ browserName=''}
function Load-NugetAssembly {
    [CmdletBinding()]
    param(
        [string]$url,
        [string]$name,
        [string]$zipinternalpath,
        [switch]$downloadonly
    )
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::GetNames([System.Net.SecurityProtocolType]) 
    $localpath = join-path $env:TEMP $name
    $tmp = "$env:TEMP\$([IO.Path]::GetRandomFileName())"
    $zip = $null
    try{
        if(!(Test-Path $localpath)){
            Add-Type -A System.IO.Compression.FileSystem
            write-host "Downloading and extracting required library '$name' ... " -F Green -NoNewline
            (New-Object System.Net.WebClient).DownloadFile($url, $tmp)
            $zip = [System.IO.Compression.ZipFile]::OpenRead($tmp)
            $zip.Entries | ?{$_.Fullname -eq $zipinternalpath} | %{
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_,$localpath)
            }
	        Unblock-File -Path $localpath
            write-host "OK" -F Green
        }
        if(!$downloadonly.IsPresent){
            Add-Type -Path $localpath -EA Stop
        }
    }catch{
        throw "Error: $($_.Exception.Message)"
    }finally{
        if ($zip){$zip.Dispose()}
        if(Test-Path $tmp){del $tmp -Force}
    }  
}

try
{
    $browser = $null
    Load-NugetAssembly -url 'https://www.nuget.org/api/v2/package/Selenium.WebDriver' -name 'WebDriver.dll' -zipinternalpath 'lib/net48/WebDriver.dll' -EA Stop
    $edge = Get-Package -Name 'Microsoft Edge' -EA SilentlyContinue | Select-Object -F 1
    if (!$edge){
        throw "Microsoft Edge Browser not installed."
        return
    }
    $version = $driverversion
    if ($version -eq ''){
        switch(([version]$edge.Version).Major){
            92 {$version = '92.0.902.73'}
            93 {$version = '93.0.967'}
            94 {$version = '94.0.986'}
            95 {$version = '95.0.1020.30'}
            96 {$version = '96.0.1054.26'}
            default {$version = ''}
        }
    }
    Load-NugetAssembly -url "https://www.nuget.org/api/v2/package/Selenium.WebDriver.MSEdgeDriver/$version" -name 'msedgedriver.exe' -zipinternalpath 'driver/win64/msedgedriver.exe' -downloadonly -EA Stop
    $dService = [OpenQA.Selenium.Edge.EdgeDriverService]::CreateDefaultService()
    $dService.HideCommandPromptWindow = $HideCommandPrompt
    $options = New-Object -TypeName OpenQA.Selenium.Edge.EdgeOptions -Property $OptionSettings
    if($PrivateBrowsing) {$options.AddArguments('InPrivate')}
    if($Headless) {$options.AddArguments('headless')}
    $browser = New-Object OpenQA.Selenium.Edge.EdgeDriver $dService, $options
    $browser.Manage().window.position = '0,0'
    foreach($email in $emails)
    {
        $ttries = 2
        do
        {
            $otries = 2
            do
            {
                $browser.Url = 'https://login.live.com/'
                $navi = $browser.Navigate()
                $emailField = $null
                $itries = 4
                do
                {
                    Start-Sleep -Milliseconds 500
                    try
                    {
                        $emailField = $browser.FindElement([OpenQA.Selenium.By]::Name("loginfmt"))
                    } catch {}
                    $itries--
                    if ($itries -lt 0) { break }
                } while ($emailField -eq $null)
                $otries--
                if ($otries -lt 0) { break }
            } while ($emailField -eq $null)
            if ($emailField -eq $null)
            {
                try { $browser.Close() } catch {}
                try { $browser.Quit() } catch {}
                Start-Sleep -Seconds 2
                $browser = New-Object OpenQA.Selenium.Edge.EdgeDriver $dService, $options
                $browser.Manage().window.position = '0,0'
            }
            $ttries--
            if ($ttries -lt 0) { break }
        } while ($emailField -eq $null)
        if ($emailField -eq $null) { throw "Was not able to get email field" }
        $emailField.SendKeys($email)
        $emailField.SendKeys([OpenQA.Selenium.Keys]::Enter)
        Start-Sleep -Milliseconds 500
        $errorField = $null
        try
        {
            $errorField = $browser.FindElement([OpenQA.Selenium.By]::Id("usernameError"))
        }
        catch {}
        if ($errorField.Enabled)
        {
            Write-Host "No  $email ($($errorField.Text.Substring(0,50).Trim())...)"
        }
        else
        {
            Start-Sleep -Milliseconds 1000
            $displayName = $null
            try
            {
                $displayName = $browser.FindElement([OpenQA.Selenium.By]::Id("displayName"))
            }
            catch {}
            if ($displayName)
            {
                Write-Host "YES $email"
            }
            else
            {
                throw "Handle result for $email"
            }
        }
    }
}
finally
{
    try { $browser.Close() } catch {}
    try { $browser.Quit() } catch {}
    Start-Sleep -Seconds 2
    Get-Process -Name msedgedriver -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
}
