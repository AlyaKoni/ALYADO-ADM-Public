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


ATTENTION:
MFA is not yet supported. You need user credentials without MFA enabled!


#>

[CmdletBinding()] 
Param  
(
    [Parameter(Mandatory=$false)]
    [string[]] $testUrls = @()
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Run-OnlinePerformanceTest-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-PackageIfNotInstalled "Microsoft.SharePointOnline.CSOM"
Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM\lib\net45\Microsoft.SharePoint.Client.dll"
Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM\lib\net45\Microsoft.SharePoint.Client.Runtime.dll"

# Defining urls to test
$testUrls += $AlyaSharePointUrl

# =============================================================
# SharePoint online stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Run-OnlinePerformanceTest | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
$csvpath = "$($AlyaData)\sharepoint\SpOnlinePerfTest-$($AlyaTimeString).csv"

Write-Host "This script measures the performance of some SharePoint Online sites." -ForegroundColor $MenuColor
Write-Host "When the script has finished, a CSV with the results will be exported to:" -ForegroundColor $MenuColor
Write-Host "$csvpath`n`n" -ForegroundColor $CommandSuccess
Write-Host "Please provide some location information about this test (ex. Koni,HomeOffice,Cablecom)" -ForegroundColor $CommandInfo
$locationInfo = Read-Host
Write-Host "Please provide the number of testruns (ex. 20)" -ForegroundColor $CommandInfo
$numRuns = Read-Host
Write-Host "Please enter your SharePoint Online credentials" -ForegroundColor $CommandInfo
#TODO enable MFA enabled users
$spCreds = Get-Credential -Message "SharePoint Online credentials:"
Write-Host "`n"
$creds = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($spCreds.UserName, $spCreds.Password)

$regexUrl = "(http)?s?:?(\/\/[^`"']*\.(?:png|jpg|jpeg|gif|png|svg|js|css))"
$regexDurationClassic = "g_duration.*?(\d*);"
$regexDurationModern = "spRequestDuration`":`"(\d*)`""
$regexIisLatClassic = "g_iisLatency.*?(\d*);"
$regexIisLatModern = "IisLatency`":`"(\d*)`""

[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Do-Request ($URL, $fromURL)
{
    if ($URL -eq $fromURL)
    {
        Write-Host "  Requesting $URL"
    }
    else
    {
        Write-Host "    Requesting $URL"
    }

    $URI = New-Object System.Uri($URL,$true)
    $request = [System.Net.HttpWebRequest]::Create($URI)
    $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
    $request.Accept = "text/html, application/xhtml+xml, image/jxr, */*"
    $request.Credentials = $creds
    $request.Headers.Add("X-FORMS_BASED_AUTH_ACCEPTED", "f")
    $request.Headers.Add("Cache-Control", "no-cache")
    $rets = @()
    try
    {
        $startTime = Get-Date
        $response = [System.Net.HttpWebResponse] $request.GetResponse()
        $reader = [IO.StreamReader] $response.GetResponseStream()
        $output = $reader.ReadToEnd()
        $stopTime = Get-Date
        $headers = $response.Headers
        $contLen = $headers["Content-Length"]
        if (-Not $contLen)
        {
            $contLen = $output.Length
        }
        $spReqDur = $headers["SPRequestDuration"]
        if (-Not $spReqDur)
        {
            $spReqDur = $output | Select-String -Pattern $regexDurationClassic | % { $_.Matches } | % { $_.Groups[1] } | % { $_.Value }
            if (-Not $spReqDur)
            {
                $spReqDur = $output | Select-String -Pattern $regexDurationModern | % { $_.Matches } | % { $_.Groups[1] } | % { $_.Value }
                if (-Not $spReqDur)
                {
                    $spReqDur = 0
                }
            }
        }
        $spIisLat = $headers["SPIisLatency"]
        if (-Not $spIisLat)
        {
            $spIisLat = $output | Select-String -Pattern $regexIisLatClassic | % { $_.Matches } | % { $_.Groups[1] } | % { $_.Value }
            if (-Not $spIisLat)
            {
                $spIisLat = $output | Select-String -Pattern $regexIisLatModern | % { $_.Matches } | % { $_.Groups[1] } | % { $_.Value }
                if (-Not $spIisLat)
                {
                    $spIisLat = 0
                }
            }
        }
        $clientTime = [int]((($stopTime - $startTime).TotalSeconds * 1000) - $spReqDur - $spIisLat)
        $ticksPerByte = [int](((($stopTime - $startTime).TotalSeconds * 1000) / $contLen) * 1000)
        $reqDur = [int](($stopTime - $startTime).TotalSeconds * 1000)
        $ret = New-Object PSObject
        $ret | Add-Member Noteproperty Location $locationInfo
        $ret | Add-Member Noteproperty URL $URL
        $ret | Add-Member Noteproperty Status $response.StatusCode
        $ret | Add-Member Noteproperty ContentLength $contLen
        $ret | Add-Member Noteproperty ContentType $headers["Content-Type"]
        $ret | Add-Member Noteproperty XSharePointHealthScore $headers["X-SharePointHealthScore"]
        $ret | Add-Member Noteproperty SPRequestGuid $headers["SPRequestGuid"]
        $ret | Add-Member Noteproperty SPRequestDuration $spReqDur
        $ret | Add-Member Noteproperty SPIisLatency $spIisLat
        $ret | Add-Member Noteproperty MicrosoftSharePointTeamServices $headers["MicrosoftSharePointTeamServices"]
        $ret | Add-Member Noteproperty Date $headers["Date"]
        $ret | Add-Member Noteproperty RequestStart $startTime.ToString("o")
        $ret | Add-Member Noteproperty RequestStop $stopTime.ToString("o")
        $ret | Add-Member Noteproperty RequestDuration $reqDur
        $ret | Add-Member Noteproperty TicksPerByte $ticksPerByte
        $ret | Add-Member Noteproperty ClientTime $clientTime
        $reader.Close()
        $response.Close()

        if ($URL -eq $fromURL)
        {
            $links = $output | Select-String -Pattern $regexUrl -AllMatches | % { $_.Matches } | % { $_.Value } | Select -Unique
            foreach($link in $links)
            {
                foreach($retsub in (Do-Request -Url $link -fromURL $URL))
                {
                    $rets += $retsub
                }
            }
            $stopTimeTot = Get-Date
            $clientTimeTot = [int]((($stopTimeTot - $startTime).TotalSeconds * 1000) - $spReqDur - $spIisLat)
            $reqDurTot = [int](($stopTimeTot - $startTime).TotalSeconds * 1000)
            $ret | Add-Member Noteproperty RequestDurationTotal $reqDurTot
            $ret | Add-Member Noteproperty ClientTimeTotal $clientTimeTot
        }
        else
        {
            $ret | Add-Member Noteproperty RequestDurationTotal 0
            $ret | Add-Member Noteproperty ClientTimeTotal 0
        }
        $ret | Add-Member Noteproperty FromRequest $fromURL
        $rets += $ret

    }
    catch
    {
		try { Write-Error ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
		Write-Error ($_.Exception) -ErrorAction Continue
        Write-Host "    Error in request" -ForegroundColor $CommandError
        Write-Host "    $_.Exception.Message" -ForegroundColor $CommandError
        $ret = New-Object PSObject
        $ret | Add-Member Noteproperty Location $locationInfo
        $ret | Add-Member Noteproperty URL $URL
        $ret | Add-Member Noteproperty Status "ERROR"
        $ret | Add-Member Noteproperty ContentLength 0
        $rets += $ret
    }
    return $rets
}

# Testing
Write-Host "Starting tests" -ForegroundColor $CommandInfo
$results = @()
for ($i = 0; $i -lt $numRuns; $i += 1)
{
    Write-Host "Run $($i+1)"
    foreach($url in $urlsToTest)
    {
        if ($null -eq $url) { continue }
        foreach($ret in (Do-Request -Url $url -fromURL $url))
        {
            $results += $ret
        }
    }
    if ($i -lt ($numRuns - 1))
    {
        Write-Host "Waiting 10 Seconds for next run"
        Start-Sleep -Seconds 10
    }
}
Write-Host "Exporting data" -ForegroundColor $CommandInfo
$results | Export-Csv -NoTypeInformation -Path $csvpath -Delimiter "," -Encoding UTF8 -Force -Confirm:$false

Write-Host "`nResults exported to: $csvpath"
Write-Host "Done, press enter to finish" -ForegroundColor $CommandInfo
Read-Host

#Stopping Transscript
Stop-Transcript