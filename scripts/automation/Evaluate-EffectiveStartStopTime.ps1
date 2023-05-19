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

cls
$runAtMinute = 10 # Scheduler Time
$startTime = "05:00" # Start tag definition
$stopTime = "21:55" # Stop tag definition
$midTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($(Get-Date), [System.TimeZoneInfo]::Local.Id, 'W. Europe Standard Time')
$midTime = $midTime.AddHours(-$midTime.Hour).AddMinutes(-$midTime.Minute).AddSeconds(-$midTime.Second).AddMilliseconds(-$midTime.Millisecond)
$midTime = $midTime.AddMinutes($runAtMinute)
if ($startTime) { $startTime = [DateTime]::parseexact($startTime,"HH:mm",$null) }
if ($stopTime) { $stopTime = [DateTime]::parseexact($stopTime,"HH:mm",$null) }

for ($runtime = $midTime; $runtime -lt $midTime.AddDays(1); $runtime = $runtime.AddHours(1))
{
    $runtime
	if ($startTime)
	{
	    if ($stopTime)
	    {
		    if ($runTime -lt $stopTime -and $runTime -gt $startTime)
		    {
			    Write-Host "- Starting VM if not running" -ForegroundColor Green
		    }
            else
		    {
			    Write-Host "- Stopping VM if running" -ForegroundColor Red
		    }
	    }
		else
		{
		    if ($runTime -gt $startTime)
		    {
			    Write-Host "- Starting VM if not running" -ForegroundColor Green
		    }
		}
	}
	else
	{
	    if ($stopTime)
	    {
		    if ($runTime -gt $stopTime)
		    {
			    Write-Host "- Stopping VM if running" -ForegroundColor Red
		    }
		    if ($runTime.Hour -eq 0 -and $stopTime.Hour -eq 23)
		    {
			    Write-Host "- Stopping VM if running" -ForegroundColor Red
		    }
	    }
	}
}
