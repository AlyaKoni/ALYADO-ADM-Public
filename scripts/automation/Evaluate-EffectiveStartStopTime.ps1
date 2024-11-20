#Requires -Version 2

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
    17.03.2020 Konrad Brunner       Initial Version
    31.07.2024 Konrad Brunner       Implemented WeekDay and Week in month

	timeTag examples:
	05:00
	07:30
	07:30(1,2,3,4,5) (WeekDay): Sunday=0
	07:30(1)[1,l] [Week in month]: 1,2,3,4,5,L=last week,l=last 7 days in month
	07:30[1]
	07:30(1,2,3,4,5);06:30[1] (separate multiple times with ;)

#>

cls
$dayOffset = -10 # 0
$informUsers = $true
$onlyStartStopOnce = $true
$runAtMinute = 10 # Scheduler Time
$runForDays = 14
$startTimeTagValue = "06:00" #"07:30[1];06:30(1)" # Start tag definition
$stopTimeTagValue = "" # "21:55[1];06:30(1)" # Stop tag definition
$midTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($(Get-Date), [System.TimeZoneInfo]::Local.Id, 'W. Europe Standard Time')
$midTime = $midTime.AddHours(-$midTime.Hour).AddMinutes(-$midTime.Minute).AddSeconds(-$midTime.Second).AddMilliseconds(-$midTime.Millisecond)
$midTime = $midTime.AddMinutes($runAtMinute).AddDays($dayOffset)
$showAllTimes = $false

$startTimeTagValues = $startTimeTagValue.Split(";")
$startTimeDefs = @()
foreach($startTimeTagValue in $startTimeTagValues)
{
    if ([string]::IsNullOrEmpty($startTimeTagValue)) { continue }
	$startTime = $null
	$startTimeWds = $null
	$startTimeWks = $null
	if (-Not [string]::IsNullOrEmpty($startTimeTagValue))
	{
		Write-Output "- startTimeTag: $($startTimeTagValue)"
		if ($startTimeTagValue.Contains("(") -or $startTimeTagValue.Contains("["))
		{
			if ($startTimeTagValue.Contains("(")) { $startTimeWds = $startTimeTagValue.Split("(")[1].Split(")")[0].Split(",") }
			if ($startTimeTagValue.Contains("[")) { $startTimeWks = $startTimeTagValue.Split("[")[1].Split("]")[0].Split(",") }
			$startTimeTag = $startTimeTagValue.Split("(")[0].Split("[")[0]
		}
		else
		{
			$startTimeTag = $startTimeTagValue
		}
		try { $startTime = [DateTime]::parseexact($startTimeTag,"HH:mm",$null).AddDays($dayOffset) }
		catch { $startTime = $null }
		Write-Output "- startTime parsed: $($startTime)"
		Write-Output "- startTimeWds parsed: $($startTimeWds)"
		Write-Output "- startTimeWks parsed: $($startTimeWks)`n"
	}
	$startTimeDefs += @{
		startTimeTag = $startTimeTagValue
		startTime = $startTime
		startTimeWds = $startTimeWds
		startTimeWks = $startTimeWks
	}
}
$stopTimeTagValues = $stopTimeTagValue.Split(";")
$stopTimeDefs = @()
foreach($stopTimeTagValue in $stopTimeTagValues)
{
    if ([string]::IsNullOrEmpty($stopTimeTagValue)) { continue }
	$stopTime = $null
	$stopTimeWds = $null
	$stopTimeWks = $null
	if (-Not [string]::IsNullOrEmpty($stopTimeTagValue))
	{
		Write-Output "- stopTimeTag: $($stopTimeTagValue)"
		if ($stopTimeTagValue.Contains("(") -or $stopTimeTagValue.Contains("["))
		{
			if ($stopTimeTagValue.Contains("(")) { $stopTimeWds = $stopTimeTagValue.Split("(")[1].Split(")")[0].Split(",") }
			if ($stopTimeTagValue.Contains("[")) { $stopTimeWks = $stopTimeTagValue.Split("[")[1].Split("]")[0].Split(",") }
			$stopTimeTag = $stopTimeTagValue.Split("(")[0].Split("[")[0]
		}
		else
		{
			$stopTimeTag = $stopTimeTagValue
		}
		try { $stopTime = [DateTime]::parseexact($stopTimeTag,"HH:mm",$null).AddDays($dayOffset) }
		catch { $stopTime = $null }
		Write-Output "- stopTime parsed: $($stopTime)"
		Write-Output "- stopTimeWds parsed: $($stopTimeWds)"
		Write-Output "- stopTimeWks parsed: $($stopTimeWks)`n"
	}
	$stopTimeDefs += @{
		stopTimeTag = $stopTimeTagValue
		stopTime = $stopTime
		stopTimeWds = $stopTimeWds
		stopTimeWks = $stopTimeWks
	}
}

$startDay = $midTime.DayOfYear
for ($runtime = $midTime; $runtime -lt $midTime.AddDays($runForDays); $runtime = $runtime.AddHours(1))
{
	if ($showAllTimes) { $runtime }
	$infTime = $runTime.AddHours(1)

	$dayCount = $runtime.DayOfYear - $startDay
	if ($dayCount -gt 0)
	{
		foreach($startTimeDef in $startTimeDefs)
		{
			$startTimeDef.startTime = $startTimeDef.startTime.AddDays(1)
		}
		foreach($stopTimeDef in $stopTimeDefs)
		{
			$stopTimeDef.stopTime = $stopTimeDef.stopTime.AddDays(1)
		}
		$startDay = $runtime.DayOfYear
	}

	$firstDay = Get-Date $runTime -Day 1
	$lastDay = $firstDay.AddMonths(1).AddDays(-1)
	$weekNumber = 0
	$maxWeek = 0
	for ($w = 0; $w -lt 7; $w++)
	{
		$weekDay = $firstDay.AddDays($w * 7)
		if ($runTime.DayOfYear -ge $weekDay.DayOfYear)
		{
			$weekNumber = $w + 1
		}
		if ($runTime.Month -eq $weekDay.Month)
		{
			$maxWeek++
		}
	}
	$isLastWeek = $weekNumber -eq $maxWeek
	$isLastWeek7 = ($lastDay.DayOfYear - $runTime.DayOfYear) -lt 7

	$informsDone = @()
	$stopsDone = @()
	if ($startTimeDefs.Count -gt 0)
	{
		if ($stopTimeDefs.Count -gt 0)
		{
			foreach($startTimeDef in $startTimeDefs)
			{
				foreach($stopTimeDef in $stopTimeDefs)
				{
					$startTime = $startTimeDef.startTime
					$startTimeTag = $startTimeDef.startTimeTag
					$ignoreStart = $false
					if ($null -ne $startTimeDef.startTimeWds -and $runTime.DayOfWeek.value__ -notin $startTimeDef.startTimeWds)
					{
						$ignoreStart = $true
					}
					if ($null -ne $startTimeDef.startTimeWks -and $weekNumber -notin $startTimeDef.startTimeWks -and -not ($startTimeDef.startTimeWks -contains "l"  -and $isLastWeek7) -and -not ($startTimeDef.startTimeWks -contains "L" -and $isLastWeek))
					{
						$ignoreStart = $true
					}
					$stopTime = $stopTimeDef.stopTime
					$stopTimeTag = $stopTimeDef.stopTimeTag
					$ignoreStop = $false
					if ($null -ne $stopTimeDef.stopTimeWds -and $runTime.DayOfWeek.value__ -notin $stopTimeDef.stopTimeWds)
					{
						$ignoreStop = $true
					}
					if ($null -ne $stopTimeDef.stopTimeWks -and $weekNumber -notin $stopTimeDef.stopTimeWks -and -not ($stopTimeDef.stopTimeWks -contains "l"  -and $isLastWeek7) -and -not ($stopTimeDef.stopTimeWks -contains "L" -and $isLastWeek))
					{
						$ignoreStop = $true
					}
					if ($startTime -lt $stopTime)
					{
						if ($informUsers -and (-Not ($infTime -lt $stopTime -and $infTime -gt $startTime) -and [Math]::Abs($stopTime.Subtract($infTime).TotalMinutes) -lt 60))
						{
							if ($informsDone -notcontains $stopTimeTag -and -not $ignoreStop)
							{
								if (-Not $showAllTimes) { $runtime }
								Write-Host "- Informing users about shutdown in 1 hour (tag=$stopTimeTag)" -ForegroundColor Yellow
								$informsDone += $stopTimeTag
							}
						}
						if ($runTime -lt $stopTime -and $runTime -gt $startTime)
						{
							if ($onlyStartStopOnce -eq $false -or [Math]::Abs($startTime.Subtract($runTime).TotalMinutes) -lt 60)
							{
								if (-not $ignoreStart)
								{
									if (-Not $showAllTimes) { $runtime }
									Write-Host "- Starting VM if not running (tag=$startTimeTag)" -ForegroundColor Green
								}
							}
						}
						else
						{
							if ($onlyStartStopOnce -eq $false -or [Math]::Abs($stopTime.Subtract($runTime).TotalMinutes) -lt 60)
							{
								if ($stopsDone -notcontains $stopTimeTag -and -not $ignoreStop)
								{
									if (-Not $showAllTimes) { $runtime }
									Write-Host "- Stopping VM if running (tag=$stopTimeTag)" -ForegroundColor Red
									$stopsDone += $stopTimeTag
								}
							}
						}
					}
					else
					{
						if ($informUsers -and ($infTime -lt $startTime -and $infTime -gt $stopTime -and [Math]::Abs($stopTime.Subtract($infTime).TotalMinutes) -lt 60))
						{
							if (-not $ignoreStop)
							{
								if (-Not $showAllTimes) { $runtime }
								Write-Host "- Informing users about shutdown in 1 hour (tag=$stopTimeTag)" -ForegroundColor Yellow
							}
						}
						if ($runTime -lt $startTime -and $runTime -gt $stopTime)
						{
							if ($onlyStartStopOnce -eq $false -or [Math]::Abs($stopTime.Subtract($runTime).TotalMinutes) -lt 60)
							{
								if (-not $ignoreStop)
								{
									if (-Not $showAllTimes) { $runtime }
									Write-Host "- Stopping VM if running (tag=$stopTimeTag)" -ForegroundColor Red
									$stopsDone += $stopTimeTag
								}
							}
						}
						else
						{
							if ($onlyStartStopOnce -eq $false -or [Math]::Abs($startTime.Subtract($runTime).TotalMinutes) -lt 60)
							{
								if (-not $ignoreStart)
								{
									if (-Not $showAllTimes) { $runtime }
									Write-Host "- Starting VM if not running (tag=$startTimeTag)" -ForegroundColor Green
								}
							}
						}
					}
				}
			}
		}
		else
		{
			foreach($startTimeDef in $startTimeDefs)
			{
				$startTime = $startTimeDef.startTime
				$startTimeTag = $startTimeDef.startTimeTag
				if ($null -ne $startTimeDef.startTimeWds -and $runTime.DayOfWeek.value__ -notin $startTimeDef.startTimeWds)
				{
					continue
				}
				if ($null -ne $startTimeDef.startTimeWks -and $weekNumber -notin $startTimeDef.startTimeWks -and -not ($startTimeDef.startTimeWks -contains "l"  -and $isLastWeek7) -and -not ($startTimeDef.startTimeWks -contains "L" -and $isLastWeek))
				{
					continue
				}
				if ($runTime -gt $startTime)
				{
					if ($onlyStartStopOnce -eq $false -or [Math]::Abs($startTime.Subtract($runTime).TotalMinutes) -lt 60)
					{
						if (-Not $showAllTimes) { $runtime }
						Write-Host "- Starting VM if not running (tag=$startTimeTag)" -ForegroundColor Green
					}
				}
			}
		}
	}
	else
	{
		if ($stopTimeDefs.Count -gt 0)
		{
			foreach($stopTimeDef in $stopTimeDefs)
			{
				$stopTime = $stopTimeDef.stopTime
				$stopTimeTag = $stopTimeDef.stopTimeTag
				if ($null -ne $stopTimeDef.stopTimeWds -and $runTime.DayOfWeek.value__ -notin $stopTimeDef.stopTimeWds)
				{
					continue
				}
				if ($null -ne $stopTimeDef.stopTimeWks -and $weekNumber -notin $stopTimeDef.stopTimeWks -and -not ($stopTimeDef.stopTimeWks -contains "l"  -and $isLastWeek7) -and -not ($stopTimeDef.stopTimeWks -contains "L" -and $isLastWeek))
				{
					continue
				}
				if ($informUsers -and ($infTime -gt $stopTime -and [Math]::Abs($stopTime.Subtract($infTime).TotalMinutes) -lt 60))
				{
					if (-Not $showAllTimes) { $runtime }
					Write-Host "- Informing users about shutdown in 1 hour (tag=$stopTimeTag)" -ForegroundColor Yellow
				}
				if ($runTime -gt $stopTime -or ($runTime.Hour -eq 0 -and $stopTime.Hour -eq 23))
				{
					if ($onlyStartStopOnce -eq $false -or [Math]::Abs($stopTime.Subtract($runTime).TotalMinutes) -lt 60)
					{
						if (-Not $showAllTimes) { $runtime }
						Write-Host "- Stopping VM if running (tag=$stopTimeTag)" -ForegroundColor Red
					}
				}
			}
		}
	}
}
