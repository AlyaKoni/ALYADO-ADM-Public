#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2025

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
    01.05.2020 Konrad Brunner       Added RDS stuff
    18.10.2021 Konrad Brunner       Move to Az
    12.03.2024 Konrad Brunner       Implemented new managed identity concept
    31.07.2024 Konrad Brunner       Implemented WeekDay and Week in month
    31.10.2024 Konrad Brunner       Better cert update handling
    28.07.2025 Konrad Brunner       Implemented REBOOTTIME

	timeTag examples:
	05:00
	07:30
	07:30(1,2,3,4,5) (WeekDay): Sunday=0
	07:30(1)[1,l] [Week in month]: 1,2,3,4,5,L=last week,l=last 7 days in month
	07:30[1]
	07:30(1,2,3,4,5);06:30[1] (separate multiple times with ;)

#>

# Defaults
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
$Global:ErrorActionPreference = "Stop"
$Global:ProgressPreference = "SilentlyContinue"
$VerbosePreference = "Continue"
$ProgressPreference = "Continue"

# Runbook
$AlyaResourceGroupName = "##AlyaResourceGroupName##"
$AlyaAutomationAccountName = "##AlyaAutomationAccountName##"
$AlyaRunbookName = "##AlyaRunbookName##"

# RunAsAccount
$AlyaAzureEnvironment = "##AlyaAzureEnvironment##"
$AlyaApplicationId = "##AlyaApplicationId##"
$AlyaTenantId = "##AlyaTenantId##"
$AlyaCertificateKeyVaultName = "##AlyaCertificateKeyVaultName##"
$AlyaCertificateSecretName = "##AlyaCertificateSecretName##"
$AlyaSubscriptionId = "##AlyaSubscriptionId##"
$AlyaSubscriptionIds = "##AlyaSubscriptionIds##"

# Mail settings
$AlyaFromMail = "##AlyaFromMail##"
$AlyaToMail = "##AlyaToMail##"

# Group settings
$grpNameAllExt = "##AlyaAllExternalsGroup##"
$grpNameAllInt = "##AlyaAllInternalsGroup##"
$grpNameDefTeam = "##AlyaDefaultTeamsGroup##"
$grpNamePrjTeam = "##AlyaProjectTeamsGroup##"

# Other settings
$TimeZone = "##AlyaTimeZone##"
$startTimeTagName = "STARTTIME"
$rebootTimeTagName = "REBOOTTIME"
$stopTimeTagName = "STOPTIME"
$onlyStartStopOnce = $true
$informUsers = $true
$certUpdateDay = 1
$certUpdateWeekDay = -1
$certUpdateWeekDayWeek = -1
$certUpdateStartCheckHour = 4
$certUpdateStopCheckHour = 7
$runTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($(Get-Date), [System.TimeZoneInfo]::Local.Id, $TimeZone)
Write-Output "Run time $($runTime)"
$infTime = $runTime.AddHours(1)
Write-Output "Inform Time $($infTime)"

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

# Login
Write-Output "Login to Az using system-assigned managed identity"
Disable-AzContextAutosave -Scope Process | Out-Null
try
{
    $AzureContext = (Connect-AzAccount -Identity -Environment $AlyaAzureEnvironment -Tenant $AlyaTenantId).Context
}
catch
{
    throw "There is no system-assigned user identity. Aborting."; 
    exit 99
}
$AzureContext = Set-AzContext -Subscription $AlyaSubscriptionId -DefaultProfile $AzureContext

# Login-AzureAutomation
$retries = 10
do
{
    Start-Sleep -Seconds ((10-$retries)*4)
	try {
	    $RunAsCertificate = Get-AutomationCertificate -Name "AzureRunAsCertificate"
	    try { Disconnect-AzAccount }catch{}
	    Write-Output "Logging in to Az..."
	    if (!$AlyaApplicationId -or $AlyaApplicationId.Contains("##")) {
	        $ErrorMessage = "Missing application id."
	        throw $ErrorMessage            
	    }
	
	    Write-Output "Logging in to Az ($AlyaAzureEnvironment)..."
	    Write-Output "  Thumbprint $($RunAsCertificate.Thumbprint)"
	    Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null
	    Add-AzAccount `
	        -ServicePrincipal `
	        -TenantId $AlyaTenantId `
	        -ApplicationId $AlyaApplicationId `
	        -CertificateThumbprint $RunAsCertificate.Thumbprint `
	        -Environment $AlyaAzureEnvironment
	    Select-AzSubscription -SubscriptionId $AlyaSubscriptionId  | Write-Verbose
		$Context = Get-AzContext
		break
	} catch {
		try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
		$retries--
		if ($retries -lt 0)
		{
			Write-Error "Max retries reached!" -ErrorAction Continue
			# Check during certificate update
			$isCertUpdating = $false
			if ($certUpdateDay -gt 0)
			{
				if ( (Get-Date).Day -eq $certUpdateDay )
				{
					$isCertUpdating = $true
				}
			}
			else
			{
				$weekDay = (Get-Date).DayOfWeek.value__
				if ($weekDay -eq $certUpdateWeekDay -and $weekNumber -eq $certUpdateWeekDayWeek)
				{
					$isCertUpdating = $true
	    		}
			}
			if ($isCertUpdating)
			{
				if ( (Get-Date).Hour -ge $certUpdateStartCheckHour -and (Get-Date).Hour -le $certUpdateStopCheckHour )
				{
					Write-Error "Guessing cert update! Exiting..." -ErrorAction Continue
					exit
				}
			}
			else
			{
				throw
			}
		}
	}
} while ($true)

function InformUsers($vmName)
{
    $hPools = Get-AzWvdHostPool
    Write-Output "$vmName"
    Write-Output "Pools"
    foreach($hPool in $hPools)
    {
        $rGrp = $hPool.Id.Split("/")[4]
        $sessHosts = Get-AzWvdSessionHost -ResourceGroupName $rGrp -HostPoolName $hPool.Name
        foreach($sessHost in $sessHosts)
        {
            $hName = $sessHost.Name.Split("/")[1].Split(".")[0]
            $sName = $sessHost.Name.Split("/")[1]
            if ($vmName -ne $hName) { continue }
            $sessions = Get-AzWvdUserSession -ResourceGroupName $rGrp -HostPoolName $hPool.Name -SessionHostName $sName
           foreach($session in $sessions)
            {
               Send-AzWvdUserSessionMessage -ResourceGroupName $rGrp `
                    -HostPoolName $hPool.Name `
                    -SessionHostName $sName `
                    -UserSessionId $session.Name.Split("/")[2] `
                    -MessageBody $MessageBody `
                    -MessageTitle $MessageTitle
            }
        }
    }
}

function LogOffSessions($vmName)
{
    $hPools = Get-AzWvdHostPool
    foreach($hPool in $hPools)
    {
        $sessHosts = Get-AzWvdSessionHost -ResourceGroupName $hPool.Id.Split("/")[4] -HostPoolName $hPool.Name
        foreach($sessHost in $sessHosts)
        {
            if ($vmName -ne $sessHost.Name.Split("/")[1]) { continue }
            $sessions = Get-AzWvdUserSession -ResourceGroupName $hPool.Id.Split("/")[4] -HostPoolName $hPool.Name -SessionHostName $sessHost.Name.Split("/")[1]
            foreach($session in $sessions)
            {
                try
                {
                    Disconnect-AzWvdUserSession -ResourceGroupName $hPool.Id.Split("/")[4] `
                        -HostPoolName $hPool.Name `
                        -SessionHostName $sessHost.Name.Split("/")[1] `
                        -Id $session.Name.Split("/")[2]
                } catch {}
                try
                {
                    Remove-AzWvdUserSession -ResourceGroupName $hPool.Id.Split("/")[4] `
                        -HostPoolName $hPool.Name `
                        -SessionHostName $sessHost.Name.Split("/")[1] `
                        -Id $session.Name.Split("/")[2]
                } catch {}
            }
        }
    }
}

try {

	# AVD stuff
	$MessageTitle = "Warnung"
	$MessageBody = "ACHTUNG: Dieser virtuelle Desktop wird in einer Stunde automatisch heruntergefahren!"

	# Members
	$subs = $AlyaSubscriptionIds.Split(",")

	# Processing subscriptions
	foreach($sub in $subs)
	{
		"Processing subscription: $($sub)"
        $null = Set-AzContext -Subscription $sub

		# Processing resource groups
		Get-AzResourceGroup | Foreach-Object {
			$ResGName = $_.ResourceGroupName
			Write-Output "  Checking ressource group $($ResGName)"
			foreach($vm in (Get-AzVM -ResourceGroupName $ResGName))
			{
				Write-Output "    Checking VM $($vm.Name)"
				$startTimeDefs = @()
				$rebootTimeDefs = @()
				$stopTimeDefs = @()
				$informsDone = @()
				$stopsDone = @()
				$tags = $vm.Tags
				$tKeys = $tags | Select-Object -ExpandProperty keys
				foreach ($tkey in $tkeys)
				{
					if ($tkey.ToUpper() -eq $startTimeTagName)
					{
						$startTimeTag = $tags[$tkey]
						Write-Output "- startTimeTag on vm: $($startTimeTag)"
						$startTimeTagValues = $startTimeTag.Split(";")
						foreach($startTimeTagValue in $startTimeTagValues)
						{
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
								$startTimeDefs += @{
									startTimeTag = $startTimeTagValue
									startTime = $startTime
									startTimeWds = $startTimeWds
									startTimeWks = $startTimeWks
								}
							}
						}
					}
					if ($tkey.ToUpper() -eq $rebootTimeTagName)
					{
						$rebootTimeTag = $tags[$tkey]
						Write-Output "- rebootTimeTag on vm: $($rebootTimeTag)"
						$rebootTimeTagValues = $rebootTimeTag.Split(";")
						foreach($rebootTimeTagValue in $rebootTimeTagValues)
						{
							$rebootTime = $null
							$rebootTimeWds = $null
							$rebootTimeWks = $null
							if (-Not [string]::IsNullOrEmpty($rebootTimeTagValue))
							{
								Write-Output "- rebootTimeTag: $($rebootTimeTagValue)"
								if ($rebootTimeTagValue.Contains("(") -or $rebootTimeTagValue.Contains("["))
								{
									if ($rebootTimeTagValue.Contains("(")) { $rebootTimeWds = $rebootTimeTagValue.Split("(")[1].Split(")")[0].Split(",") }
									if ($rebootTimeTagValue.Contains("[")) { $rebootTimeWks = $rebootTimeTagValue.Split("[")[1].Split("]")[0].Split(",") }
									$rebootTimeTag = $rebootTimeTagValue.Split("(")[0].Split("[")[0]
								}
								else
								{
									$rebootTimeTag = $rebootTimeTagValue
								}
								try { $rebootTime = [DateTime]::parseexact($rebootTimeTag,"HH:mm",$null).AddDays($dayOffset) }
								catch { $rebootTime = $null }
								Write-Output "- rebootTime parsed: $($rebootTime)"
								Write-Output "- rebootTimeWds parsed: $($rebootTimeWds)"
								Write-Output "- rebootTimeWks parsed: $($rebootTimeWks)`n"
								$rebootTimeDefs += @{
									rebootTimeTag = $rebootTimeTagValue
									rebootTime = $rebootTime
									rebootTimeWds = $rebootTimeWds
									rebootTimeWks = $rebootTimeWks
								}
							}
						}
					}
					if ($tkey.ToUpper() -eq $stopTimeTagName)
					{
						$stopTimeTag = $tags[$tkey]
						Write-Output "- stopTimeTag on vm: $($stopTimeTag)"
						$stopTimeTagValues = $stopTimeTag.Split(";")
						foreach($stopTimeTagValue in $stopTimeTagValues)
						{
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
								$stopTimeDefs += @{
									stopTimeTag = $stopTimeTagValue
									stopTime = $stopTime
									stopTimeWds = $stopTimeWds
									stopTimeWks = $stopTimeWks
								}
							}
						}
					}
				}
	            if ($rebootTimeDefs.Count -gt 0)
	            {
					foreach($rebootTimeDef in $rebootTimeDefs)
					{
						$rebootTime = $rebootTimeDef.rebootTime
						$rebootTimeTag = $rebootTimeDef.rebootTimeTag
						$ignoreReboot = $false
						if ($null -ne $rebootTimeDef.rebootTimeWds -and $runTime.DayOfWeek.value__ -notin $rebootTimeDef.rebootTimeWds)
						{
							Write-Output "- Restart ignored. Not right weekday."
							$ignoreReboot = $true
						}
						if ($null -ne $rebootTimeDef.rebootTimeWks -and $weekNumber -notin $rebootTimeDef.rebootTimeWks -and -not ($rebootTimeDef.rebootTimeWks -contains "l"  -and $isLastWeek7) -and -not ($rebootTimeDef.rebootTimeWks -contains "L" -and $isLastWeek))
						{
							Write-Output "- Restart ignored. Not right week."
							$ignoreReboot = $true
						}
						if ($informUsers -and $infTime -gt $rebootTime -and [Math]::Abs($rebootTime.Subtract($infTime).TotalMinutes) -lt 60)
						{
							if ($informsDone -notcontains $rebootTimeTag -and -not $ignoreReboot)
							{
								Write-Output "- Informing users about restart in 1 hour (tag=$rebootTimeTag)"
								InformUsers -vmName $vm.Name
								$informsDone += $rebootTimeTag
							}
						}
						if ($runTime -gt $rebootTime)
						{
							$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
							foreach ($VMStatus in $VMDetail.Statuses)
							{
								Write-Output "- VM Status: $($VMStatus.Code)"
								if($VMStatus.Code.CompareTo("PowerState/running") -eq 0)
								{
									if ([Math]::Abs($rebootTime.Subtract($runTime).TotalMinutes) -lt 60)
									{
										if (-not $ignoreReboot)
										{
											Write-Output "- Restarting VM (tag=$rebootTimeTag)"
											Restart-AzVM -ResourceGroupName $ResGName -Name $vm.Name
										}
									}
								}
								else
								{
									Write-Output "- VM not running. Ignoring reboot."
								}
							}
						}
					}
				}
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
									Write-Output "- Start ignored. Not right weekday."
									$ignoreStart = $true
								}
								if ($null -ne $startTimeDef.startTimeWks -and $weekNumber -notin $startTimeDef.startTimeWks -and -not ($startTimeDef.startTimeWks -contains "l"  -and $isLastWeek7) -and -not ($startTimeDef.startTimeWks -contains "L" -and $isLastWeek))
								{
									Write-Output "- Start ignored. Not right week."
									$ignoreStart = $true
								}
								$stopTime = $stopTimeDef.stopTime
								$stopTimeTag = $stopTimeDef.stopTimeTag
								$ignoreStop = $false
								if ($null -ne $stopTimeDef.stopTimeWds -and $runTime.DayOfWeek.value__ -notin $stopTimeDef.stopTimeWds)
								{
									Write-Output "- Stop ignored. Not right weekday."
									$ignoreStop = $true
								}
								if ($null -ne $stopTimeDef.stopTimeWks -and $weekNumber -notin $stopTimeDef.stopTimeWks -and -not ($stopTimeDef.stopTimeWks -contains "l"  -and $isLastWeek7) -and -not ($stopTimeDef.stopTimeWks -contains "L" -and $isLastWeek))
								{
									Write-Output "- Stop ignored. Not right week."
									$ignoreStop = $true
								}
								if ($startTime -lt $stopTime)
								{
									if ($informUsers -and (-Not ($infTime -lt $stopTime -and $infTime -gt $startTime) -and [Math]::Abs($stopTime.Subtract($infTime).TotalMinutes) -lt 60))
									{
										if ($informsDone -notcontains $stopTimeTag -and -not $ignoreStop)
										{
											Write-Output "- Informing users about shutdown in 1 hour (tag=$stopTimeTag)"
											InformUsers -vmName $vm.Name
											$informsDone += $stopTimeTag
										}
									}
									if ($runTime -lt $stopTime -and $runTime -gt $startTime)
									{
										$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
										foreach ($VMStatus in $VMDetail.Statuses)
										{
											Write-Output "- VM Status: $($VMStatus.Code)"
											if($VMStatus.Code.CompareTo("PowerState/deallocated") -eq 0 -or $VMStatus.Code.CompareTo("PowerState/stopped") -eq 0)
											{
												if ($onlyStartStopOnce -eq $false -or [Math]::Abs($startTime.Subtract($runTime).TotalMinutes) -lt 60)
												{
													if (-not $ignoreStart)
													{
														Write-Output "- Starting VM (tag=$startTimeTag)"
														Start-AzVM -ResourceGroupName $ResGName -Name $vm.Name
													}
												}
												else
												{
													Write-Output "- Start ignored by onlyStartStopOnce."
												}
											}
										}
									}
									else
									{
										$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
										foreach ($VMStatus in $VMDetail.Statuses)
										{
											Write-Output "- VM Status: $($VMStatus.Code)"
											if($VMStatus.Code.CompareTo("PowerState/running") -eq 0)
											{
												if ($onlyStartStopOnce -eq $false -or [Math]::Abs($stopTime.Subtract($runTime).TotalMinutes) -lt 60)
												{
													if ($stopsDone -notcontains $stopTimeTag -and -not $ignoreStop)
													{
														Write-Output "- Stopping VM (tag=$stopTimeTag)"
														LogOffSessions -vmName $vm.Name
														Stop-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Force
														$stopsDone += $stopTimeTag
													}
												}
												else
												{
													Write-Output "- Stop ignored by onlyStartStopOnce."
												}
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
											Write-Output "Informing users about shutdown in 1 hour (tag=$stopTimeTag)"
											InformUsers -vmName $vm.Name
											$informsDone += $stopTimeTag
										}
									}
									if ($runTime -lt $startTime -and $runTime -gt $stopTime)
									{
										$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
										foreach ($VMStatus in $VMDetail.Statuses)
										{
											Write-Output "- VM Status: $($VMStatus.Code)"
											if($VMStatus.Code.CompareTo("PowerState/running") -eq 0)
											{
												if ($onlyStartStopOnce -eq $false -or [Math]::Abs($stopTime.Subtract($runTime).TotalMinutes) -lt 60)
												{
													if (-not $ignoreStop)
													{
														Write-Output "- Stopping VM (tag=$stopTimeTag)"
														LogOffSessions -vmName $vm.Name
														Stop-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Force
														$stopsDone += $stopTimeTag
													}
												}
												else
												{
													Write-Output "- Stop ignored by onlyStartStopOnce."
												}
											}
										}
									}
									else
									{
										$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
										foreach ($VMStatus in $VMDetail.Statuses)
										{
											Write-Output "- VM Status: $($VMStatus.Code)"
											if($VMStatus.Code.CompareTo("PowerState/deallocated") -eq 0 -or $VMStatus.Code.CompareTo("PowerState/stopped") -eq 0)
											{
												if ($onlyStartStopOnce -eq $false -or [Math]::Abs($startTime.Subtract($runTime).TotalMinutes) -lt 60)
												{
													if (-not $ignoreStart)
													{
														Write-Output "- Starting VM (tag=$startTimeTag)"
														Start-AzVM -ResourceGroupName $ResGName -Name $vm.Name
													}
												}
												else
												{
													Write-Output "- Start ignored by onlyStartStopOnce."
												}
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
							$ignoreStart = $false
							if ($null -ne $startTimeDef.startTimeWds -and $runTime.DayOfWeek.value__ -notin $startTimeDef.startTimeWds)
							{
								Write-Output "- Start ignored. Not right weekday."
								$ignoreStart = $true
							}
							if ($null -ne $startTimeDef.startTimeWks -and $weekNumber -notin $startTimeDef.startTimeWks -and -not ($startTimeDef.startTimeWks -contains "l"  -and $isLastWeek7) -and -not ($startTimeDef.startTimeWks -contains "L" -and $isLastWeek))
							{
								Write-Output "- Start ignored. Not right week."
								$ignoreStart = $true
							}
							if ($runTime -gt $startTime)
							{
								$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
								foreach ($VMStatus in $VMDetail.Statuses)
								{
									Write-Output "- VM Status: $($VMStatus.Code)"
									if($VMStatus.Code.CompareTo("PowerState/deallocated") -eq 0 -or $VMStatus.Code.CompareTo("PowerState/stopped") -eq 0)
									{
										if ($onlyStartStopOnce -eq $false -or [Math]::Abs($startTime.Subtract($runTime).TotalMinutes) -lt 60)
										{
											if (-not $ignoreStart)
											{
												Write-Output "- Starting VM (tag=$startTimeTag)"
												Start-AzVM -ResourceGroupName $ResGName -Name $vm.Name
											}
										}
										else
										{
											Write-Output "- Start ignored by onlyStartStopOnce."
										}
									}
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
							$ignoreStop = $false
							if ($null -ne $stopTimeDef.stopTimeWds -and $runTime.DayOfWeek.value__ -notin $stopTimeDef.stopTimeWds)
							{
								Write-Output "- Stop ignored. Not right weekday."
								$ignoreStop = $true
							}
							if ($null -ne $stopTimeDef.stopTimeWks -and $weekNumber -notin $stopTimeDef.stopTimeWks -and -not ($stopTimeDef.stopTimeWks -contains "l"  -and $isLastWeek7) -and -not ($stopTimeDef.stopTimeWks -contains "L" -and $isLastWeek))
							{
								Write-Output "- Stop ignored. Not right week."
								$ignoreStop = $true
							}
							if ($informUsers -and ($infTime -gt $stopTime -and [Math]::Abs($stopTime.Subtract($infTime).TotalMinutes) -lt 60))
							{
								if (-not $ignoreStop)
								{
									Write-Output "Informing users about shutdown in 1 hour (tag=$stopTimeTag)"
									InformUsers -vmName $vm.Name
									$informsDone += $stopTimeTag
								}
							}
							if ($runTime -gt $stopTime -or ($runTime.Hour -eq 0 -and $stopTime.Hour -eq 23))
							{
								$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
								foreach ($VMStatus in $VMDetail.Statuses)
								{
									Write-Output "- VM Status: $($VMStatus.Code)"
									if($VMStatus.Code.CompareTo("PowerState/running") -eq 0)
									{
										if ($onlyStartStopOnce -eq $false -or [Math]::Abs($stopTime.Subtract($runTime).TotalMinutes) -lt 60)
										{
											if (-not $ignoreStop)
											{
												Write-Output "- Stopping VM (tag=$stopTimeTag)"
												LogOffSessions -vmName $vm.Name
												Stop-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Force
											}
										}
										else
										{
											Write-Output "- Stop ignored by onlyStartStopOnce."
										}
									}
								}
							}
						}
	                }
	            }
			}
		}
	}
    Write-output "Done"
}
catch
{
    Write-Error $_ -ErrorAction Continue
    try { Write-Error ($_ | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}

    # Login back
    Write-Output "Login back to Az using system-assigned managed identity"
    try { Disconnect-AzAccount }catch{}
    $AzureContext = (Connect-AzAccount -Identity).Context
    $AzureContext = Set-AzContext -Subscription $AlyaSubscriptionId -DefaultProfile $AzureContext

    # Getting MSGraph Token
    Write-Output "Getting MSGraph Token"
    $tokenSec = Get-AzAccessToken -ResourceUrl $AlyaGraphEndpoint -TenantId $AlyaTenantId -AsSecureString
    $tokenPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenSec.Token))

    # Sending email
    Write-Output "Sending email"
    Write-Output "  From: $AlyaFromMail"
    Write-Output "  To: $AlyaToMail"
    $subject = "Error in automation runbook '$AlyaRunbookName' in automation account '$AlyaAutomationAccountName'"
    $contentType = "Text"
    $content = "TenantId: $($AlyaTenantId)`n"
    $content += "SubscriptionId: $($AlyaSubscriptionId)`n"
    $content += "ResourceGroupName: $($AlyaResourceGroupName)`n"
    $content += "AutomationAccountName: $($AlyaAutomationAccountName)`n"
    $content += "RunbookName: $($AlyaRunbookName)`n"
    $content += "Exception:`n$($_)`n`n"
    $payload = @{
        Message = @{
            Subject = $subject
            Body = @{ ContentType = $contentType; Content = $content }
            ToRecipients = @( @{ EmailAddress = @{ Address = $AlyaToMail } } )
        }
        saveToSentItems = $false
    }
    $body = ConvertTo-Json $payload -Depth 99 -Compress
    $HeaderParams = @{
        'Accept' = "application/json;odata=nometadata"
        'Content-Type' = "application/json"
        'Authorization' = "$($tokenSec.Type) $($tokenPlain)"
    }
    Clear-Variable -Name "tokenPlain" -Force -ErrorAction Continue
    $Result = ""
    $StatusCode = ""
    do {
        try {
            $Uri = "$AlyaGraphEndpoint/beta/users/$($AlyaFromMail)/sendMail"
            Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "POST" -ContentType "application/json" -Body $body
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 429 -or $StatusCode -eq 503) {
                Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                Start-Sleep -Seconds 45
            }
            else {
                Write-Error $_.Exception -ErrorAction Continue
                throw
            }
        }
    } while ($StatusCode -eq 429 -or $StatusCode -eq 503)

    throw
}

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDn+UQYYHwxOvt2
# Ra/a59csDGJFp8gA16VkDiybGAN776CCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g604YfM/tV
# 5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD4ED6gVYD
# U/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S/gJXhZrh
# 0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp8nKmrVa4
# 6Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqtf2phU7+y
# R2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJQWTEE/bP
# 0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKXvYkPbEdx
# +QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4yMYgcMKb
# 9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmYF8T4xO2k
# 6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2mMIVpqWC
# Z1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7spNY6rQb
# 3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd2jANBgkq
# hkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy/fAHsVv1
# RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW2H3Bh6zN
# XULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0MP6pBPKO
# L6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/pFL9zlcc
# tWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcexU0bcV0hL
# Q4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf6AMOGaM5
# 6A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzECp9LnR+34
# c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9mUF5qE6Yw
# QqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+KuaJRsz+cn
# ZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/JlN6m6GM1j
# EhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutofdgNBzMUx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDTRIeWLsTQyOWN/
# ShWBbCTPtzmOFMyyMpjKGxsSmgx2MA0GCSqGSIb3DQEBAQUABIICAKFr8/Ecqjrd
# Rz9w78qH+VhXYqRpv9Qo/dMzu17t0X8z8MI3XLE2Kbij+ZcaUn0eufBww9Rbv92Y
# nv855p9PZziBoDdgcVccx40BFk3GIUFE+tQX8mT+2A83/kHZewvS669XpPZg58Eq
# LMVOi8cy0OrBaVcq5chl1MmVbXNEJY7FVBIseC3mGlAFQgy6uAdPyO5bPX20S1jG
# 7itgcw3Tv90H0rwWpdlFr7sixQZrzAyIpErbx8crTjdRPOn49lRQnG+6ofYSIb5r
# ifey6DHT+aarjSol9cj+ebG1Wism83pzA5KCKh2Jn5eC00gbvvMP5uKQZINQoQc0
# x2Wmxw2UaahYNjNxeN60+UdMCD9e0s7e52SWFyYVhzb1SzOB5ynV/poEnJHBi+D9
# rzgbPMJuBKknpjeIcoU6NPwlp6sks2lmralDrWDt/t7mwChp2h/j6dLcS0t1gg5Y
# ch3OzdR12R7H2Rracsm+2ZawIbgIOzLN7gHzJiAp3pucbHthc3LlghE96zlq+rLq
# HhQ9Xzj9OfN4DdKghoWaN1IjU8tu0xo0waJ73R7z6sAe5JvBQR6MzSXu7/78oVgL
# oL9GW7VJ60VW8narrMBIXmeWps5ZR+kxtfydAm9iLXbzLZEt5h/8c1t313TMsylm
# fISmGp2krDR3UDx3RrK9Pxa6M+LSwOhsoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCBtQpLYIQAT0DBD1Fm8bUMBkCEUyzeG7/qyO19bkpeywQIUMqLu04WXf+MK
# FPxOOxQMcaLtwToYDzIwMjUxMjE3MjMyNzQyWjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# IEQbxaF6h2cT/L1k8fI25i8AucXqf+zHfg7Uj5Wb1xFfMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAhsI9Ptapaefs
# 6DtJhF+R0rmlrF0Yn8UHN34Gf0ZMJPi7ZdJGO2D0YBDUOiZWn8TMaEsqlFSHgbWy
# 9TjKsMlTBbi+dip2R+3PbApQLq/KdorZDPzFq3M0abMR5hAcwTEN+WjpAZdbZMgr
# WByXyDI0noGbqsQQSLtS6GXHS4rfQu1R8ZsaX7ZKFKM9y73DIOq7lI63OkfQoj+f
# 9+lcABZlxPLnccH3w9r4azEe1fUq8bOw/npkFFU6d2KyBomnK7a+b1HN3b3lcP5x
# h0o24kHBzhYEkQ4prMMgDdPBwtyqcQLgBQlRN9Nu24QyIUVknzZiDj+Gt/dw/Fli
# rjh+OAkQMjtbStp1TR8OJL1LPDQBCpT7B45ZIa5v4IzJfTG2SqF1HS+fpm6y4pMH
# TdGx5hhmwUSIeEjl1Rq0laaQWu/g3alvlaLdGKLQy2LR8ZzMJNh9GejaNGd9ry+H
# TbM6qMTWK7WVAdLRUQVnufbolklNRraMTaFack13RRKfFvFAz1eJ
# SIG # End signature block
