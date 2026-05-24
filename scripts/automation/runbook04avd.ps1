#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    06.02.2026 Konrad Brunner       Added powershell documentation

	timeTag examples:
	05:00
	07:30
	07:30(1,2,3,4,5) (WeekDay): Sunday=0
	07:30(1)[1,l] [Week in month]: 1,2,3,4,5,L=last week,l=last 7 days in month
	07:30[1]
	07:30(1,2,3,4,5);06:30[1] (separate multiple times with ;)

#>

<#
.SYNOPSIS
Automates the management of Azure Virtual Desktop (AVD) virtual machines by starting, stopping, or restarting them according to time-based tags defined on the VM resources.

.DESCRIPTION
This runbook script connects to Azure using a managed identity and processes one or multiple Azure subscriptions to manage the power state of virtual machines based on tag definitions such as STARTTIME, STOPTIME, and REBOOTTIME. It supports complex scheduling with weekday and week-in-month conditions and notifies logged-in users before shutdowns or restarts. The script handles certificate updates, retries Azure authentication, and sends detailed error reports via Microsoft Graph when execution issues occur.

.PARAMETER vmName
Used by internal functions (InformUsers, LogOffSessions) to specify the target virtual machine for sending messages to users or logging off sessions.

.INPUTS
None. The script retrieves all required input values from predefined global variables and Azure resources.

.OUTPUTS
Outputs informational messages about the connection process, VM actions taken (start, stop, restart, inform), and potential errors. Errors are also sent via email to the configured notification address.

.EXAMPLE
PS> .\runbook04avd.ps1
Executes the runbook to evaluate all VMs across configured subscriptions and applies start, stop, or restart actions based on tag schedules and runtime conditions.

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
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
for ($w = 0; $w -lt 7; $w++) {
	$weekDay = $firstDay.AddDays($w * 7)
	if ($runTime.DayOfYear -ge $weekDay.DayOfYear) {
		$weekNumber = $w + 1
	}
	if ($runTime.Month -eq $weekDay.Month) {
		$maxWeek++
	}
}
$isLastWeek = $weekNumber -eq $maxWeek
$isLastWeek7 = ($lastDay.DayOfYear - $runTime.DayOfYear) -lt 7

# Login
Write-Output "Login to Az using system-assigned managed identity"
Disable-AzContextAutosave -Scope Process | Out-Null
try {
	$AzureContext = (Connect-AzAccount -Identity -Environment $AlyaAzureEnvironment -Tenant $AlyaTenantId).Context
}
catch {
	throw "There is no system-assigned user identity. Aborting."; 
	exit 99
}
$AzureContext = Set-AzContext -Subscription $AlyaSubscriptionId -DefaultProfile $AzureContext

# Login-AzureAutomation
$retries = 10
do {
	Start-Sleep -Seconds ((10 - $retries) * 4)
	try {
		$RunAsCertificate = Get-AutomationCertificate -Name "AzureRunAsCertificate"
		try { Disconnect-AzAccount }catch {}
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
	}
 catch {
		try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
		$retries--
		if ($retries -lt 0) {
			Write-Error "Max retries reached!" -ErrorAction Continue
			# Check during certificate update
			$isCertUpdating = $false
			if ($certUpdateDay -gt 0) {
				if ( (Get-Date).Day -eq $certUpdateDay ) {
					$isCertUpdating = $true
				}
			}
			else {
				$weekDay = (Get-Date).DayOfWeek.value__
				if ($weekDay -eq $certUpdateWeekDay -and $weekNumber -eq $certUpdateWeekDayWeek) {
					$isCertUpdating = $true
				}
			}
			if ($isCertUpdating) {
				if ( (Get-Date).Hour -ge $certUpdateStartCheckHour -and (Get-Date).Hour -le $certUpdateStopCheckHour ) {
					Write-Error "Guessing cert update! Exiting..." -ErrorAction Continue
					exit
				}
			}
			else {
				throw
			}
		}
	}
} while ($true)

function InformUsers($vmName) {
	$hPools = Get-AzWvdHostPool
	Write-Output "$vmName"
	Write-Output "Pools"
	foreach ($hPool in $hPools) {
		$rGrp = $hPool.Id.Split("/")[4]
		$sessHosts = Get-AzWvdSessionHost -ResourceGroupName $rGrp -HostPoolName $hPool.Name
		foreach ($sessHost in $sessHosts) {
			$hName = $sessHost.Name.Split("/")[1].Split(".")[0]
			$sName = $sessHost.Name.Split("/")[1]
			if ($vmName -ne $hName) { continue }
			$sessions = Get-AzWvdUserSession -ResourceGroupName $rGrp -HostPoolName $hPool.Name -SessionHostName $sName
			foreach ($session in $sessions) {
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

function LogOffSessions($vmName) {
	$hPools = Get-AzWvdHostPool
	foreach ($hPool in $hPools) {
		$sessHosts = Get-AzWvdSessionHost -ResourceGroupName $hPool.Id.Split("/")[4] -HostPoolName $hPool.Name
		foreach ($sessHost in $sessHosts) {
			if ($vmName -ne $sessHost.Name.Split("/")[1]) { continue }
			$sessions = Get-AzWvdUserSession -ResourceGroupName $hPool.Id.Split("/")[4] -HostPoolName $hPool.Name -SessionHostName $sessHost.Name.Split("/")[1]
			foreach ($session in $sessions) {
				try {
					Disconnect-AzWvdUserSession -ResourceGroupName $hPool.Id.Split("/")[4] `
						-HostPoolName $hPool.Name `
						-SessionHostName $sessHost.Name.Split("/")[1] `
						-Id $session.Name.Split("/")[2]
				}
				catch {}
				try {
					Remove-AzWvdUserSession -ResourceGroupName $hPool.Id.Split("/")[4] `
						-HostPoolName $hPool.Name `
						-SessionHostName $sessHost.Name.Split("/")[1] `
						-Id $session.Name.Split("/")[2]
				}
				catch {}
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
	foreach ($sub in $subs) {
		"Processing subscription: $($sub)"
		$null = Set-AzContext -Subscription $sub

		# Processing resource groups
		Get-AzResourceGroup | Foreach-Object {
			$ResGName = $_.ResourceGroupName
			Write-Output "  Checking ressource group $($ResGName)"
			foreach ($vm in (Get-AzVM -ResourceGroupName $ResGName)) {
				Write-Output "    Checking VM $($vm.Name)"
				$startTimeDefs = @()
				$rebootTimeDefs = @()
				$stopTimeDefs = @()
				$informsDone = @()
				$stopsDone = @()
				$tags = $vm.Tags
				$tKeys = $tags | Select-Object -ExpandProperty keys
				foreach ($tkey in $tkeys) {
					if ($tkey.ToUpper() -eq $startTimeTagName) {
						$startTimeTag = $tags[$tkey]
						Write-Output "- startTimeTag on vm: $($startTimeTag)"
						$startTimeTagValues = $startTimeTag.Split(";")
						foreach ($startTimeTagValue in $startTimeTagValues) {
							$startTime = $null
							$startTimeWds = $null
							$startTimeWks = $null
							if (-Not [string]::IsNullOrEmpty($startTimeTagValue)) {
								Write-Output "- startTimeTag: $($startTimeTagValue)"
								if ($startTimeTagValue.Contains("(") -or $startTimeTagValue.Contains("[")) {
									if ($startTimeTagValue.Contains("(")) { $startTimeWds = $startTimeTagValue.Split("(")[1].Split(")")[0].Split(",") }
									if ($startTimeTagValue.Contains("[")) { $startTimeWks = $startTimeTagValue.Split("[")[1].Split("]")[0].Split(",") }
									$startTimeTag = $startTimeTagValue.Split("(")[0].Split("[")[0]
								}
								else {
									$startTimeTag = $startTimeTagValue
								}
								try { $startTime = [DateTime]::parseexact($startTimeTag, "HH:mm", $null).AddDays($dayOffset) }
								catch { $startTime = $null }
								Write-Output "- startTime parsed: $($startTime)"
								Write-Output "- startTimeWds parsed: $($startTimeWds)"
								Write-Output "- startTimeWks parsed: $($startTimeWks)`n"
								$startTimeDefs += @{
									startTimeTag = $startTimeTagValue
									startTime    = $startTime
									startTimeWds = $startTimeWds
									startTimeWks = $startTimeWks
								}
							}
						}
					}
					if ($tkey.ToUpper() -eq $rebootTimeTagName) {
						$rebootTimeTag = $tags[$tkey]
						Write-Output "- rebootTimeTag on vm: $($rebootTimeTag)"
						$rebootTimeTagValues = $rebootTimeTag.Split(";")
						foreach ($rebootTimeTagValue in $rebootTimeTagValues) {
							$rebootTime = $null
							$rebootTimeWds = $null
							$rebootTimeWks = $null
							if (-Not [string]::IsNullOrEmpty($rebootTimeTagValue)) {
								Write-Output "- rebootTimeTag: $($rebootTimeTagValue)"
								if ($rebootTimeTagValue.Contains("(") -or $rebootTimeTagValue.Contains("[")) {
									if ($rebootTimeTagValue.Contains("(")) { $rebootTimeWds = $rebootTimeTagValue.Split("(")[1].Split(")")[0].Split(",") }
									if ($rebootTimeTagValue.Contains("[")) { $rebootTimeWks = $rebootTimeTagValue.Split("[")[1].Split("]")[0].Split(",") }
									$rebootTimeTag = $rebootTimeTagValue.Split("(")[0].Split("[")[0]
								}
								else {
									$rebootTimeTag = $rebootTimeTagValue
								}
								try { $rebootTime = [DateTime]::parseexact($rebootTimeTag, "HH:mm", $null).AddDays($dayOffset) }
								catch { $rebootTime = $null }
								Write-Output "- rebootTime parsed: $($rebootTime)"
								Write-Output "- rebootTimeWds parsed: $($rebootTimeWds)"
								Write-Output "- rebootTimeWks parsed: $($rebootTimeWks)`n"
								$rebootTimeDefs += @{
									rebootTimeTag = $rebootTimeTagValue
									rebootTime    = $rebootTime
									rebootTimeWds = $rebootTimeWds
									rebootTimeWks = $rebootTimeWks
								}
							}
						}
					}
					if ($tkey.ToUpper() -eq $stopTimeTagName) {
						$stopTimeTag = $tags[$tkey]
						Write-Output "- stopTimeTag on vm: $($stopTimeTag)"
						$stopTimeTagValues = $stopTimeTag.Split(";")
						foreach ($stopTimeTagValue in $stopTimeTagValues) {
							$stopTime = $null
							$stopTimeWds = $null
							$stopTimeWks = $null
							if (-Not [string]::IsNullOrEmpty($stopTimeTagValue)) {
								Write-Output "- stopTimeTag: $($stopTimeTagValue)"
								if ($stopTimeTagValue.Contains("(") -or $stopTimeTagValue.Contains("[")) {
									if ($stopTimeTagValue.Contains("(")) { $stopTimeWds = $stopTimeTagValue.Split("(")[1].Split(")")[0].Split(",") }
									if ($stopTimeTagValue.Contains("[")) { $stopTimeWks = $stopTimeTagValue.Split("[")[1].Split("]")[0].Split(",") }
									$stopTimeTag = $stopTimeTagValue.Split("(")[0].Split("[")[0]
								}
								else {
									$stopTimeTag = $stopTimeTagValue
								}
								try { $stopTime = [DateTime]::parseexact($stopTimeTag, "HH:mm", $null).AddDays($dayOffset) }
								catch { $stopTime = $null }
								Write-Output "- stopTime parsed: $($stopTime)"
								Write-Output "- stopTimeWds parsed: $($stopTimeWds)"
								Write-Output "- stopTimeWks parsed: $($stopTimeWks)`n"
								$stopTimeDefs += @{
									stopTimeTag = $stopTimeTagValue
									stopTime    = $stopTime
									stopTimeWds = $stopTimeWds
									stopTimeWks = $stopTimeWks
								}
							}
						}
					}
				}
				if ($rebootTimeDefs.Count -gt 0) {
					foreach ($rebootTimeDef in $rebootTimeDefs) {
						$rebootTime = $rebootTimeDef.rebootTime
						$rebootTimeTag = $rebootTimeDef.rebootTimeTag
						$ignoreReboot = $false
						if ($null -ne $rebootTimeDef.rebootTimeWds -and $runTime.DayOfWeek.value__ -notin $rebootTimeDef.rebootTimeWds) {
							Write-Output "- Restart ignored. Not right weekday."
							$ignoreReboot = $true
						}
						if ($null -ne $rebootTimeDef.rebootTimeWks -and $weekNumber -notin $rebootTimeDef.rebootTimeWks -and -not ($rebootTimeDef.rebootTimeWks -contains "l" -and $isLastWeek7) -and -not ($rebootTimeDef.rebootTimeWks -contains "L" -and $isLastWeek)) {
							Write-Output "- Restart ignored. Not right week."
							$ignoreReboot = $true
						}
						if ($informUsers -and $infTime -gt $rebootTime -and [Math]::Abs($rebootTime.Subtract($infTime).TotalMinutes) -lt 60) {
							if ($informsDone -notcontains $rebootTimeTag -and -not $ignoreReboot) {
								Write-Output "- Informing users about restart in 1 hour (tag=$rebootTimeTag)"
								InformUsers -vmName $vm.Name
								$informsDone += $rebootTimeTag
							}
						}
						if ($runTime -gt $rebootTime) {
							$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
							foreach ($VMStatus in $VMDetail.Statuses) {
								Write-Output "- VM Status: $($VMStatus.Code)"
								if ($VMStatus.Code.CompareTo("PowerState/running") -eq 0) {
									if ([Math]::Abs($rebootTime.Subtract($runTime).TotalMinutes) -lt 60) {
										if (-not $ignoreReboot) {
											Write-Output "- Restarting VM (tag=$rebootTimeTag)"
											Restart-AzVM -ResourceGroupName $ResGName -Name $vm.Name
										}
									}
								}
							}
						}
					}
				}
				if ($startTimeDefs.Count -gt 0) {
					if ($stopTimeDefs.Count -gt 0) {
						foreach ($startTimeDef in $startTimeDefs) {
							foreach ($stopTimeDef in $stopTimeDefs) {
								$startTime = $startTimeDef.startTime
								$startTimeTag = $startTimeDef.startTimeTag
								$ignoreStart = $false
								if ($null -ne $startTimeDef.startTimeWds -and $runTime.DayOfWeek.value__ -notin $startTimeDef.startTimeWds) {
									Write-Output "- Start ignored. Not right weekday."
									$ignoreStart = $true
								}
								if ($null -ne $startTimeDef.startTimeWks -and $weekNumber -notin $startTimeDef.startTimeWks -and -not ($startTimeDef.startTimeWks -contains "l" -and $isLastWeek7) -and -not ($startTimeDef.startTimeWks -contains "L" -and $isLastWeek)) {
									Write-Output "- Start ignored. Not right week."
									$ignoreStart = $true
								}
								$stopTime = $stopTimeDef.stopTime
								$stopTimeTag = $stopTimeDef.stopTimeTag
								$ignoreStop = $false
								if ($null -ne $stopTimeDef.stopTimeWds -and $runTime.DayOfWeek.value__ -notin $stopTimeDef.stopTimeWds) {
									Write-Output "- Stop ignored. Not right weekday."
									$ignoreStop = $true
								}
								if ($null -ne $stopTimeDef.stopTimeWks -and $weekNumber -notin $stopTimeDef.stopTimeWks -and -not ($stopTimeDef.stopTimeWks -contains "l" -and $isLastWeek7) -and -not ($stopTimeDef.stopTimeWks -contains "L" -and $isLastWeek)) {
									Write-Output "- Stop ignored. Not right week."
									$ignoreStop = $true
								}
								if ($startTime -lt $stopTime) {
									if ($informUsers -and (-Not ($infTime -lt $stopTime -and $infTime -gt $startTime) -and [Math]::Abs($stopTime.Subtract($infTime).TotalMinutes) -lt 60)) {
										if ($informsDone -notcontains $stopTimeTag -and -not $ignoreStop) {
											Write-Output "- Informing users about shutdown in 1 hour (tag=$stopTimeTag)"
											InformUsers -vmName $vm.Name
											$informsDone += $stopTimeTag
										}
									}
									if ($runTime -lt $stopTime -and $runTime -gt $startTime) {
										$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
										foreach ($VMStatus in $VMDetail.Statuses) {
											Write-Output "- VM Status: $($VMStatus.Code)"
											if ($VMStatus.Code.CompareTo("PowerState/deallocated") -eq 0 -or $VMStatus.Code.CompareTo("PowerState/stopped") -eq 0) {
												if ($onlyStartStopOnce -eq $false -or [Math]::Abs($startTime.Subtract($runTime).TotalMinutes) -lt 60) {
													if (-not $ignoreStart) {
														Write-Output "- Starting VM (tag=$startTimeTag)"
														Start-AzVM -ResourceGroupName $ResGName -Name $vm.Name
													}
												}
												else {
													Write-Output "- Start ignored by onlyStartStopOnce."
												}
											}
										}
									}
									else {
										$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
										foreach ($VMStatus in $VMDetail.Statuses) {
											Write-Output "- VM Status: $($VMStatus.Code)"
											if ($VMStatus.Code.CompareTo("PowerState/running") -eq 0) {
												if ($onlyStartStopOnce -eq $false -or [Math]::Abs($stopTime.Subtract($runTime).TotalMinutes) -lt 60) {
													if ($stopsDone -notcontains $stopTimeTag -and -not $ignoreStop) {
														Write-Output "- Stopping VM (tag=$stopTimeTag)"
														LogOffSessions -vmName $vm.Name
														Stop-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Force
														$stopsDone += $stopTimeTag
													}
												}
												else {
													Write-Output "- Stop ignored by onlyStartStopOnce."
												}
											}
										}
									}
								}
								else {
									if ($informUsers -and ($infTime -lt $startTime -and $infTime -gt $stopTime -and [Math]::Abs($stopTime.Subtract($infTime).TotalMinutes) -lt 60)) {
										if (-not $ignoreStop) {
											Write-Output "Informing users about shutdown in 1 hour (tag=$stopTimeTag)"
											InformUsers -vmName $vm.Name
											$informsDone += $stopTimeTag
										}
									}
									if ($runTime -lt $startTime -and $runTime -gt $stopTime) {
										$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
										foreach ($VMStatus in $VMDetail.Statuses) {
											Write-Output "- VM Status: $($VMStatus.Code)"
											if ($VMStatus.Code.CompareTo("PowerState/running") -eq 0) {
												if ($onlyStartStopOnce -eq $false -or [Math]::Abs($stopTime.Subtract($runTime).TotalMinutes) -lt 60) {
													if (-not $ignoreStop) {
														Write-Output "- Stopping VM (tag=$stopTimeTag)"
														LogOffSessions -vmName $vm.Name
														Stop-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Force
														$stopsDone += $stopTimeTag
													}
												}
												else {
													Write-Output "- Stop ignored by onlyStartStopOnce."
												}
											}
										}
									}
									else {
										$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
										foreach ($VMStatus in $VMDetail.Statuses) {
											Write-Output "- VM Status: $($VMStatus.Code)"
											if ($VMStatus.Code.CompareTo("PowerState/deallocated") -eq 0 -or $VMStatus.Code.CompareTo("PowerState/stopped") -eq 0) {
												if ($onlyStartStopOnce -eq $false -or [Math]::Abs($startTime.Subtract($runTime).TotalMinutes) -lt 60) {
													if (-not $ignoreStart) {
														Write-Output "- Starting VM (tag=$startTimeTag)"
														Start-AzVM -ResourceGroupName $ResGName -Name $vm.Name
													}
												}
												else {
													Write-Output "- Start ignored by onlyStartStopOnce."
												}
											}
										}
									}
								}
							}
						}
					}
					else {
						foreach ($startTimeDef in $startTimeDefs) {
							$startTime = $startTimeDef.startTime
							$startTimeTag = $startTimeDef.startTimeTag
							$ignoreStart = $false
							if ($null -ne $startTimeDef.startTimeWds -and $runTime.DayOfWeek.value__ -notin $startTimeDef.startTimeWds) {
								Write-Output "- Start ignored. Not right weekday."
								$ignoreStart = $true
							}
							if ($null -ne $startTimeDef.startTimeWks -and $weekNumber -notin $startTimeDef.startTimeWks -and -not ($startTimeDef.startTimeWks -contains "l" -and $isLastWeek7) -and -not ($startTimeDef.startTimeWks -contains "L" -and $isLastWeek)) {
								Write-Output "- Start ignored. Not right week."
								$ignoreStart = $true
							}
							if ($runTime -gt $startTime) {
								$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
								foreach ($VMStatus in $VMDetail.Statuses) {
									Write-Output "- VM Status: $($VMStatus.Code)"
									if ($VMStatus.Code.CompareTo("PowerState/deallocated") -eq 0 -or $VMStatus.Code.CompareTo("PowerState/stopped") -eq 0) {
										if ($onlyStartStopOnce -eq $false -or [Math]::Abs($startTime.Subtract($runTime).TotalMinutes) -lt 60) {
											if (-not $ignoreStart) {
												Write-Output "- Starting VM (tag=$startTimeTag)"
												Start-AzVM -ResourceGroupName $ResGName -Name $vm.Name
											}
										}
										else {
											Write-Output "- Start ignored by onlyStartStopOnce."
										}
									}
								}
							}
						}
					}
				}
				else {
					if ($stopTimeDefs.Count -gt 0) {
						foreach ($stopTimeDef in $stopTimeDefs) {
							$stopTime = $stopTimeDef.stopTime
							$stopTimeTag = $stopTimeDef.stopTimeTag
							$ignoreStop = $false
							if ($null -ne $stopTimeDef.stopTimeWds -and $runTime.DayOfWeek.value__ -notin $stopTimeDef.stopTimeWds) {
								Write-Output "- Stop ignored. Not right weekday."
								$ignoreStop = $true
							}
							if ($null -ne $stopTimeDef.stopTimeWks -and $weekNumber -notin $stopTimeDef.stopTimeWks -and -not ($stopTimeDef.stopTimeWks -contains "l" -and $isLastWeek7) -and -not ($stopTimeDef.stopTimeWks -contains "L" -and $isLastWeek)) {
								Write-Output "- Stop ignored. Not right week."
								$ignoreStop = $true
							}
							if ($informUsers -and ($infTime -gt $stopTime -and [Math]::Abs($stopTime.Subtract($infTime).TotalMinutes) -lt 60)) {
								if (-not $ignoreStop) {
									Write-Output "Informing users about shutdown in 1 hour (tag=$stopTimeTag)"
									InformUsers -vmName $vm.Name
									$informsDone += $stopTimeTag
								}
							}
							if ($runTime -gt $stopTime -or ($runTime.Hour -eq 0 -and $stopTime.Hour -eq 23)) {
								$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
								foreach ($VMStatus in $VMDetail.Statuses) {
									Write-Output "- VM Status: $($VMStatus.Code)"
									if ($VMStatus.Code.CompareTo("PowerState/running") -eq 0) {
										if ($onlyStartStopOnce -eq $false -or [Math]::Abs($stopTime.Subtract($runTime).TotalMinutes) -lt 60) {
											if (-not $ignoreStop) {
												Write-Output "- Stopping VM (tag=$stopTimeTag)"
												LogOffSessions -vmName $vm.Name
												Stop-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Force
											}
										}
										else {
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
catch {
	Write-Error $_ -ErrorAction Continue
	try { Write-Error ($_ | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}

	# Login back
	Write-Output "Login back to Az using system-assigned managed identity"
	try { Disconnect-AzAccount }catch {}
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
		Message         = @{
			Subject      = $subject
			Body         = @{ ContentType = $contentType; Content = $content }
			ToRecipients = @( @{ EmailAddress = @{ Address = $AlyaToMail } } )
		}
		saveToSentItems = $false
	}
	$body = ConvertTo-Json $payload -Depth 99 -Compress
	$HeaderParams = @{
		'Accept'        = "application/json;odata=nometadata"
		'Content-Type'  = "application/json"
		'Authorization' = "$($tokenSec.Type) $($tokenPlain)"
	}
	Clear-Variable -Name "tokenPlain" -Force -ErrorAction Continue
	$Result = ""
	$StatusCode = ""
	do {
		try {
			$Uri = "$AlyaGraphEndpoint/beta/users/$($AlyaFromMail)/sendMail"
			Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "POST" -ContentType "application/json" -Body $body
		}
		catch {
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
# MIIwlQYJKoZIhvcNAQcCoIIwhjCCMIICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDFbWY+Gp9ibL5v
# ik3CiKfk+rEU2jJZ/mvS2JrL+r59bKCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# giEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKR7lprIhEZLj+QU
# ZWnRQXT9tiU66weevYXy45vvu0IWMA0GCSqGSIb3DQEBAQUABIICAGZhLL9tGep+
# gLYynsarPtWzZzNpQBlfzl3CNX76+5WCvfrQyolLDxxJwcoQiXpf9jEdgj+L8M7v
# evF0MfLtN/yK4jK63DhVJmALOWl02duhmoUp1953jbn1DgfeMDzJNgyTdOKjciAp
# jUM/Cu7AvZZJS7mym5IqL90qN1gtfrH1ZuOK0EHEUDe8SB+f40C6uRP6fUl80dqs
# 4V+dlOqsoL29+4Dz5Q8tW9qjiFvR4diogzPoB2+CLQ4igQ4aF4cDtqMq5Vl//RZd
# nc7nQghnA5d0eAiGd3A5JhrYeRwsv4b07LKTWZDcoA6nmV4P21sNGzYl5KxC50Xu
# Mgukxh5PFKEz/7rAZxensMYHh2wu2eDpHFpRCXYis4qVLuvK8f+qr3B1CPc4Q7lG
# U0naneY0TjZGynPXDxbGawL2fgCtRRSNjAYMawZrhbu9ILo81EGvT6Zmbrle9ylU
# z2ZdzS7KHJy2Ld+7FmfIkEdUpYx5epFDfG46Nw/tKCVBlq1dv5eLc8T6zAtGNEuC
# DJt6ZHD24Ra/PzavRK8QqKifrda7J9uYpoywUzDnrNdSv3Gv9x6yTS3/m6tj7Gus
# AkCSbpS6oxWjEzAdCH0QN/8Uqk3SBPE0WS+NYsDsF1VyFY+2ZjZUbFa3iXES2KRi
# KdJruxt94t7zcRoyc94j5nKf/s+05UQboYId7TCCHekGCisGAQQBgjcDAwExgh3Z
# MIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIwgeQGCyqG
# SIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCGSAFlAwQC
# AQUABCB/tCdfXjrhlowD++H3254nsdNrVNhPJYti1NuvSBXIDAIUBZzR/U4wUxuZ
# 5aGId/InU4gtxv4YDzIwMjYwNTEyMDk1NjIwWjADAgEBoF2kWzBZMQswCQYDVQQG
# EwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFs
# c2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCCBHKgAwIB
# AgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNp
# Z24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUxMDE1MDcy
# NTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xv
# YmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNBIGZvciBD
# b2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDR
# So2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6rVD8pgy1
# sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6qADUMn96m
# qHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6CjX0t3wJfh
# L0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHux0InYS7R
# r54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKOC7QkFbkl
# hPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ0SoibbUq
# xsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQbPGs02Ba
# 8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+TfueCIU0C
# AwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEF
# BQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8dPIxlNigG
# GTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYBBQUHAQEE
# gZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dz
# b2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0cDovL3Nl
# Y3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGltZXN0YW1w
# Y2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmdsb2JhbHNp
# Z24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYDVR0gBE8w
# TTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8v
# d3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4IC
# AQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOfBvhcvoFQ
# w4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SCNLHs6vCg
# 6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdByiHteLxgj
# ugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRWLzPVcUkR
# k9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZsH8EXwiT
# UTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdPL/F8VCMK
# j3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWIV3hgRl+V
# yKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/xCB0/lSK
# LnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJsnmVbS0x
# 50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5+6PokOkQ
# 8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSIoAMCAQIC
# EQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNVBAYTAkJF
# MRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWdu
# IFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00MTA3MTYw
# MDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNh
# MTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFtcGluZyBD
# QSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW+O19i+Ld
# AoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzoZ3nN0CMn
# cZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hfGMG4PJvY
# FvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSaZKraMxFt
# 676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJexYwEVU0
# GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVrYXEdhfVL
# wuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfFJC4P5FW1
# SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z8oTvSaSI
# REovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDzPk+UbLmg
# ZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlTZbVHdqNi
# u0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxUYgoVSxqb
# 4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1UdDwEB/wQE
# AwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/AgEAMB0G
# A1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRGshx34XsV
# 8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcwAYYraHR0
# cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBEBggrBgEF
# BQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvdGltZXN0
# YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAIMAYGBFUd
# IAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1n//quXGL
# VfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM+YjPEf8A
# tC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3yZ6Vcu6Ha
# 0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8njTvAwaT
# MGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534nUINB9whO
# RicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+sQdBidnP
# uLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTfd4yw4nQd
# k1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7NacoTVxZnKG
# kv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZxci6TX78
# smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDXQbEfa93l
# hikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6DC74n5+O5
# bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkqhkiG9w0B
# AQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UE
# ChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEyMDkwMDAw
# MDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBS
# b290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0M+wn3BI4
# IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0lHI7cQ0a
# 72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/WrNU0Pn1k7
# 9S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8NyiwAS+CA6
# YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOooMUz5IWqo
# zfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+PuNF2cvN8
# oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMsDpt3UCA0
# QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvbQhQFB6r7
# FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6SW/bPnf+
# uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jhan+HKd45
# m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32xRdvPBUQ
# sA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNVHQ8BAf8E
# BAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
# HQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwFo5MT4qLn
# 4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJodHRwOi8v
# b2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9odHRwOi8v
# c2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2BgNVHR8E
# LzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3Js
# MEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5n
# bG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAi0i6
# Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l74Z/4omN
# laV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VPZnpmqUdU
# M7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+CLDZZCv5
# 6vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPVSbj/S9Il
# T0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTVha1Fe7Wf
# uy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXeP6Z/xyjv
# oW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb5O1mjj2A
# naSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZmIVHCh5i
# 2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDaI4lgH4Nx
# krXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvxbwPBKVLi
# lL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgECAg5F5rsD
# gzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWdu
# IFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xv
# YmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMaw
# iGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjI
# ElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0y
# BqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3
# YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHN
# V5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTah
# b1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV
# 2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9
# ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmF
# zzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT
# 6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEw
# DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOT
# E+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1Og
# MA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jW
# ZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMT
# VlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgH
# M3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3b
# mZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9Bx
# gXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1e
# bcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRg
# emSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2Zla
# tJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQl
# p7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l3
# 1VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MF
# WsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2Jh
# bFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBSNDUgVGlt
# ZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCGSAFlAwQC
# AqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3DQEJNDEe
# MBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJBDEyBDDy
# 00Rm5wen963F7gFEcglVKEYFHuWIjypoXhU+QguomyBJIosPjayeFVKYz+IsSpww
# gbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS858bMJhdk
# iChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xv
# YmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5lIFI0NSBU
# aW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcN
# AQEMBQAEggGAe3P/qf1IhIOc3OSjm3Uz2PSrteu/Z4zr1S05RtmOv8huA5EwabVy
# gkzm6fzVx2SUo8h+vvFmUmNtZ1rO4K/NmYGTDGtxcm/7lo5n+SYSv+QRlEdSSB9E
# 1xmH0ZSc86V5qTig6sIbK/VlCuI6+9XGyfXEqewPWGAVg1S1OjlhkAzvQhiyhtZ6
# tM7MS48oYpuAqtLaUSa27U1RD14BdhiVvfNea6oN8bpVBO4DCUvC5rHmsJrPRC1L
# sDnysyXQBYtGv7rnarnhqfot9mbdOKpSTM3s+upXkqA5Xj5A93VbrDPalQxeamQw
# 5zqUOFTeUun032Qd+v1/530t3kbXtuXOAQvyTtNtznTQtyscSDlUefmd4EJQYLMQ
# rGrq1bz4A8v91pKvcKwhsFNltLoIzIYSIkuD4+LeWCmLCw6h5SXeQ4521FbGhEh5
# R9QPvtxIkI5IojvzIuwSnistjshIcS5DTpbJxzFdZNzi6ppQmcDGNYhrRWUHC3rC
# OxQpgmI9xFfF
# SIG # End signature block
