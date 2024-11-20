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
    17.03.2020 Konrad Brunner       Initial Version
    18.10.2021 Konrad Brunner       Move to Az
    12.03.2024 Konrad Brunner       Implemented new managed identity concept
    31.07.2024 Konrad Brunner       Implemented WeekDay and Week in month
    31.10.2024 Konrad Brunner       Better cert update handling

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
$Global:ErrorActionPreference = "Stop"
$Global:ProgressPreference = "SilentlyContinue"

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
$stopTimeTagName = "STOPTIME"
$onlyStartStopOnce = $true
$certUpdateDay = 1
$certUpdateWeekDay = -1
$certUpdateWeekDayWeek = -1
$certUpdateStartCheckHour = 4
$certUpdateStopCheckHour = 7
$runTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($(Get-Date), [System.TimeZoneInfo]::Local.Id, $TimeZone)
Write-Output "Run time $($runTime)"
$infTime = $runTime.AddHours(1)

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

try {
	# Members
	$subs = $AlyaSubscriptionIds.Split(",")

	# Processing subscriptions
	foreach($sub in $subs)
	{
		"Processing subscription: $($sub)"
        $null = Set-AzContext -Subscription $sub

		# Processing
		Get-AzResourceGroup | Foreach-Object {
			$ResGName = $_.ResourceGroupName
			Write-Output "  Checking ressource group $($ResGName)"
			foreach($vm in (Get-AzVM -ResourceGroupName $ResGName))
			{
				Write-Output "    Checking VM $($vm.Name)"
				$startTimeDefs = @()
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
    $token = Get-AzAccessToken -ResourceUrl "$AlyaGraphEndpoint" -TenantId $AlyaTenantId

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
        'Authorization' = "$($token.Type) $($token.Token)"
    }
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
