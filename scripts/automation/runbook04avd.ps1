#Requires -Version 2.0

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


    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    17.03.2020 Konrad Brunner       Initial Version
    01.05.2020 Konrad Brunner       Added RDS stuff
    18.10.2021 Konrad Brunner       Move to Az

#>

param(
    [Parameter(Mandatory = $true)]
    [string] $Subscriptions,
    [Parameter(Mandatory = $true)]
    [string] $TimeZone,
    [Parameter(Mandatory = $true)]
    [string] $AzureEnvironment
)
$ErrorActionPreference = "Stop"

# Check pause during certificate update
if ( (Get-Date).Day -eq 1 )
{
    if ( (Get-Date).Hour -ge 1 -and (Get-Date).Hour -le 7 )
    {
        Write-Output "Stopping execution to prevent errors during certificate update."
        Exit
    }
}

# Constants
$RunAsConnectionName = "AzureRunAsConnection"
$RunAsCertificateName = "AzureRunAsCertificate"
$ConnectionTypeName = "AzureServicePrincipal"

# Login-AzureAutomation
try {
	$RunAsConnection = Get-AutomationConnection -Name $RunAsConnectionName
	Write-Output "Logging in to Az ($AzureEnvironment)..."
    Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null
	$null = Add-AzAccount `
		-ServicePrincipal `
		-TenantId $RunAsConnection.TenantId `
        -SubscriptionId $RunAsConnection.SubscriptionId `
		-ApplicationId $RunAsConnection.ApplicationId `
		-CertificateThumbprint $RunAsConnection.CertificateThumbprint `
		-Environment $AzureEnvironment
} catch {
	if (!$RunAsConnection) {
		Write-Output $_.Exception
		Write-Output "Connection $RunAsConnectionName not found."
	}
	throw
}

try {
	# RDS stuff
	$AlyaTenantId = "##AlyaTenantId##"
	$AlyaLocalDomainName = "##AlyaLocalDomainName##"
	$AlyaWvdRDBroker = "##AlyaWvdRDBroker##"
	$AlyaWvdTenantNameProd = "##AlyaWvdTenantNameProd##"
	$AlyaWvdTenantNameTest = "##AlyaWvdTenantNameTest##"
	$AlyaWvdServicePrincipalNameProd = "##AlyaWvdServicePrincipalNameProd##"
	$AlyaWvdServicePrincipalNameTest = "##AlyaWvdServicePrincipalNameTest##"
	$AlyaWvdTenantGroupName = "##AlyaWvdTenantGroupName##"

	$MessageTitle = "Warnung"
	$MessageBody = "Windows Virtual Desktop wird um {0} automatisch heruntergefahren"

	$WvdProdAppCred = Get-AutomationPSCredential -Name $AlyaWvdServicePrincipalNameProd
	$WvdTestAppCred = Get-AutomationPSCredential -Name $AlyaWvdServicePrincipalNameTest

	# Members
	$subs = $Subscriptions.Split(",")
	$runTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($(Get-Date), [System.TimeZoneInfo]::Local.Id, $TimeZone)
	"Run time $($runTime)"
    $infTime = $runTime.AddHours(1)

	# Processing subscriptions
	foreach($sub in $subs)
	{
		"Processing subscription: $($sub)"
        $null = Set-AzContext -Subscription $sub

		Get-AzResourceGroup | Foreach-Object {
			$ResGName = $_.ResourceGroupName
			"  Checking ressource group $($ResGName)"
			foreach($vm in (Get-AzVM -ResourceGroupName $ResGName))
			{
				"    Checking VM $($vm.Name)"
				$tags = $vm.Tags
				$tKeys = $tags | Select-Object -ExpandProperty keys
				$startTime = $null
				$stopTime = $null
				foreach ($tkey in $tkeys)
				{
					if ($tkey.ToUpper() -eq "STARTTIME")
					{
						$startTimeTag = $tags[$tkey]
						"- startTimeTag: $($startTimeTag)"
						try { $startTime = [DateTime]::parseexact($startTimeTag,"HH:mm",$null) }
						catch { $startTime = $null }
						"- startTime parsed: $($startTime)"
					}
					if ($tkey.ToUpper() -eq "STOPTIME")
					{
						$stopTimeTag = $tags[$tkey]
						"- stopTimeTag: $($stopTimeTag)"
						try { $stopTime = [DateTime]::parseexact($stopTimeTag,"HH:mm",$null) }
						catch { $stopTime = $null }
						"- stopTime parsed: $($stopTime)"
					}
				}
	            if ($startTime)
	            {
	                if ($stopTime)
	                {
						if ($startTime -lt $stopTime)
						{
		                    if (-Not ($infTime -lt $stopTime -and $infTime -gt $startTime))
		                    {
								$hostName = $vm.Name + "." + $AlyaLocalDomainName
								$null = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $WvdTestAppCred -ServicePrincipal -AadTenantId $AlyaTenantId
								$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameTest
								foreach ($hpool in $hpools)
								{
									$hosti = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -Name $hostName -ErrorAction SilentlyContinue
									if ($hosti)
									{
										$sessns = Get-RdsUserSession -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -ErrorAction SilentlyContinue
										foreach ($sessn in $sessns)
										{
											if ($sessn.SessionHostName -eq $hostName)
											{
												Send-RdsUserSessionMessage -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -SessionHostName $sessn.SessionHostName -SessionId $sessn.SessionId -MessageTitle $MessageTitle -MessageBody ($MessageBody -f $stopTimeTag) -ErrorAction SilentlyContinue
											}
										}
									}
								}
								$null = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $WvdProdAppCred -ServicePrincipal -AadTenantId $AlyaTenantId
								$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameProd
								foreach ($hpool in $hpools)
								{
									$hosti = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -Name $hostName -ErrorAction SilentlyContinue
									if ($hosti)
									{
										$sessns = Get-RdsUserSession -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -ErrorAction SilentlyContinue
										foreach ($sessn in $sessns)
										{
											if ($sessn.SessionHostName -eq $hostName)
											{
												Send-RdsUserSessionMessage -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -SessionHostName $sessn.SessionHostName -SessionId $sessn.SessionId -MessageTitle $MessageTitle -MessageBody ($MessageBody -f $stopTimeTag) -ErrorAction SilentlyContinue
											}
										}
									}
								}
		                    }
							if ($runTime -lt $stopTime -and $runTime -gt $startTime)
							{
								$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
								foreach ($VMStatus in $VMDetail.Statuses)
								{
									"- VM Status: $($VMStatus.Code)"
									if($VMStatus.Code.CompareTo("PowerState/deallocated") -eq 0 -or $VMStatus.Code.CompareTo("PowerState/stopped") -eq 0)
									{
										"- Starting VM"
										Start-AzVM -ResourceGroupName $ResGName -Name $vm.Name
									}
								}
							}
							else
							{
								$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
								foreach ($VMStatus in $VMDetail.Statuses)
								{
									"- VM Status: $($VMStatus.Code)"
									if($VMStatus.Code.CompareTo("PowerState/running") -eq 0)
									{
										"- Stopping VM"
										$hostName = $vm.Name + "." + $AlyaLocalDomainName
										$null = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $WvdTestAppCred -ServicePrincipal -AadTenantId $AlyaTenantId
										$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameTest
										foreach ($hpool in $hpools)
										{
											$hosti = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -Name $hostName -ErrorAction SilentlyContinue
											if ($hosti)
											{
												$sessns = Get-RdsUserSession -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -ErrorAction SilentlyContinue
												foreach ($sessn in $sessns)
												{
													Invoke-RdsUserSessionLogoff -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -SessionHostName $sessn.SessionHostName -SessionId $sessn.SessionId -NoUserPrompt -ErrorAction SilentlyContinue
												}
												if ($sessns.Count -gt 0)
												{
													Start-Sleep -Seconds 30
												}
											}
										}
										$null = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $WvdProdAppCred -ServicePrincipal -AadTenantId $AlyaTenantId
										$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameProd
										foreach ($hpool in $hpools)
										{
											$hosti = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -Name $hostName -ErrorAction SilentlyContinue
											if ($hosti)
											{
												$sessns = Get-RdsUserSession -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -ErrorAction SilentlyContinue
												foreach ($sessn in $sessns)
												{
													if ($sessn.SessionHostName -eq $hostName)
													{
														Invoke-RdsUserSessionLogoff -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -SessionHostName $sessn.SessionHostName -SessionId $sessn.SessionId -NoUserPrompt -ErrorAction SilentlyContinue
													}
												}
												if ($sessns.Count -gt 0)
												{
													Start-Sleep -Seconds 30
												}
											}
										}
										Stop-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Force
									}
								}
							}
						}
						else
						{
		                    if ($infTime -lt $startTime -and $infTime -gt $stopTime)
		                    {
								$hostName = $vm.Name + "." + $AlyaLocalDomainName
								$null = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $WvdTestAppCred -ServicePrincipal -AadTenantId $AlyaTenantId
								$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameTest
								foreach ($hpool in $hpools)
								{
									$hosti = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -Name $hostName -ErrorAction SilentlyContinue
									if ($hosti)
									{
										$sessns = Get-RdsUserSession -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -ErrorAction SilentlyContinue
										foreach ($sessn in $sessns)
										{
											if ($sessn.SessionHostName -eq $hostName)
											{
												Send-RdsUserSessionMessage -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -SessionHostName $sessn.SessionHostName -SessionId $sessn.SessionId -MessageTitle $MessageTitle -MessageBody ($MessageBody -f $stopTimeTag) -ErrorAction SilentlyContinue
											}
										}
									}
								}
								$null = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $WvdProdAppCred -ServicePrincipal -AadTenantId $AlyaTenantId
								$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameProd
								foreach ($hpool in $hpools)
								{
									$hosti = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -Name $hostName -ErrorAction SilentlyContinue
									if ($hosti)
									{
										$sessns = Get-RdsUserSession -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -ErrorAction SilentlyContinue
										foreach ($sessn in $sessns)
										{
											if ($sessn.SessionHostName -eq $hostName)
											{
												Send-RdsUserSessionMessage -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -SessionHostName $sessn.SessionHostName -SessionId $sessn.SessionId -MessageTitle $MessageTitle -MessageBody ($MessageBody -f $stopTimeTag) -ErrorAction SilentlyContinue
											}
										}
									}
								}
		                    }
							if ($runTime -lt $startTime -and $runTime -gt $stopTime)
							{
								$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
								foreach ($VMStatus in $VMDetail.Statuses)
								{
									"- VM Status: $($VMStatus.Code)"
									if($VMStatus.Code.CompareTo("PowerState/running") -eq 0)
									{
										"- Stopping VM"
										$hostName = $vm.Name + "." + $AlyaLocalDomainName
										$null = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $WvdTestAppCred -ServicePrincipal -AadTenantId $AlyaTenantId
										$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameTest
										foreach ($hpool in $hpools)
										{
											$hosti = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -Name $hostName -ErrorAction SilentlyContinue
											if ($hosti)
											{
												$sessns = Get-RdsUserSession -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -ErrorAction SilentlyContinue
												foreach ($sessn in $sessns)
												{
													Invoke-RdsUserSessionLogoff -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -SessionHostName $sessn.SessionHostName -SessionId $sessn.SessionId -NoUserPrompt -ErrorAction SilentlyContinue
												}
												if ($sessns.Count -gt 0)
												{
													Start-Sleep -Seconds 30
												}
											}
										}
										$null = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $WvdProdAppCred -ServicePrincipal -AadTenantId $AlyaTenantId
										$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameProd
										foreach ($hpool in $hpools)
										{
											$hosti = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -Name $hostName -ErrorAction SilentlyContinue
											if ($hosti)
											{
												$sessns = Get-RdsUserSession -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -ErrorAction SilentlyContinue
												foreach ($sessn in $sessns)
												{
													if ($sessn.SessionHostName -eq $hostName)
													{
														Invoke-RdsUserSessionLogoff -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -SessionHostName $sessn.SessionHostName -SessionId $sessn.SessionId -NoUserPrompt -ErrorAction SilentlyContinue
													}
												}
												if ($sessns.Count -gt 0)
												{
													Start-Sleep -Seconds 30
												}
											}
										}
										Stop-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Force
									}
								}
							}
							else
							{
								$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
								foreach ($VMStatus in $VMDetail.Statuses)
								{
									"- VM Status: $($VMStatus.Code)"
									if($VMStatus.Code.CompareTo("PowerState/deallocated") -eq 0 -or $VMStatus.Code.CompareTo("PowerState/stopped") -eq 0)
									{
										"- Starting VM"
										Start-AzVM -ResourceGroupName $ResGName -Name $vm.Name
									}
								}
							}
						}
	                }
		            else
		            {
		                if ($runTime -gt $startTime)
		                {
						    $VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
						    foreach ($VMStatus in $VMDetail.Statuses)
						    {
							    "- VM Status: $($VMStatus.Code)"
							    if($VMStatus.Code.CompareTo("PowerState/deallocated") -eq 0 -or $VMStatus.Code.CompareTo("PowerState/stopped") -eq 0)
							    {
								    "- Starting VM"
								    Start-AzVM -ResourceGroupName $ResGName -Name $vm.Name
							    }
		                    }
		                }
		            }
	            }
	            else
	            {
	                if ($stopTime)
	                {
		                if ($infTime -gt $stopTime)
		                {
							$hostName = $vm.Name + "." + $AlyaLocalDomainName
							$null = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $WvdTestAppCred -ServicePrincipal -AadTenantId $AlyaTenantId
							$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameTest
							foreach ($hpool in $hpools)
							{
								$hosti = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -Name $hostName -ErrorAction SilentlyContinue
								if ($hosti)
								{
									$sessns = Get-RdsUserSession -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -ErrorAction SilentlyContinue
									foreach ($sessn in $sessns)
									{
										if ($sessn.SessionHostName -eq $hostName)
										{
											Send-RdsUserSessionMessage -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -SessionHostName $sessn.SessionHostName -SessionId $sessn.SessionId -MessageTitle $MessageTitle -MessageBody ($MessageBody -f $stopTimeTag) -ErrorAction SilentlyContinue
										}
									}
								}
							}
							$null = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $WvdProdAppCred -ServicePrincipal -AadTenantId $AlyaTenantId
							$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameProd
							foreach ($hpool in $hpools)
							{
								$hosti = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -Name $hostName -ErrorAction SilentlyContinue
								if ($hosti)
								{
									$sessns = Get-RdsUserSession -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -ErrorAction SilentlyContinue
									foreach ($sessn in $sessns)
									{
										if ($sessn.SessionHostName -eq $hostName)
										{
											Send-RdsUserSessionMessage -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -SessionHostName $sessn.SessionHostName -SessionId $sessn.SessionId -MessageTitle $MessageTitle -MessageBody ($MessageBody -f $stopTimeTag) -ErrorAction SilentlyContinue
										}
									}
								}
							}
		                }
		                if ($runTime -gt $stopTime -or ($runTime.Hour -eq 0 -and $stopTime.Hour -eq 23))
		                {
						    $VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
						    foreach ($VMStatus in $VMDetail.Statuses)
						    {
							    "- VM Status: $($VMStatus.Code)"
							    if($VMStatus.Code.CompareTo("PowerState/running") -eq 0)
							    {
								    "- Stopping VM"
									$hostName = $vm.Name + "." + $AlyaLocalDomainName
									$null = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $WvdTestAppCred -ServicePrincipal -AadTenantId $AlyaTenantId
									$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameTest
									foreach ($hpool in $hpools)
									{
										$hosti = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -Name $hostName -ErrorAction SilentlyContinue
										if ($hosti)
										{
											$sessns = Get-RdsUserSession -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -ErrorAction SilentlyContinue
											foreach ($sessn in $sessns)
											{
												Invoke-RdsUserSessionLogoff -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -SessionHostName $sessn.SessionHostName -SessionId $sessn.SessionId -NoUserPrompt -ErrorAction SilentlyContinue
											}
											if ($sessns.Count -gt 0)
											{
												Start-Sleep -Seconds 30
											}
										}
									}
									$null = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $WvdProdAppCred -ServicePrincipal -AadTenantId $AlyaTenantId
									$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameProd
									foreach ($hpool in $hpools)
									{
										$hosti = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -Name $hostName -ErrorAction SilentlyContinue
										if ($hosti)
										{
											$sessns = Get-RdsUserSession -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -ErrorAction SilentlyContinue
											foreach ($sessn in $sessns)
											{
												if ($sessn.SessionHostName -eq $hostName)
												{
													Invoke-RdsUserSessionLogoff -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName -SessionHostName $sessn.SessionHostName -SessionId $sessn.SessionId -NoUserPrompt -ErrorAction SilentlyContinue
												}
											}
											if ($sessns.Count -gt 0)
											{
												Start-Sleep -Seconds 30
											}
										}
									}
								    Stop-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Force
							    }
		                    }
		                }
	                }
	            }
			}
		}
	}
} catch {
    Write-Error $_.Exception -ErrorAction Continue
    throw
}
