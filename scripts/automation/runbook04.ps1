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
    Date       Author               Description
    ---------- -------------------- ----------------------------
    17.03.2020 Konrad Brunner       Initial Version
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
	$tmp = Add-AzAccount `
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
	# Members
	$subs = $Subscriptions.Split(",")
	$runTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($(Get-Date), [System.TimeZoneInfo]::Local.Id, $TimeZone)
	"Run time $($runTime)"

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
										Stop-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Force
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
									"- VM Status: $($VMStatus.Code)"
									if($VMStatus.Code.CompareTo("PowerState/running") -eq 0)
									{
										"- Stopping VM"
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
		                if ($runTime -gt $stopTime -or ($runTime.Hour -eq 0 -and $stopTime.Hour -eq 23))
		                {
						    $VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
						    foreach ($VMStatus in $VMDetail.Statuses)
						    {
							    "- VM Status: $($VMStatus.Code)"
							    if($VMStatus.Code.CompareTo("PowerState/running") -eq 0)
							    {
								    "- Stopping VM"
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
