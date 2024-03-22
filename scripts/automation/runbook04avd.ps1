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
    01.05.2020 Konrad Brunner       Added RDS stuff
    18.10.2021 Konrad Brunner       Move to Az
    12.03.2024 Konrad Brunner       Implemented new managed identity concept

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

# Check pause during certificate update
if ( (Get-Date).Day -eq 1 )
{
    if ( (Get-Date).Hour -ge 1 -and (Get-Date).Hour -le 7 )
    {
        Write-Output "Stopping execution to prevent errors during certificate update."
        Exit
    }
}

# Login
Write-Output "Login to Az using system-assigned managed identity"
Disable-AzContextAutosave -Scope Process | Out-Null
try
{
    $AzureContext = (Connect-AzAccount -Identity -Environment $AlyaAzureEnvironment).Context
}
catch
{
    throw "There is no system-assigned user identity. Aborting."; 
    exit 99
}
$AzureContext = Set-AzContext -Subscription $AlyaSubscriptionId -DefaultProfile $AzureContext

try {
    $RunAsCertificate = Get-AutomationCertificate -Name "AzureRunAsCertificate"
    try { Disconnect-AzAccount }catch{}
    Write-Output "Logging in to Az..."
    Write-Output "  Thumbprint $($RunAsCertificate.Thumbprint)"
    Add-AzAccount `
        -ServicePrincipal `
        -TenantId $AlyaTenantId `
        -ApplicationId $AlyaApplicationId `
        -CertificateThumbprint $RunAsCertificate.Thumbprint `
        -Environment $AlyaAzureEnvironment
    Select-AzSubscription -SubscriptionId $AlyaSubscriptionId  | Write-Verbose
	$Context = Get-AzContext
} catch {
    if (!$RunAsCertificate) {
        Write-Output $RunAsCertificateName
        try { Write-Output ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
        Write-Output "Certificate $RunAsCertificateName not found."
    }
    throw
}

function InformUsers($vmName)
{
    $hPools = Get-AzWvdHostPool
    Write-Output "$vmName"
    Write-Output "Pools"
    foreach($hPool in $hPools)
    {
        $rGrp = $hPool.Id.Split("/")[4]
        $sessHosts = Get-AzWvdSessionHost -ResourceGroupName $rGrp -HostPoolName $hPool.Name
    Write-Output "Hosts"
        foreach($sessHost in $sessHosts)
        {
            $hName = $sessHost.Name.Split("/")[1].Split(".")[0]
            $sName = $sessHost.Name.Split("/")[1]
    Write-Output "Host $hName"
            if ($vmName -ne $hName) { continue }
            $sessions = Get-AzWvdUserSession -ResourceGroupName $rGrp -HostPoolName $hPool.Name -SessionHostName $sName
     Write-Output "Sessions"
           foreach($session in $sessions)
            {
     Write-Output "Send"
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
	$runTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($(Get-Date), [System.TimeZoneInfo]::Local.Id, $TimeZone)
	Write-Output "Run time $($runTime)"
    $infTime = $runTime.AddHours(1)

	# Processing subscriptions
	foreach($sub in $subs)
	{
		"Processing subscription: $($sub)"
        $null = Set-AzContext -Subscription $sub

		Get-AzResourceGroup | Foreach-Object {
			$ResGName = $_.ResourceGroupName
			Write-Output "  Checking ressource group $($ResGName)"
			foreach($vm in (Get-AzVM -ResourceGroupName $ResGName))
			{
				Write-Output "    Checking VM $($vm.Name)"
				$tags = $vm.Tags
				$tKeys = $tags | Select-Object -ExpandProperty keys
				$startTime = $null
				$stopTime = $null
				foreach ($tkey in $tkeys)
				{
					if ($tkey.ToUpper() -eq "STARTTIME")
					{
						$startTimeTag = $tags[$tkey]
						Write-Output "- startTimeTag: $($startTimeTag)"
	                    $startTimeTagWd = $null
	                    if ($startTimeTag.Contains("("))
	                    {
	                        Write-Output "- Today is $($runTime.DayOfWeek) which is day $($runTime.DayOfWeek.value__) in week"
	                        $startTimeTagWd = $startTimeTag.Split("(")[1].Replace(")","").Trim(",").Split(",")
	                        $startTimeTag = $startTimeTag.Split("(")[0]
	                    }
						try { $startTime = [DateTime]::parseexact($startTimeTag,"HH:mm",$null) }
						catch { $startTime = $null }
	                    if ($startTimeTagWd -ne $null -and $runTime.DayOfWeek.value__ -notin $startTimeTagWd)
	                    {
	                        $startTime = $null
	                    }
						Write-Output "- startTime parsed: $($startTime)"
					}
					if ($tkey.ToUpper() -eq "STOPTIME")
					{
						$stopTimeTag = $tags[$tkey]
						Write-Output "- stopTimeTag: $($stopTimeTag)"
	                    $stopTimeTagWd = $null
	                    if ($stopTimeTag.Contains("("))
	                    {
	                        Write-Output "- Today is $($runTime.DayOfWeek) which is day $($runTime.DayOfWeek.value__) in week"
	                        $stopTimeTagWd = $stopTimeTag.Split("(")[1].Replace(")","").Trim(",").Split(",")
	                        $stopTimeTag = $stopTimeTag.Split("(")[0]
	                    }
						try { $stopTime = [DateTime]::parseexact($stopTimeTag,"HH:mm",$null) }
						catch { $stopTime = $null }
	                    if ($stopTimeTagWd -ne $null -and $runTime.DayOfWeek.value__ -notin $stopTimeTagWd)
	                    {
	                        $stopTime = $null
	                    }
						Write-Output "- stopTime parsed: $($stopTime)"
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
	                            Write-Output "Informing users about shutdown in 1 hour"
				                InformUsers -vmName $vm.Name
			                }
							if ($runTime -lt $stopTime -and $runTime -gt $startTime)
							{
								$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
								foreach ($VMStatus in $VMDetail.Statuses)
								{
									Write-Output "- VM Status: $($VMStatus.Code)"
									if($VMStatus.Code.CompareTo("PowerState/deallocated") -eq 0 -or $VMStatus.Code.CompareTo("PowerState/stopped") -eq 0)
									{
										Write-Output "- Starting VM"
										Start-AzVM -ResourceGroupName $ResGName -Name $vm.Name
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
										Write-Output "- Stopping VM"
									    LogOffSessions -vmName $vm.Name
										Stop-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Force
									}
								}
							}
						}
						else
						{
			                if ($infTime -lt $startTime -and $infTime -gt $stopTime)
			                {
	                            Write-Output "Informing users about shutdown in 1 hour"
				                InformUsers -vmName $vm.Name
			                }
							if ($runTime -lt $startTime -and $runTime -gt $stopTime)
							{
								$VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
								foreach ($VMStatus in $VMDetail.Statuses)
								{
									Write-Output "- VM Status: $($VMStatus.Code)"
									if($VMStatus.Code.CompareTo("PowerState/running") -eq 0)
									{
										Write-Output "- Stopping VM"
									    LogOffSessions -vmName $vm.Name
										Stop-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Force
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
										Write-Output "- Starting VM"
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
							    Write-Output "- VM Status: $($VMStatus.Code)"
							    if($VMStatus.Code.CompareTo("PowerState/deallocated") -eq 0 -or $VMStatus.Code.CompareTo("PowerState/stopped") -eq 0)
							    {
								    Write-Output "- Starting VM"
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
	                        Write-Output "Informing users about shutdown in 1 hour"
				            InformUsers -vmName $vm.Name
			            }
		                if ($runTime -gt $stopTime -or ($runTime.Hour -eq 0 -and $stopTime.Hour -eq 23))
		                {
						    $VMDetail = Get-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Status
						    foreach ($VMStatus in $VMDetail.Statuses)
						    {
							    Write-Output "- VM Status: $($VMStatus.Code)"
							    if($VMStatus.Code.CompareTo("PowerState/running") -eq 0)
							    {
								    Write-Output "- Stopping VM"
								    LogOffSessions -vmName $vm.Name
								    Stop-AzVM -ResourceGroupName $ResGName -Name $vm.Name -Force
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
