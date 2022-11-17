#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2022

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
    02.04.2020 Konrad Brunner       Initial Version
    13.03.2022 Konrad Brunner       Changed to avd

#>

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\test\40_listRds-$($AlyaTimeString).log" | Out-Null

# Constants
$ErrorActionPreference = "Stop"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionNameTest

# =============================================================
# AVD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AVD | 40_listRds | AVD" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting workspaces
Write-Host "Getting workspaces" -ForegroundColor $CommandInfo
$wrkspcs = Get-AzWvdWorkspace
$hPools = Get-AzWvdHostPool
foreach($wrkspc in $wrkspcs)
{
    Write-Host "Workspace: $($wrkspc.Name) - $($wrkspc.FriendlyName) - $($wrkspc.Description)" -ForegroundColor Blue
    Write-Host "  Properties:"
    Write-Host "    Location: $($wrkspc.Location)"
    Write-Host "    ObjectId: $($wrkspc.ObjectId)"
    Write-Host "    CloudPcResource: $($wrkspc.CloudPcResource)"
    $appRefs = $wrkspc.ApplicationGroupReference
    foreach($appRef in $appRefs)
    {
        $null, $subId, $null, $resGrp, $null, $null, $null, $appGrpName = $appRef.Trim().Trim("/").Split("/")
        $appGrp = Get-AzWvdApplicationGroup -SubscriptionId $subId -ResourceGroupName $resGrp -Name $appGrpName
        Write-Host "  Application Group: $($appGrp.Name) - $($appGrp.FriendlyName) - $($appGrp.Description)" -ForegroundColor DarkGray
        Write-Host "    Properties:"
        Write-Host "      Kind: $($appGrp.Kind)"
        Write-Host "      Location: $($appGrp.Location)"
        Write-Host "      ObjectId: $($appGrp.ObjectId)"
        Write-Host "      CloudPcResource: $($appGrp.CloudPcResource)"
        $apps = Get-AzWvdApplication -SubscriptionId $subId -ResourceGroupName $resGrp -GroupName $appGrpName
        foreach($app in $apps)
        {
            Write-Host "    Application: $($app.Name) - $($app.FriendlyName) - $($app.Description)" -ForegroundColor Gray
            Write-Host "      Properties:"
            Write-Host "        Type: $($app.Type)"
            Write-Host "        ObjectId: $($app.ObjectId)"
        }
        $apps = Get-AzWvdDesktop -SubscriptionId $subId -ResourceGroupName $resGrp -ApplicationGroupName $appGrpName
        foreach($app in $apps)
        {
            Write-Host "    Desktop Application: $($app.Name) - $($app.FriendlyName) - $($app.Description)" -ForegroundColor Gray
            Write-Host "      Properties:"
            Write-Host "        Type: $($app.Type)"
            Write-Host "        ObjectId: $($app.ObjectId)"
        }
        foreach($hPool in $hPools)
        {
            if ($hPool.ApplicationGroupReference -contains $appRef)
            {
                Write-Host "    Hostpool: $($hPool.Name) - $($hPool.FriendlyName) - $($hPool.Description)" -ForegroundColor Magenta
                Write-Host "      Properties:"
                Write-Host "        HostPoolType: $($hPool.HostPoolType)"
                Write-Host "        MaxSessionLimit: $($hPool.MaxSessionLimit)"
                Write-Host "        LoadBalancerType: $($hPool.LoadBalancerType)"
                Write-Host "        Location: $($hPool.Location)"
                Write-Host "        CustomRdpProperty: $($hPool.CustomRdpProperty)"
                Write-Host "        ObjectId: $($hPool.ObjectId)"
                Write-Host "        CloudPcResource: $($hPool.CloudPcResource)"
                $sessHosts = Get-AzWvdSessionHost -SubscriptionId $subId -ResourceGroupName $resGrp -HostPoolName $hPool.Name
                $lastAgent = $null
                $lastSxs = $null
                foreach($sessHost in $sessHosts)
                {
                    $hResult = ""
                    foreach($hr in $sessHost.HealthCheckResult)
                    {
                        $h1 = $hr.HealthCheckName.ToString().Replace("Check", "")
                        $h2 = $hr.HealthCheckResult.ToString().Replace("HealthCheck", "")
                        $hResult += "$($h1):$($h2),"
                    }
                    $hResult = $hResult.Trim(",")
                    $color = "White"
                    Write-Host "      Session Host: $($sessHost.Name)" -ForegroundColor Yellow
                    Write-Host "        Properties:"
                    if (-Not $sessHost.AllowNewSession) { $color = "Red" }
                    Write-Host "          AllowNewSession: $($sessHost.AllowNewSession)" -ForegroundColor $color
                    $color = "White"
                    if ($lastAgent -ne $null -and $lastAgent -ne $sessHost.AgentVersion) { $color = "Red" }
                    Write-Host "          AgentVersion: $($sessHost.AgentVersion)" -ForegroundColor $color
                    $color = "White"
                    $lastAgent = $sessHost.AgentVersion
                    Write-Host "          HealthCheckResult: $($hResult)"
                    Write-Host "          LastHeartBeat: $($sessHost.LastHeartBeat)"
                    Write-Host "          ObjectId: $($sessHost.ObjectId)"
                    Write-Host "          Status: $($sessHost.Status)"
                    Write-Host "          StatusTimestamp: $($sessHost.StatusTimestamp)"
                    if ($sessHost.UpdateState -ne "Succeeded") { $color = "Red" }
                    Write-Host "          UpdateState: $($sessHost.UpdateState)" -ForegroundColor $color
                    $color = "White"
                    Write-Host "          LastUpdateTime: $($sessHost.LastUpdateTime)"
                    if (-Not [string]::IsNullOrEmpty($sessHost.UpdateErrorMessage)) { $color = "Red" }
                    Write-Host "          UpdateErrorMessage: $($sessHost.UpdateErrorMessage)" -ForegroundColor $color
                    $color = "White"
                    if ($lastSxs -ne $null -and $lastSxs -ne $sessHost.SxSStackVersion) { $color = "Red" }
                    Write-Host "          SxSStackVersion: $($sessHost.SxSStackVersion)" -ForegroundColor $color
                    $color = "White"
                    $lastSxs = $sessHost.SxSStackVersion
                    try
                    {
                        $sessions = Get-AzWvdUserSession -SubscriptionId $subId -ResourceGroupName $resGrp -HostPoolName $hPool.Name -SessionHostName $sessHost.Name.Split("/")[1]
                        foreach($session in $sessions)
                        {
                            #$session = $sessions[0]
                            $color = "Red"
                            if ($session.SessionState -eq "Active") { $color = "Green" }
                            if ($session.SessionState -eq "Disconnected") { $color = "DarkGreen" }
                            Write-Host "        Session: $($session.SessionState) - $($session.UserPrincipalName) - $($session.Name)" -ForegroundColor $color
                            Write-Host "          Properties:"
                            Write-Host "            ActiveDirectoryUserName: $($session.ActiveDirectoryUserName)"
                            Write-Host "            CreateTime: $($session.CreateTime)"
                            Write-Host "            Type: $($session.Type)"
                            Write-Host "            ApplicationType: $($session.ApplicationType)"
                        }
                    } catch
                    { }
                }
            }
        }
    }
}

#Stopping Transscript
Stop-Transcript
