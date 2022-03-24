#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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

#>

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019prod\41_getDiagnostics-$($AlyaTimeString).log" | Out-Null

# Constants
$ErrorActionPreference = "Stop"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# WVD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 41_getDiagnostics | WVD" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$AzureAdApplication = Get-AzADApplication -DisplayName $AlyaWvdServicePrincipalNameProd -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    throw "Azure AD Application not found. Please create the Azure AD Application $AlyaWvdServicePrincipalNameProd"
}
$AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdServicePrincipalNameProd

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$AlyaWvdServicePrincipalAssetName = "$($AlyaWvdServicePrincipalNameProd)Key"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AlyaWvdServicePrincipalAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    throw "Key Vault secret not found. Please create the secret $AlyaWvdServicePrincipalAssetName"
}
$AlyaWvdServicePrincipalPasswordSave = $AzureKeyVaultSecret.SecretValue
Clear-Variable -Name AlyaWvdServicePrincipalPassword -Force -ErrorAction SilentlyContinue
Clear-Variable -Name AzureKeyVaultSecret -Force -ErrorAction SilentlyContinue

# Login to WVD
if (-Not $Global:RdsContext)
{
	Write-Host "Logging in to wvd" -ForegroundColor $CommandInfo
	$rdsCreds = New-Object System.Management.Automation.PSCredential($AzureAdServicePrincipal.AppId, $AlyaWvdServicePrincipalPasswordSave)
	$Global:RdsContext = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $rdsCreds -ServicePrincipal -AadTenantId $AlyaTenantId
	#LoginTo-Wvd -AppId $AzureAdServicePrincipal.AppId -SecPwd $AlyaWvdServicePrincipalPasswordSave
}

#Main
$reportStartTime = Get-Date | Get-Date -Hour 0 -Minute 0 -Second 0 

Write-Host "Getting diagnostics" -ForegroundColor $CommandInfo
$acts = Get-RdsDiagnosticActivities -TenantName $AlyaWvdTenantNameProd -Detailed -StartTime $reportStartTime -ErrorAction SilentlyContinue # | where {$_.UserName -like "*$($AlyaDomainName)"}

Write-Host ""
Write-Host "Activities:" -ForegroundColor $CommandInfo
$acts | select ActivityType, Status, StartTime, UserName | Out-String | % {Write-Host $_}

Write-Host "Disconnects:" -ForegroundColor $CommandInfo
$acts = $acts | where {$_.CheckPoints.Name -eq "OnClientDisconnected"}
if (-Not $acts)
{
    Write-Host "No disconnects found`n"
}
else
{
    $errors = @()
    foreach($act in $acts)
    {
        foreach($err in $act.CheckPoints | where {$_.Name -eq "OnClientDisconnected"})
        {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name UserName -Value $act.UserName
            $obj | Add-Member -MemberType NoteProperty -Name Time -Value $err.Time
            $obj | Add-Member -MemberType NoteProperty -Name Code -Value $err.Parameters.DisconnectCode
            $initiatedBy = ""
            if ($err.Parameters.IsProxyServerInitiated -eq 1) {$initiatedBy = "ProxyServer"}
            if ($err.Parameters.IsServerStackInitiated -eq 1) {$initiatedBy = "ServerStack"}
            if ($err.Parameters.IsUserInitiated -eq 1) {$initiatedBy = "User"}
            $obj | Add-Member -MemberType NoteProperty -Name InitiatedBy -Value $initiatedBy
            $obj | Add-Member -MemberType NoteProperty -Name DisconnectCodeSymbolic -Value $err.Parameters.DisconnectCodeSymbolic
            $errors += $obj
        }
    }
    $errors | ft | Out-String | % {Write-Host $_}
}

Write-Host "Errors:" -ForegroundColor $CommandInfo
$acts = Get-RdsDiagnosticActivities -TenantName $AlyaWvdTenantNameProd -Detailed -StartTime $reportStartTime -Outcome Failure -ErrorAction SilentlyContinue
if (-Not $acts)
{
    Write-Host "No errors found`n"
}
else
{
    $errors = @()
    foreach($act in $acts)
    {
        foreach($err in $act.Errors)
        {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name UserName -Value $act.UserName
            $obj | Add-Member -MemberType NoteProperty -Name Time -Value $err.Time
            $obj | Add-Member -MemberType NoteProperty -Name ErrorCode -Value $err.ErrorCodeSymbolic
            $obj | Add-Member -MemberType NoteProperty -Name ReportedBy -Value $err.ReportedBy
            $errors += $obj
        }
    }
    $errors  | Out-String | % {Write-Host $_}
}

Write-Host ""
Write-Host "Health check:" -ForegroundColor $CommandInfo
$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameProd
foreach ($hpool in $hpools)
{
    Write-Host " + HostPool: $($hpool.HostPoolName)"
    Write-Host "   - Hosts"
    $hosts = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameProd -HostPoolName $hpool.HostPoolName
    foreach ($hosti in $hosts)
    {
        Write-Host "     - $($hosti.SessionHostName) AllowNew:$($hosti.AllowNewSession) Status:$($hosti.Status) LastHeartBeat:$($hosti.LastHeartBeat)"
        Write-Host "       Agents: AgentVersion: $($hosti.AgentVersion) SxSStackVersion:$($hosti.SxSStackVersion)"
        Write-Host "       Update: UpdateState: $($hosti.UpdateState) LastUpdateTime:$($hosti.LastUpdateTime) UpdateErrorMessage:$($hosti.UpdateErrorMessage)"
        if ($hosti.SessionHostHealthCheckResult)
        {
            $hosti.SessionHostHealthCheckResult | ConvertFrom-Json | fl *
        }
        else
        {
            Write-Host "       Host health check is null"
        }
    }
}

#Get-RdsDiagnosticActivities -TenantName $AlyaWvdTenantNameProd -UserName Renata.Tozzi@alyaconsulting.ch -Detailed -StartTime "18.09.2019 13:00:00"
#((Get-RdsDiagnosticActivities -TenantName $AlyaWvdTenantNameProd -UserName alex.papadopoulos@alyaconsulting.ch -Detailed -StartTime "18.09.2019 13:00:00").CheckPoints | where {$_.Name -eq "OnClientDisconnected"}).Parameters
#Get-RdsDiagnosticActivities -TenantName $AlyaWvdTenantNameProd -UserName alex.papadopoulos@alyaconsulting.ch -Detailed -StartTime "19.08.2019 17:00:00" | ft ActivityType,StartTime,Outcome
#Get-RdsDiagnosticActivities -TenantName $AlyaWvdTenantNameProd -UserName test.user@alyaconsulting.ch -Detailed -StartTime "19.08.2019 17:00:00" | ft ActivityType,StartTime,Outcome
#(Get-RdsDiagnosticActivities -TenantName $AlyaWvdTenantNameProd -UserName first.last@alyaconsulting.ch -Detailed -StartTime "19.08.2019 17:00:00" | where { $_.Outcome -eq "Failure" }).Errors
#Get-RdsDiagnosticActivities -TenantName $AlyaWvdTenantNameProd -Detailed -ActivityId 05427ab5-6582-4346-8e12-30a1262b89b0

#Stopping Transscript
Stop-Transcript
