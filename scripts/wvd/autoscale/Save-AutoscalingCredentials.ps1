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
    21.04.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "Autoscaling_Config.json", <#"Autoscaling_Config.json"#>
    [Parameter(Mandatory=$false)]
    [ValidateSet("Prod","Test")]
    [string]$ConfigEnv = "Prod"
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\autoscale\Save-AutoscalingCredentials-$($AlyaTimeString).log" | Out-Null

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD Autoscaling | Save-AutoscalingCredentials | LOCAL" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# =============================================================
# Functions
# =============================================================

#Store PWD Function
Function Store-Credentials {
    param(
        [Parameter(Mandatory=$true)]
        [String]$UserName,
        [Parameter(Mandatory=$true)]
        [SecureString]$Password
        )
    $Password | ConvertFrom-SecureString | Out-File "$($AlyaData)\wvd\autoscale\Creds\$($UserName).cred" -Force
}

Function Get-StoredCredential {
    param(
        [Parameter(Mandatory=$false, ParameterSetName="Get")]
        [string]$UserName,
        [Parameter(Mandatory=$false, ParameterSetName="List")]
        [switch]$List
        )

    if ($List) {
        try {
            $CredentialList = @(Get-ChildItem -Path "$($AlyaData)\wvd\autoscale\Creds" -Filter *.cred -ErrorAction STOP)
            foreach ($Cred in $CredentialList) {
                Write-Host $Cred.BaseName
            }
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
    if ($UserName) {
        if (Test-Path "$($AlyaData)\wvd\autoscale\Creds\$($Username).cred") {
            $PwdSecureString = Get-Content "$($AlyaData)\wvd\autoscale\Creds\$($Username).cred" | ConvertTo-SecureString
            $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, $PwdSecureString
        }
        else {
            throw "Unable to locate a credential for $($Username)"
        }
        return $Credential
    }
}

#Function for creating a variable from JSON
function Set-ScriptVariable ($Name,$Value) {
  Invoke-Expression ("`$Script:" + $Name + " = `"" + $Value + "`"")
}

# =============================================================
# Main
# =============================================================

New-Item -Path "$($AlyaData)\wvd\autoscale\Creds" -ItemType Directory -Force | Out-Null

if ($ConfigFile -eq "Autoscaling_Config.json")
{
    Write-Warning "$ConfigFile is just a template. We have to create a new config file in data directory"
    $Variable = Get-Content "$PSScriptRoot\$ConfigFile" -Raw -Encoding UTF8 | ConvertFrom-Json

    Install-ModuleIfNotInstalled Az
    LoginTo-Az -SubscriptionName $AlyaSubscriptionName
    $AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdAzureServicePrincipalName
    ($Variable.WVDScale.Azure.Variables | Where-Object { $_.Name -eq "AADTenantId" }).Value = $AlyaTenantId
    ($Variable.WVDScale.Azure.Variables | Where-Object { $_.Name -eq "AADApplicationId" }).Value = $AzureAdServicePrincipal.AppId.Guid
    ($Variable.WVDScale.Deployment.Variables | Where-Object { $_.Name -eq "rdBroker" }).Value = $AlyaWvdRDBroker
    $ConfigValue = Read-Host -Prompt "Host pool name"
    ($Variable.WVDScale.Azure.Variables | Where-Object { $_.Name -eq "hostPoolName" }).Value = $ConfigValue
    $ConfigFile = "Autoscaling_$ConfigValue.json"
    $ConfigValue = Read-Host -Prompt "Resource group name"
    ($Variable.WVDScale.Deployment.Variables | Where-Object { $_.Name -eq "ResourceGroupName" }).Value = $ConfigValue

    if ($ConfigEnv -eq "Prod")
    {
        $AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdServicePrincipalNameProd
        ($Variable.WVDScale.Azure.Variables | Where-Object { $_.Name -eq "tenantName" }).Value = $AlyaWvdTenantNameProd
        $sub = Get-AzSubscription -SubscriptionName $AlyaSubscriptionName
        ($Variable.WVDScale.Azure.Variables | Where-Object { $_.Name -eq "currentAzureSubscriptionId" }).Value = $sub.Id
        ($Variable.WVDScale.Deployment.Variables | Where-Object { $_.Name -eq "userName" }).Value = $AzureAdServicePrincipal.AppId.Guid
    }
    else
    {
        $AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdServicePrincipalNameTest
        ($Variable.WVDScale.Azure.Variables | Where-Object { $_.Name -eq "tenantName" }).Value = $AlyaWvdTenantNameTest
        $sub = Get-AzSubscription -SubscriptionName $AlyaSubscriptionNameTest
        ($Variable.WVDScale.Azure.Variables | Where-Object { $_.Name -eq "currentAzureSubscriptionId" }).Value = $sub.Id
        ($Variable.WVDScale.Deployment.Variables | Where-Object { $_.Name -eq "userName" }).Value = $AzureAdServicePrincipal.AppId.Guid
    }

    $Variable | ConvertTo-Json -Depth 50 | Set-Content -Path "$($AlyaData)\wvd\autoscale\$ConfigFile" -Encoding UTF8 -Force
}



##### Json path #####
$JsonPath = "$($AlyaData)\wvd\autoscale\$ConfigFile"

###### Verify Json file ######
if (Test-Path $JsonPath) {
  Write-Verbose "Found $JsonPath"
  Write-Verbose "Validating file..."
  try {
    $Variable = Get-Content $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
  }
  catch {
    #$Validate = $false
    Write-Error "$JsonPath is invalid. Check Json syntax - Unable to proceed" -ErrorAction Continue
    exit 1
  }
}
else {
  #$Validate = $false
  Write-Error "Missing $JsonPath - Unable to proceed" -ErrorAction Continue
  exit 1
}
##### Load Json Configuration values as variables #########
Write-Verbose "Loading values from Config.Json"
$Variable = Get-Content $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
$Variable.WVDScale.Azure | ForEach-Object { $_.Variables } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
$Variable.WVDScale.WVDScaleSettings | ForEach-Object { $_.Variables } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
$Variable.WVDScale.Deployment | ForEach-Object { $_.Variables } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }

##### Getting secrets #####
$sCreds = Get-StoredCredential -List
if ($sCreds -notcontains $AADApplicationId)
{
    Write-Host "Missing credentials for AADApplicationId"
    $creds = Get-Credential -Message "Please provide credentials for AADApplicationId" -UserName "AADApplicationId"
    Store-Credentials -UserName $AADApplicationId -Password $creds.Password
}
else
{
    Write-Host "Credentials for AADApplicationId already set"
}
if ($sCreds -notcontains $UserName)
{
    Write-Host "Missing credentials for WVDApplicationId"
    $creds = Get-Credential -Message "Please provide credentials for WVDApplicationId" -UserName "WVDApplicationId"
    Store-Credentials -UserName $UserName -Password $creds.Password
}
else
{
    Write-Host "Credentials for UserName already set"
}

Write-Host "Actual credentials: "
Get-StoredCredential -List

#Stopping Transscript
Stop-Transcript
