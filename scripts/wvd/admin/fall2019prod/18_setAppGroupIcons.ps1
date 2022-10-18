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
    12.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019prod\18_setAppGroupIcons-$($AlyaTimeString).log" | Out-Null

# Constants
$BasePath = "C:\$($AlyaCompanyName)\WvdIcons"
$HostPoolName = "$($AlyaNamingPrefix)hpol002"
$availableIcons = @("Word","Excel","PowerPoint","Outlook","OneDrive","Access","Visio","Explorer","OneNote2016","SkypeForBusiness","Project","GoogleChrome","CitrixWorkspace","IrfanView64453","Pdf24","Taskmanager","SapLogon","FinancialConsolidation","FileZilla","BarracudaMessageArchiverSearch","AcrobatReader2017","AutodeskDesignReview","DwgTrueView2020English","Visimove","DimMan","DrTaxOffice","IDLCockpit","Immopac","Quorum","Teams","IMSWare","AbacusAbaStart","AdobeCreativeCloud","AgentRansack","Firefox","TinyPicExe","WinRar","Notepad","RemoteDesktopConnection","MicrosoftEdgeBeta","AcrobatReaderDC","AdobeAcrobatDC")
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.KeyVault"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 18_setAppGroupIcons | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

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

# Main
Write-Host "Please copy folder 'WvdIcons' into folder $($BasePath) on each host in pool."  -ForegroundColor Red
pause

Write-Host "Start menu apps on host:"
$stMenuApps = Get-RDSStartMenuApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName "Desktop Application Group"
foreach ($app in $stMenuApps)
{
    Write-Host " - App $($app.FriendlyName)"
}

$appGrps = Get-RdsAppGroup -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -ErrorAction SilentlyContinue
foreach($appGrp in $appGrps)
{
    #$appGrp = $appGrps[0
    Write-Host "AppGoup $($appGrp.AppGroupName)"

    Write-Host "  Remote apps:"
    $appGrpApps = Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName $appGrp.AppGroupName
    foreach ($app in $appGrpApps)
    {
        Write-Host " - App $($app.RemoteAppName)"
        if ($availableIcons.Contains($app.RemoteAppName))
        {
            $iconPath = $BasePath + "\" + $app.RemoteAppName + ".Ico"
            if ($app.IconPath -ne $iconPath)
            {
                Write-Host "   Setting icon"
                Write-Host "    Actual: $($app.IconPath)"
                Write-Host "    New: $($iconPath)"
                Set-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName $appGrp.AppGroupName -Name $app.RemoteAppName -IconPath $iconPath -IconIndex 0
                <#
                $remApp = Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName $appGrp.AppGroupName
                ($remApp.RemoteAppName)+"."
                (Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName $appGrp.AppGroupName).RemoteAppName + "."
                Remove-RdsRemoteApp $remApp[$remApp.Length-1]
                New-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName $appGrpName -Name $appName -FilePath "C:\Windows\explorer.exe" -RemoteAppName $appName -IconPath "C:\Windows\explorer.exe"
                #>
            }
        }
        else
        {
            Write-Host "   No icon available"
        }
    }
}

#Get-RdsRemoteApp -TenantName "ALYA Prod" -HostPoolName "$($AlyaNamingPrefix)hpol002" -AppGroupName "Standard Apps"
#$activity = Get-RdsDiagnosticActivities -TenantName $AlyaWvdTenantNameProd -ActivityId d1fc9a64-8457-4c63-9600-1ac4a26cdf7e
#Remove-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName "Standard Apps" -Name "File Explorer"
#$activity = Get-RdsDiagnosticActivities -TenantName $AlyaWvdTenantNameProd -ActivityId c9063ef8-03ed-483c-bcff-0e09f48d6bc0
#Set-RdsRemoteApp -TenantName "ALYA Prod" -HostPoolName "$($AlyaNamingPrefix)hpol002" -AppGroupName "Standard Apps" -Name "Explorer" -IconPath "C:\Mobimo\WvdIcons\File Explorer.Ico" -IconIndex 0
#Get-RDSStartMenuApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName "Desktop Application Group" | where {$_.AppAlias -eq "Notepad"}

#Stopping Transscript
Stop-Transcript
