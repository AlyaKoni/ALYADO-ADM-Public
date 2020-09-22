#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This unpublished material is proprietary to Alya Consulting.
    All rights reserved. The methods and techniques described
    herein are considered trade secrets and/or confidential. 
    Reproduction or distribution, in whole or in part, is 
    forbidden except by express written permission of Alya Consulting.

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
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\test\18_setAppGroupIcons-$($AlyaTimeString).log" | Out-Null

# Constants
$BasePath = "C:\$($AlyaCompanyName)\WvdIcons"
$HostPoolName = "$($AlyaNamingPrefixTest)hpol002"
$availableIcons = @("Word","Excel","PowerPoint","Outlook","OneDrive","Access","Visio","Explorer","OneNote2016","SkypeForBusiness","Project","GoogleChrome","CitrixWorkspace","IrfanView64453","Pdf24","Taskmanager","SapLogon","FinancialConsolidation","FileZilla","BarracudaMessageArchiverSearch","AcrobatReader2017","AutodeskDesignReview","DwgTrueView2020English","Visimove","DimMan","DrTaxOffice","IDLCockpit","Immopac","Quorum","Teams","IMSWare","AbacusAbaStart","AdobeCreativeCloud","AgentRansack","Firefox","TinyPicExe","WinRar","Notepad","RemoteDesktopConnection","MicrosoftEdgeBeta","AcrobatReaderDC","AdobeAcrobatDC")
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
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
    Write-Error -Message "Can't get Az context! Not logged in?"
    Exit 1
}

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$AzureAdApplication = Get-AzADApplication -DisplayName $AlyaWvdServicePrincipalNameTest -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    throw "Azure AD Application not found. Please create the Azure AD Application $AlyaWvdServicePrincipalNameTest"
}
$AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdServicePrincipalNameTest

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$AlyaWvdServicePrincipalAssetName = "$($AlyaWvdServicePrincipalNameTest)Key"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AlyaWvdServicePrincipalAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    throw "Key Vault secret not found. Please create the secret $AlyaWvdServicePrincipalAssetName"
}
$AlyaWvdServicePrincipalPassword = $AzureKeyVaultSecret.SecretValueText
$AlyaWvdServicePrincipalPasswordSave = ConvertTo-SecureString $AlyaWvdServicePrincipalPassword -AsPlainText -Force

# Login to WVD
if (-Not $Global:RdsContext)
{
	Write-Host "Logging in to wvd" -ForegroundColor $CommandInfo
	$rdsCreds = New-Object System.Management.Automation.PSCredential($AzureAdServicePrincipal.ApplicationId, $AlyaWvdServicePrincipalPasswordSave)
	$Global:RdsContext = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $rdsCreds -ServicePrincipal -AadTenantId $AlyaTenantId
	#LoginTo-Wvd -AppId $AzureAdServicePrincipal.ApplicationId -SecPwd $AlyaWvdServicePrincipalPasswordSave
}

# Main
Write-Host "Please copy folder 'WvdIcons' into folder $($BasePath) on each host in pool."  -ForegroundColor Red
pause

Write-Host "Start menu apps on host:"
$stMenuApps = Get-RDSStartMenuApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName "Desktop Application Group"
foreach ($app in $stMenuApps)
{
    Write-Host " - App $($app.FriendlyName)"
}

$appGrps = Get-RdsAppGroup -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -ErrorAction SilentlyContinue
foreach($appGrp in $appGrps)
{
    #$appGrp = $appGrps[0
    Write-Host "AppGoup $($appGrp.AppGroupName)"

    Write-Host "  Remote apps:"
    $appGrpApps = Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName $appGrp.AppGroupName
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
                Set-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName $appGrp.AppGroupName -Name $app.RemoteAppName -IconPath $iconPath -IconIndex 0
                <#
                $remApp = Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName $appGrp.AppGroupName
                ($remApp.RemoteAppName)+"."
                (Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName $appGrp.AppGroupName).RemoteAppName + "."
                Remove-RdsRemoteApp $remApp[$remApp.Length-1]
                New-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName $appGrpName -Name $appName -FilePath "C:\Windows\explorer.exe" -RemoteAppName $appName -IconPath "C:\Windows\explorer.exe"
                #>
            }
        }
        else
        {
            Write-Host "   No icon available"
        }
    }
}

#Get-RdsRemoteApp -TenantName "ALYA-Test" -HostPoolName "$($AlyaNamingPrefixTest)hpol002" -AppGroupName "Standard Apps"
#$activity = Get-RdsDiagnosticActivities -TenantName $AlyaWvdTenantNameTest -ActivityId d1fc9a64-8457-4c63-9600-1ac4a26cdf7e
#Remove-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName "Standard Apps" -Name "File Explorer"
#$activity = Get-RdsDiagnosticActivities -TenantName $AlyaWvdTenantNameTest -ActivityId c9063ef8-03ed-483c-bcff-0e09f48d6bc0
#Set-RdsRemoteApp -TenantName "ALYA-Test" -HostPoolName "$($AlyaNamingPrefixTest)hpol002" -AppGroupName "Standard Apps" -Name "Explorer" -IconPath "C:\Mobimo\WvdIcons\File Explorer.Ico" -IconIndex 0
#Get-RDSStartMenuApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName "Desktop Application Group" | where {$_.AppAlias -eq "Notepad"}

#Stopping Transscript
Stop-Transcript
