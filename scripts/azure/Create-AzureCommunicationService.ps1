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
    02.02.2025 Konrad Brunner       Initial version

#>

[CmdletBinding()]
Param(
	[bool]$ConnectCommunicationEmailService = $true
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Create-AzureCommunicationService-$($AlyaTimeString).log" | Out-Null

# Checks
if (-Not $AlyaResIdCommunicationService)
{
    Write-Warning "Please configure `$AlyaResIdCommunicationService in ConfigureEnv.ps1 an rerun this script"
    Pause
    Exit 1
}
if ($ConnectCommunicationEmailService -and -Not $AlyaResIdCommunicationEmailService)
{
    Write-Warning "Please configure `$AlyaResIdCommunicationEmailService in ConfigureEnv.ps1 an rerun this script"
    Pause
    Exit 1
}

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$CommServiceName = "$($AlyaNamingPrefix)coms$($AlyaResIdCommunicationService)"
$CommEmailServiceName = "$($AlyaNamingPrefix)come$($AlyaResIdCommunicationEmailService)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$DataLocation = "europe"
switch($AlyaLocation)
{
    "westeurope" { $DataLocation = "europe" }
    "switzerlandnorth" { $DataLocation = "switzerland" }
    default { 
        Write-Error "Please update in this script the location mapping for $AlyaLocation. Possible dat locations are: unitedstates, europe, uk, australia, asiapacific, brazil, canada, germany, france, africa, india, japan, korea, uae, switzerland, norway" -ErrorAction Continue
        Exit 1
    }
}
$UserEngagementTracking = "1" #0=Disabled, 1=Enabled

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Communication"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Azure | Create-AzureCommunicationService | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking resource provider registration
Write-Host "Checking resource provider registration Microsoft.Communication" -ForegroundColor $CommandInfo
$resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Communication" -Location $AlyaLocation
if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
{
    Write-Warning "Resource provider Microsoft.Communication not registered. Registering now resource provider Microsoft.Communication"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Communication" | Out-Null
    do
    {
        Start-Sleep -Seconds 5
        $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Communication" -Location $AlyaLocation
    } while ($resProv[0].RegistrationState -ne "Registered")
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ResourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $ResourceGroupName -Location $AlyaLocation -Tag @{displayName="Main Infrastructure Services";ownerEmail=$Context.Account.Id}
}

# Checking key vault
Write-Host "Checking key vault" -ForegroundColor $CommandInfo
$KeyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue
if (-Not $KeyVault)
{
    Write-Error "Key Vault not found!" -ErrorAction Continue
    Exit 1
}

# Setting own key vault access
Write-Host "Setting own key vault access" -ForegroundColor $CommandInfo
$user = Get-AzAdUser -UserPrincipalName $Context.Account.Id
if ($KeyVault.EnableRbacAuthorization)
{
    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $user.Id -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
    $Retries = 0;
    While ($null -eq $RoleAssignment -and $Retries -le 6)
    {
        $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $user.Id -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue
        Start-Sleep -s 10
        $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $user.Id -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
        $Retries++;
    }
    if ($Retries -gt 6)
    {
        throw "Was not able to set role assigment 'Key Vault Administrator' for user $($user.Id) on scope $($KeyVault.ResourceId)"
    }
}
else
{
    Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $user.Id -PermissionsToCertificates "All" -PermissionsToSecrets "All" -PermissionsToKeys "All" -PermissionsToStorage "All" -ErrorAction Continue
}

if ($ConnectCommunicationEmailService)
{
	
	# Checking custom role
	Write-Host "Checking custom role" -ForegroundColor $CommandInfo
	$scope = "/subscriptions/$($Context.Subscription.Id)"
	$role = Get-AzRoleDefinition -Name "$($AlyaCompanyNameShortM365)CommunicationServiceSmtp" -Scope $scope -ErrorAction SilentlyContinue
	if (-Not $Role)
	{
	    $roleDef = @"
{
    "Name": "$($AlyaCompanyNameShortM365)CommunicationServiceSmtp",
    "IsCustom": true,
    "Description": "Role to allow smtp email sending over azure communication services.",
    "Actions": [
    "Microsoft.Communication/CommunicationServices/Read",
    "Microsoft.Communication/CommunicationServices/Write",
    "Microsoft.Communication/EmailServices/write"
    ],
    "NotActions": [],
    "DataActions": [],
    "NotDataActions": [],
    "AssignableScopes": [
    "$scope"
    ]
}
"@
	    $temp = New-TemporaryFile
	    $roleDef | Set-Content -Path $temp -Encoding UTF8 -Force
	    New-AzRoleDefinition -InputFile $temp.FullName
	    Remove-Item -Path $temp -Force
	    do
	    {
	        Start-Sleep -Seconds 10
	        $role = Get-AzRoleDefinition -Name "$($AlyaCompanyNameShortM365)CommunicationServiceSmtp" -Scope $scope -ErrorAction SilentlyContinue
	    }
	    while (-Not $role)
	}
	
	# Checking smtp application
	Write-Host "Checking smtp application" -ForegroundColor $CommandInfo
	$AzureAdApplication = Get-AzADApplication -DisplayName "$($AlyaCompanyNameShortM365)CommunicationServiceSmtp" -ErrorAction SilentlyContinue
	if (-Not $AzureAdApplication)
	{
	    Write-Warning "Azure AD Application not found. Creating the Azure AD Application $($AlyaCompanyNameShortM365)CommunicationServiceSmtp"
	
	    #Creating application and service principal
	    $KeyId = [Guid]::NewGuid()
	    $HomePageUrl = "https://portal.azure.com"
	    $AzureAdApplication = New-AzADApplication -DisplayName "$($AlyaCompanyNameShortM365)CommunicationServiceSmtp" -HomePage $HomePageUrl -IdentifierUris ("http://$AlyaTenantName/$KeyId")
	    $AzureAdServicePrincipal = New-AzADServicePrincipal -ApplicationId $AzureAdApplication.AppId
	
	    #Create credential 
	    $startDate = (Get-Date)
	    $endDate = (Get-Date).AddMonths(120)
	    $AlyaServicePrincipalSecret = New-AzADAppCredential -ApplicationId $AzureAdApplication.AppId -CustomKeyIdentifier ([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("KeyVault $KeyVaultName"))) -StartDate $startDate -EndDate $endDate
	
	    # Checking key vault secret
	    Write-Host "Writing app key to key vault" -ForegroundColor $CommandInfo
	    $AzureSecretName = "$($AlyaCompanyNameShortM365)CommunicationServiceSmtptSecret"
	    $PasswordSec = ConvertTo-SecureString $AlyaServicePrincipalSecret.SecretText -AsPlainText -Force
	    $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AzureSecretName -SecretValue $PasswordSec
	}
	else
	{
	    $AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName "$($AlyaCompanyNameShortM365)CommunicationServiceSmtp"
	}
	
	# Checking communication email service
	Write-Host "Checking communication email service" -ForegroundColor $CommandInfo
	$CommEmailService = Get-AzEmailService -ResourceGroupName $ResourceGroupName -Name $CommEmailServiceName -ErrorAction SilentlyContinue
	if (-Not $CommEmailService)
	{
	    throw "Please create the commincation email service with the script Create-AzureCommunicationEmailService.ps1"
	}

}

# Checking communication service
Write-Host "Checking communication service" -ForegroundColor $CommandInfo
$CommService = Get-AzCommunicationService -ResourceGroupName $ResourceGroupName -Name $CommServiceName -ErrorAction SilentlyContinue
if (-Not $CommService)
{
    Write-Warning "Communication service not found. Creating communication service $CommServiceName"
    $CommService = New-AzCommunicationService -Name $CommServiceName -ResourceGroupName $ResourceGroupName -Location Global -DataLocation $DataLocation -Tag @{displayName="Communication Email Service"}
    if (-Not $CommService)
    {
        Write-Error "Communication service $CommServiceName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}
else
{
    Write-Host "Updating"
    $CommService = Update-AzCommunicationService -Name $CommServiceName -ResourceGroupName $ResourceGroupName -Tag @{displayName="Communication Service"}
}

if ($ConnectCommunicationEmailService)
{

    # Checking sender email domains
    Write-Host "Checking sender email domains" -ForegroundColor $CommandInfo
    $linkedDomains = @()
    $domains = @($AlyaDomainName)
    $domains += $AlyaAdditionalDomainNames
    foreach($domain in $domains)
    {
        $dom = Get-AzEmailServiceDomain -ResourceGroupName $ResourceGroupName -EmailServiceName $CommEmailServiceName -Name $domain -ErrorAction SilentlyContinue
        $linkedDomains += $dom.id
    }

	Write-Host "Connecting email service" -ForegroundColor $CommandInfo
    $CommService = Update-AzCommunicationService -Name $CommServiceName -ResourceGroupName $ResourceGroupName -LinkedDomain $linkedDomains

	Write-Host "Checking sender" -ForegroundColor $CommandInfo
	$senders = Get-AzEmailServiceSenderUsername -EmailServiceName $CommEmailServiceName -ResourceGroupName $ResourceGroupName -DomainName $domain
	foreach($sender in $senders)
	{
	    Write-Host "    $($sender.Name)@$($domain)"
	}
	Write-Host "  To add more senders, please create a Microsoft ticket and request Default Sending Limits change"
	
	# Checking role assignment
	Write-Host "Checking role assignment" -ForegroundColor $CommandInfo
	$RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "$($AlyaCompanyNameShortM365)CommunicationServiceSmtp" -ObjectId $AzureAdServicePrincipal.Id -Scope $CommService.Id -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $CommService.Id }
	$Retries = 0;
	While ($null -eq $RoleAssignment -and $Retries -le 6)
	{
	    $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "$($AlyaCompanyNameShortM365)CommunicationServiceSmtp" -ObjectId $AzureAdServicePrincipal.Id -Scope $CommService.Id -ErrorAction SilentlyContinue
	    Start-Sleep -s 10
	    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "$($AlyaCompanyNameShortM365)CommunicationServiceSmtp" -ObjectId $AzureAdServicePrincipal.Id -Scope $CommService.Id -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $CommService.Id }
	    $Retries++;
	}
	if ($Retries -gt 6)
	{
	    throw "Was not able to set role assigment '$($AlyaCompanyNameShortM365)CommunicationServiceSmtp' for app $($AzureAdServicePrincipal.Id) on scope $($CommService.Id)"
	}
	
	# Done
	$username = "$CommServiceName|$($AzureAdServicePrincipal.AppId)|$AlyaTenantId"
	if ([string]::IsNullOrEmpty($AlyaServicePrincipalPassword))
	{
	    $AlyaServicePrincipalPassword = "stored in Secret $($AlyaCompanyNameShortM365)CommunicationServiceSmtptSecret in KeyVault $KeyVaultName"
	}
	Write-Host "Your SMTP configuration:"
	Write-Host "  Server: smtp.azurecomm.net"
	Write-Host "  Port: 587"
	Write-Host "  TLS/StartTLS: Enabled"
	Write-Host "  From address: $($senders[0].Name)@$($domain)"
	Write-Host "  Username: $username"
	Write-Host "  Password: $AlyaServicePrincipalPassword"
	Write-Host "TLS 1.2 or higher is required"

}

<# TO TEST
[Net.ServicePointManager]::SecurityProtocol = @([Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13)
$EmailTo = "konrad.brunner@alyaconsulting.ch"
$EmailFrom = "$($senders[0].Name)@$($domain)"
$EmailSubject = "Test" 
$EmailBody = "Test Body" 
$SMTPServer = "smtp.azurecomm.net" 
$SMTPMessage = New-Object System.Net.Mail.MailMessage($EmailFrom,$EmailTo,$EmailSubject,$EmailBody)
$SMTPClient = New-Object Net.Mail.SmtpClient($SMTPServer, 587) 
$SMTPClient.EnableSsl = $true 
$SMTPClient.Credentials = New-Object System.Net.NetworkCredential($username, "********************"); 
$SMTPClient.Send($SMTPMessage)
#>


#Stopping Transscript
Stop-Transcript
