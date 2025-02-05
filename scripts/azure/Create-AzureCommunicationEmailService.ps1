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
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Create-AzureCommunicationEmailService-$($AlyaTimeString).log" | Out-Null

# Checks
if (-Not $AlyaResIdCommunicationEmailService)
{
    Write-Warning "Please configure `$AlyaResIdCommunicationEmailService in ConfigureEnv.ps1 an rerun this script"
    Pause
    Exit 1
}

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
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
Write-Host "Azure | Create-AzureCommunicationEmailService | AZURE" -ForegroundColor $CommandInfo
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

# Checking communication email service
Write-Host "Checking communication email service" -ForegroundColor $CommandInfo
$CommEmailService = Get-AzEmailService -ResourceGroupName $ResourceGroupName -Name $CommEmailServiceName -ErrorAction SilentlyContinue
if (-Not $CommEmailService)
{
    Write-Warning "Communication email service not found. Creating communication email service $CommEmailServiceName"
    $CommEmailService = New-AzEmailService -Name $CommEmailServiceName -ResourceGroupName $ResourceGroupName -Location Global -DataLocation $DataLocation -Tag @{displayName="Communication Email Service"}
    if (-Not $CommEmailService)
    {
        Write-Error "Communication email service $CommEmailServiceName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}
else
{
    Write-Host "Updating"
    $CommEmailService = Update-AzEmailService -Name $CommEmailServiceName -ResourceGroupName $ResourceGroupName -Tag @{displayName="Communication Email Service"}
}

# Checking sender email domains
Write-Host "Checking sender email domains" -ForegroundColor $CommandInfo
$domains = @($AlyaDomainName)
$domains += $AlyaAdditionalDomainNames
foreach($domain in $domains)
{
    $dom = Get-AzEmailServiceDomain -ResourceGroupName $ResourceGroupName -EmailServiceName $CommEmailServiceName -Name $domain -ErrorAction SilentlyContinue
    if (-Not $dom)
    {
        Write-Warning "Sender email domain not found. Creating sender email domain $domain"
        $dom = New-AzEmailServiceDomain -ResourceGroupName $ResourceGroupName -EmailServiceName $CommEmailServiceName -Name $domain -DomainManagement "CustomerManaged" -UserEngagementTracking $UserEngagementTracking -Tag @{displayName="$domain Communication Email Service Domain"}
        if (-Not $dom)
        {
            Write-Error "Sender email domain $domain creation failed. Please fix and start over again" -ErrorAction Continue
            Exit 1
        }
    }
    else
    {
        Write-Host "Updating"
        $dom = Update-AzEmailServiceDomain -EmailServiceName $CommEmailServiceName -ResourceGroupName $ResourceGroupName -Name $domain -UserEngagementTracking $UserEngagementTracking -Tag @{displayName="$domain Communication Email Service Domain"}
    }

    Write-Host "  Checking records"
    $missing = $false
    $rec = Resolve-DnsName -Name "$($dom.VerificationRecord.DKIMName).$($domain)" -Type $dom.VerificationRecord.DKIMType -ErrorAction SilentlyContinue
    if (-Not $rec)
    {
        $missing = $true
    }
    else
    {
        if ($rec.NameHost -ne $dom.VerificationRecord.DKIMValue)
        {
            Write-Warning "$($dom.VerificationRecord.DKIMType) record $($dom.VerificationRecord.DKIMName) should be changed from $($rec.NameHost) to $($dom.VerificationRecord.DKIMValue)"
            $missing = $true
        }
    }

    $rec = Resolve-DnsName -Name "$($dom.VerificationRecord.DKIM2Name).$($domain)" -Type $dom.VerificationRecord.DKIM2Type -ErrorAction SilentlyContinue
    if (-Not $rec)
    {
        $missing = $true
    }
    else
    {
        if ($rec.NameHost -ne $dom.VerificationRecord.DKIM2Value)
        {
            Write-Warning "$($dom.VerificationRecord.DKIM2Type) record $($dom.VerificationRecord.DKIM2Name) should be changed from $($rec.NameHost) to $($dom.VerificationRecord.DKIM2Value)"
            $missing = $true
        }
    }

    $recs = Resolve-DnsName -Name "$($dom.VerificationRecord.DomainName)" -Type $dom.VerificationRecord.DomainType -ErrorAction SilentlyContinue
    if (-Not $rec)
    {
        $missing = $true
    }
    else
    {
        $fnd = $false
        foreach($rec in $recs)
        {
            foreach($str in $rec.Strings)
            {
                if ($str -eq $dom.VerificationRecord.DomainValue)
                {
                    $fnd = $true
                    break
                }
            }
        }
        if (-Not $fnd)
        {
            Write-Warning "$($dom.VerificationRecord.DomainType) record $($dom.VerificationRecord.DomainValue) should contain $($dom.VerificationRecord.DomainName)"
            $missing = $true
        }
    }

    $recs = Resolve-DnsName -Name "$($dom.VerificationRecord.DomainName)" -Type $dom.VerificationRecord.SPFType -ErrorAction SilentlyContinue
    if (-Not $rec)
    {
        $missing = $true
    }
    else
    {
        $include = $dom.VerificationRecord.SPFValue.Split()[1]
        $fnd = $false
        foreach($rec in $recs)
        {
            foreach($str in $rec.Strings)
            {
                if ($str.Contains($include))
                {
                    $fnd = $true
                    break
                }
            }
        }
        if (-Not $fnd)
        {
            Write-Warning "$($dom.VerificationRecord.SPFType) record $($dom.VerificationRecord.SPFName) should contain $($dom.VerificationRecord.SPFValue)"
            $missing = $true
        }
    }

    if ($missing)
    {
        Write-Host "Please prepare following DNS records in Domain $($domain) an rerun this script:"
        ($dom.VerificationRecord | ConvertFrom-Json).Domain | Format-List
        ($dom.VerificationRecord | ConvertFrom-Json).SPF | Format-List
        ($dom.VerificationRecord | ConvertFrom-Json).DKIM | Format-List
        ($dom.VerificationRecord | ConvertFrom-Json).DKIM2 | Format-List
        exit
    }
    else
    {
        Write-Host "  Checking verification"
        $dom = Get-AzEmailServiceDomain -ResourceGroupName $ResourceGroupName -EmailServiceName $CommEmailServiceName -Name $domain -ErrorAction SilentlyContinue

        if ($dom.DomainStatus -ne "Verified")
        {
            Write-Host "    Verifying Domain"
            Invoke-AzEmailServiceInitiateDomainVerification -EmailServiceName $CommEmailServiceName -ResourceGroupName $ResourceGroupName -DomainName $domain -VerificationType "Domain"
            #Stop-AzEmailServiceDomainVerification -EmailServiceName $CommEmailServiceName -ResourceGroupName $ResourceGroupName -DomainName $domain -VerificationType "Domain"
        }

        if ($dom.DkimStatus -ne "Verified")
        {
            Write-Host "    Verifying Dkim"
            Invoke-AzEmailServiceInitiateDomainVerification -EmailServiceName $CommEmailServiceName -ResourceGroupName $ResourceGroupName -DomainName $domain -VerificationType "DKIM"
            #Stop-AzEmailServiceDomainVerification -EmailServiceName $CommEmailServiceName -ResourceGroupName $ResourceGroupName -DomainName $domain -VerificationType "DKIM"
        }

        if ($dom.Dkim2Status -ne "Verified")
        {
            Write-Host "    Verifying Dkim2"
            Invoke-AzEmailServiceInitiateDomainVerification -EmailServiceName $CommEmailServiceName -ResourceGroupName $ResourceGroupName -DomainName $domain -VerificationType "DKIM2"
            #Stop-AzEmailServiceDomainVerification -EmailServiceName $CommEmailServiceName -ResourceGroupName $ResourceGroupName -DomainName $domain -VerificationType "DKIM2"
        }

        if ($dom.SpfStatus -ne "Verified")
        {
            Write-Host "    Verifying Spf"
            Invoke-AzEmailServiceInitiateDomainVerification -EmailServiceName $CommEmailServiceName -ResourceGroupName $ResourceGroupName -DomainName $domain -VerificationType "SPF"
            #Stop-AzEmailServiceDomainVerification -EmailServiceName $CommEmailServiceName -ResourceGroupName $ResourceGroupName -DomainName $domain -VerificationType "SPF"
        }

        # if ($dom.DmarcStatus -ne "Verified")
        # {
        #     Write-Host "    Verifying Dmarc"
        #     Invoke-AzEmailServiceInitiateDomainVerification -EmailServiceName $CommEmailServiceName -ResourceGroupName $ResourceGroupName -DomainName $domain -VerificationType "DMARC"
        #     #Stop-AzEmailServiceDomainVerification -EmailServiceName $CommEmailServiceName -ResourceGroupName $ResourceGroupName -DomainName $domain -VerificationType "DMARC"
        # }

        $dom = Get-AzEmailServiceDomain -ResourceGroupName $ResourceGroupName -EmailServiceName $CommEmailServiceName -Name $domain -ErrorAction SilentlyContinue
        $verifying = $false
        if ($dom.DomainStatus -ne "Verified") { $verifying = $true }
        if ($dom.DkimStatus -ne "Verified") { $verifying = $true }
        if ($dom.Dkim2Status -ne "Verified") { $verifying = $true }
        if ($dom.SpfStatus -ne "Verified") { $verifying = $true }
        if ($verifying)
        {
            Write-Warning "Please rerun this script after verification has been done"
            exit
        }
    
    }

}

Write-Host "Checking sender" -ForegroundColor $CommandInfo
$senders = Get-AzEmailServiceSenderUsername -EmailServiceName $CommEmailServiceName -ResourceGroupName $ResourceGroupName -DomainName $domain
foreach($sender in $senders)
{
    Write-Host "    $($sender.Name)@$($domain)"
}
Write-Host "  To add more senders, please create a Microsoft ticket and request Default Sending Limits change"

#Stopping Transscript
Stop-Transcript
