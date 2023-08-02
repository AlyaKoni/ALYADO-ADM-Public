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
    18.10.2022 Konrad Brunner       Initial Version
    24.07.2023 Konrad Brunner       Added collaboration and other settings

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Set-CrossTenantAccessSettings-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Reports"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"
    
# Logins
LoginTo-MgGraph -Scopes @("Policy.Read.All","Policy.ReadWrite.CrossTenantAccess")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-CrossTenantAccessSettings | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$policies = Get-MgBetaPolicyCrossTenantAccessPolicy
$partners = Get-MgBetaPolicyCrossTenantAccessPolicyPartner

Write-Warning "Actually we do not have an api to check if the"
Write-Warning "'Microsoft cloud settings' are configured. Please check"
Write-Warning "if the cloud env is active your partners relies to."

foreach($tenant in $AlyaFullTrustCrossTenantAccess)
{
    Write-Host "Tenant '$($tenant.Name)' $($tenant.TenantId)" -ForegroundColor $CommandInfo
    $partner = $partners | Where-Object { $_.TenantId -eq $tenant.TenantId }

    $EnableCollaboration = $false
    $EnableDirectConnect = $false
    $IsMfaAccepted = $true
    $IsCompliantDeviceAccepted = $false
    $IsHybridAzureADJoinedDeviceAccepted = $false
    $AllowUsersSync = $false
    $AutomaticRedemption = $false
    if ($null -ne $tenant.EnableCollaboration) { $EnableCollaboration = $tenant.EnableCollaboration }
    if ($null -ne $tenant.EnableDirectConnect) { $EnableDirectConnect = $tenant.EnableDirectConnect }
    if ($null -ne $tenant.IsMfaAccepted) { $IsMfaAccepted = $tenant.IsMfaAccepted }
    if ($null -ne $tenant.IsCompliantDeviceAccepted) { $IsCompliantDeviceAccepted = $tenant.IsCompliantDeviceAccepted }
    if ($null -ne $tenant.IsHybridAzureADJoinedDeviceAccepted) { $IsHybridAzureADJoinedDeviceAccepted = $tenant.IsHybridAzureADJoinedDeviceAccepted }
    if ($null -ne $tenant.AllowUsersSync) { $AllowUsersSync = $tenant.AllowUsersSync }
    if ($null -ne $tenant.AutomaticRedemption) { $AutomaticRedemption = $tenant.AutomaticRedemption }

    if ($null -ne $tenant.CloudEnv) {
       Write-Host "  from cloud $($tenant.CloudEnv)" -ForegroundColor $CommandInfo
    }

    $params = @{
	    TenantId = $tenant.TenantId
        InboundTrust = @{
            IsMfaAccepted = $IsMfaAccepted
            IsCompliantDeviceAccepted = $IsCompliantDeviceAccepted
            IsHybridAzureADJoinedDeviceAccepted = $IsHybridAzureADJoinedDeviceAccepted
        }
        AutomaticUserConsentSettings = @{
            InboundAllowed = $AutomaticRedemption
            OutboundAllowed = $AutomaticRedemption
        }
        <#IdentitySynchronization = @{
            UserSyncInbound = @{
                IsSyncAllowed = $AllowUsersSync
            }
        }#>
    }
    if ($EnableDirectConnect)
    {
        $params.B2bDirectConnectOutbound = @{
            UsersAndGroups = @{
                AccessType = "allowed"
                Targets = @(
                    @{
                        Target = "AllUsers"
                        TargetType = "user"
                    }
                )
            }
            Applications = @{
                AccessType = "allowed"
                Targets = @(
                    @{
                        Target = "AllApplications"
                        TargetType = "application"
                    }
                )
            }
        }
        $params.B2bDirectConnectInbound = @{
            UsersAndGroups = @{
                AccessType = "allowed"
                Targets = @(
                    @{
                        Target = "AllUsers"
                        TargetType = "user"
                    }
                )
            }
            Applications = @{
                AccessType = "allowed"
                Targets = @(
                    @{
                        Target = "AllApplications"
                        TargetType = "application"
                    }
                )
            }
        }
    }
    if ($EnableCollaboration)
    {
        $params.B2bCollaborationOutbound = @{
            UsersAndGroups = @{
                AccessType = "allowed"
                Targets = @(
                    @{
                        Target = "AllUsers"
                        TargetType = "user"
                    }
                )
            }
            Applications = @{
                AccessType = "allowed"
                Targets = @(
                    @{
                        Target = "AllApplications"
                        TargetType = "application"
                    }
                )
            }
        }
        $params.B2bCollaborationInbound = @{
            UsersAndGroups = @{
                AccessType = "allowed"
                Targets = @(
                    @{
                        Target = "AllUsers"
                        TargetType = "user"
                    }
                )
            }
            Applications = @{
                AccessType = "allowed"
                Targets = @(
                    @{
                        Target = "AllApplications"
                        TargetType = "application"
                    }
                )
            }
        }
    }

    if (-Not $partner)
    {
        Write-Host "  Creating policy"
        New-MgBetaPolicyCrossTenantAccessPolicyPartner -BodyParameter $params
    }
    else
    {
        Write-Host "  Updating policy"
        Update-MgBetaPolicyCrossTenantAccessPolicyPartner -CrossTenantAccessPolicyConfigurationPartnerTenantId $tenant.TenantId -BodyParameter $params
    }

    if ($AllowUsersSync)
    {
        Write-Warning "We have actually issues, configuring AllowUsersSync. Pleas eupdate it by hand"
    }

}


#Stopping Transscript
Stop-Transcript
