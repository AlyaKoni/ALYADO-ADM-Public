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
    08.10.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Register-PnPApp.ps1-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Applications"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"

# Logins
LoginTo-MgGraph -Scopes @("Directory.Read.All","AppRoleAssignment.ReadWrite.All","Application.ReadWrite.All","DelegatedPermissionGrant.ReadWrite.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Register-PnPApp.ps1 | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$applicationName = "$($AlyaCompanyNameShortM365)PnPManagementShell"
$MgApplication = Get-MgBetaApplication -Filter "DisplayName eq '$applicationName'" -Property "*"
if (-Not $MgApplication)
{
    Write-Warning "Azure AD Application not found. Creating the Azure AD Application $applicationName"

    $GraphApp = Get-MgBetaServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'" -Property "*"
    $GraphPerms = @(
        @{Id="e4aa47b9-9a69-4109-82ed-36ec70d85ff1";Type="Scope"},
        @{Id="7b8a2d34-6b3f-4542-a343-54651608ad81";Type="Scope"},
        @{Id="bdfbf15f-ee85-4955-8675-146e8e5296b5";Type="Scope"},
        @{Id="0e263e50-5827-48a4-b97c-d940288653c7";Type="Scope"},
        @{Id="c5366453-9fb0-48a5-a156-24f0c49a4b84";Type="Scope"},
        @{Id="64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0";Type="Scope"},
        @{Id="5447fe39-cb82-4c1a-b977-520e67e724eb";Type="Scope"},
        @{Id="863451e7-0667-486c-a5d6-d135439485f0";Type="Scope"},
        @{Id="8019c312-3263-48e6-825e-2b833497195b";Type="Scope"},
        @{Id="17dde5bd-8c17-420f-a486-969730c1b827";Type="Scope"},
        @{Id="ef2779dc-ef1b-4211-8310-8a0ac2450081";Type="Scope"},
        @{Id="4e46008b-f24c-477d-8fff-7bb4ec7aafe0";Type="Scope"},
        @{Id="f81125ac-d3b7-4573-a3b2-7099cc39df9e";Type="Scope"},
        @{Id="7427e0e9-2fba-42fe-b0c0-848c9e6a8182";Type="Scope"},
        @{Id="37f7f235-527c-4136-accd-4a02d197296e";Type="Scope"},
        @{Id="14dad69e-099b-42c9-810b-d002981feec1";Type="Scope"},
        @{Id="5a54b8b3-347c-476d-8f8e-42d5c7424d29";Type="Scope"},
        @{Id="f89c84ef-20d0-4b54-87e9-02e856d66d53";Type="Scope"},
        @{Id="4bb440cd-2cf2-4f90-8004-aa2acd2537c5";Type="Scope"},
        @{Id="405a51b5-8d8d-430b-9842-8be4b0e9f324";Type="Scope"},
        @{Id="63dd7cd9-b489-4adf-a28c-ac38b9a0f962";Type="Scope"},
        @{Id="637d7bec-b31e-4deb-acc9-24275642a2c9";Type="Scope"},
        @{Id="204e0828-b5ca-4ad8-b9f3-f32a958e7cc4";Type="Scope"},
        @{Id="fc30e98b-8810-4501-81f5-c20a3196387b";Type="Scope"}
    )
    $GraphScopes = ($GraphApp.PublishedPermissionScopes | Where-Object { $_.Id -in $GraphPerms.Id }).Value -join " "
    $SpApp = Get-MgBetaServicePrincipal -Filter "DisplayName eq 'Office 365 SharePoint Online'" -Property "*"
    $SpPerms = @(
        @{Id="a4c14cd7-8bd6-4337-8e87-78623dfc023b";Type="Scope"},
        @{Id="c4258712-0efb-41f1-b6bc-be58e4e32f3f";Type="Scope"},
        @{Id="2511a087-5795-4cae-9123-d5b7d6ec4844";Type="Scope"},
        @{Id="b8341dab-4143-49da-8eb9-3d8c073f9e77";Type="Scope"},
        @{Id="d75a7b17-f04e-40d9-8e35-79b949bdb891";Type="Scope"},
        @{Id="2beb830c-70d1-4f5b-a983-79cbdb0c6c6a";Type="Scope"},
        @{Id="e7e732bd-932b-45c4-8ce5-40d60a7daad9";Type="Scope"},
        @{Id="59a198b5-0420-45a8-ae59-6da1cb640505";Type="Scope"},
        @{Id="1002502a-9a71-4426-8551-69ab83452fab";Type="Scope"},
        @{Id="56680e0d-d2a3-4ae1-80d8-3c4f2100e3d0";Type="Scope"},
        @{Id="dd2c8d78-58e1-46d7-82dd-34d411282686";Type="Scope"},
        @{Id="2cfdc887-d7b4-4798-9b33-3d98d6b95dd2";Type="Scope"},
        @{Id="82866913-39a9-4be7-8091-f4fa781088ae";Type="Scope"}
    )
    $SpScopes = ($SpApp.PublishedPermissionScopes | Where-Object { $_.Id -in $SpPerms.Id }).Value -join " "

    #Creating application and service principal
    $KeyId = [Guid]::NewGuid()
    $MgApplication = New-MgBetaApplication -DisplayName "$($applicationName)" `
        -SignInAudience "AzureADMyOrg" `
        -IdentifierUris "http://$AlyaTenantName/$KeyId" `
        -PublicClient @{ RedirectUris="http://localhost" } `
        -RequiredResourceAccess @(@{ ResourceAppId=$GraphApp.AppId; ResourceAccess=$GraphPerms } ,@{ ResourceAppId=$SpApp.AppId; ResourceAccess=$SpPerms })
    $MgServicePrincipal = New-MgBetaServicePrincipal -AppId $MgApplication.AppId

    # Waiting for admin consent
    $tmp = Get-MgBetaApplication -ApplicationId $MgApplication.Id -Property "RequiredResourceAccess"
    while ($tmp.RequiredResourceAccess.Count -lt 2)
    {
        Start-Sleep -Seconds 10
        $tmp = Get-MgBetaApplication -ApplicationId $MgApplication.Id -Property "RequiredResourceAccess"
    }
    Start-Sleep -Seconds 60 # Looks like there is some time issue for admin consent #TODO 60 seconds enough

    #Admin consent
    $params = @{
        ClientId = $MgServicePrincipal.Id
        ConsentType = "AllPrincipals"
        ResourceId = $GraphApp.Id
        Scope = $GraphScopes
        ExpiryTime = [DateTime]::MaxValue
    }
    New-MgBetaOauth2PermissionGrant -BodyParameter $params
    $params = @{
        ClientId = $MgServicePrincipal.Id
        ConsentType = "AllPrincipals"
        ResourceId = $SpApp.Id
        Scope = $SpScopes
        ExpiryTime = [DateTime]::MaxValue
    }
    New-MgBetaOauth2PermissionGrant -BodyParameter $params
}
else
{
    $MgServicePrincipal = Get-MgBetaServicePrincipal -Filter "AppId eq '$($MgApplication.AppId)'"
}

$pnpAppId = $MgServicePrincipal.AppId
$cont = Get-Content -Path "$AlyaData\ConfigureEnv.ps1" -Raw -Encoding $AlyaUtf8Encoding
$cont = $cont.Replace("`$AlyaPnPAppId = `"PleaseSpecify`"", "`$AlyaPnPAppId = `"$pnpAppId`"")
$cont | Set-Content -Path "$AlyaData\ConfigureEnv.ps1" -Encoding $AlyaUtf8Encoding
Write-Warning "PnP AppId $pnpAppId has been set in variable AlyaPnPAppId in data\ConfigureEnv.ps1"

#Stopping Transscript
Stop-Transcript
