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
    11.06.2023 Konrad Brunner       Initial Version

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

# Mail settings
$AlyaFromMail = "##AlyaFromMail##"
$AlyaToMail = "##AlyaToMail##"

# Group settings
$grpNameAllExt = "##AlyaAllExternalsGroup##"
$grpNameAllInt = "##AlyaAllInternalsGroup##"
$grpNameDefTeam = "##AlyaDefaultTeamsGroup##"
$grpNamePrjTeam = "##AlyaProjectTeamsGroup##"

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

try
{

	# Check AzureAutomationCertificate
	$RunAsCert = Get-AutomationCertificate -Name "AzureRunAsCertificate"
	Write-Output ("Existing certificate will expire at " + $RunAsCert.NotAfter)

    $grpAllExt = Get-AzAdGroup -DisplayName $grpNameAllExt -Select "Id, DisplayName"
    if ($grpAllExt) {
        Write-Output "Found $($grpAllExt.DisplayName) with id $($grpAllExt.Id)"

        $grpAllMembsExt = Get-AzADGroupMember -GroupObjectId $grpAllExt.Id -Select "Id, UserPrincipalName"
        Write-Output "Existing external members: $($grpAllMembsExt.Count)"
        $grpAllUsersExt = @()
        foreach($memb in $grpAllMembsExt)
        {
            $grpAllUsersExt += Get-AzAdUser -ObjectId $memb.Id -Select "UserPrincipalName, OtherMail, UserType, Id"
        }

    } else {
        Write-Warning "All externals group not found"
    }

    $grpAllInt = Get-AzAdGroup -DisplayName $grpNameAllInt -Select "Id, DisplayName"
    if ($grpAllInt) {
        Write-Output "Found $($grpAllInt.DisplayName) with id $($grpAllInt.Id)"

        $grpAllMembsInt = Get-AzADGroupMember -GroupObjectId $grpAllInt.Id -Select "Id, UserPrincipalName"
        Write-Output "Existing internal members: $($grpAllMembsInt.Count)"
        $grpAllUsersInt = @()
        foreach($memb in $grpAllMembsInt)
        {
            $grpAllUsersInt += Get-AzAdUser -ObjectId $memb.Id -Select "UserPrincipalName, OtherMail, UserType, Id"
        }

    } else {
        Write-Warning "All internals group not found"
    }

    $grpDefTeam = Get-AzAdGroup -DisplayName $grpNameDefTeam -Select "Id, DisplayName"
    if ($grpDefTeam) {
        Write-Output "Found $($grpDefTeam.DisplayName) with id $($grpDefTeam.Id)"

        $grpAllMembsDefTeam = Get-AzADGroupMember -GroupObjectId $grpDefTeam.Id -Select "Id, UserPrincipalName"
        Write-Output "Existing internal members: $($grpAllMembsDefTeam.Count)"
        $grpAllUsersDefTeam = @()
        foreach($memb in $grpAllMembsDefTeam)
        {
            $grpAllUsersDefTeam += Get-AzAdUser -ObjectId $memb.Id -Select "UserPrincipalName, OtherMail, UserType, Id"
        }

    } else {
        Write-Warning "Default teams group not found"
    }

    $grpPrjTeam = Get-AzAdGroup -DisplayName $grpNamePrjTeam -Select "Id, DisplayName"
    if ($grpPrjTeam) {
        Write-Output "Found $($grpPrjTeam.DisplayName) with id $($grpPrjTeam.Id)"

        $grpAllMembsPrjTeam = Get-AzADGroupMember -GroupObjectId $grpPrjTeam.Id -Select "Id, UserPrincipalName"
        Write-Output "Existing internal members: $($grpAllMembsPrjTeam.Count)"
        $grpAllUsersPrjTeam = @()
        foreach($memb in $grpAllMembsPrjTeam)
        {
            $grpAllUsersPrjTeam += Get-AzAdUser -ObjectId $memb.Id -Select "UserPrincipalName, OtherMail, UserType, Id"
        }

    } else {
        Write-Warning "Pproject teams group not found"
    }

    $users = Get-AzAdUser -Select "UserPrincipalName, OtherMail, UserType, Id"
    foreach($user in $users)
    {
        if ($user.UserType -eq "Member")
        {
            Write-Output "Checking member user $($user.UserPrincipalName)"
            if ($grpAllUsersInt -and $grpAllUsersInt.UserPrincipalName -notcontains $user.UserPrincipalName)
            {
                Write-Output "Adding internal user $($user.UserPrincipalName) to all internals group"
                Add-AzADGroupMember -TargetGroupObjectId $grpAllInt.Id -MemberObjectId $user.Id
            }
            if ($grpAllUsersDefTeam -and $grpAllUsersDefTeam.UserPrincipalName -notcontains $user.UserPrincipalName)
            {
                Write-Output "Adding internal user $($user.UserPrincipalName) to default team"
                Add-AzADGroupMember -TargetGroupObjectId $grpDefTeam.Id -MemberObjectId $user.Id
            }
            if ($grpAllUsersPrjTeam -and $grpAllUsersPrjTeam.UserPrincipalName -notcontains $user.UserPrincipalName)
            {
                Write-Output "Adding internal user $($user.UserPrincipalName) to projects team"
                Add-AzADGroupMember -TargetGroupObjectId $grpPrjTeam.Id -MemberObjectId $user.Id
            }
        }
        if ($user.UserType -eq "Guest")
        {
            Write-Output "Checking guest user $($user.UserPrincipalName)"
            if ($grpAllUsersExt -and $grpAllUsersExt.UserPrincipalName -notcontains $user.UserPrincipalName)
            {
                Write-Output "Adding external user $($user.UserPrincipalName) to all externals group"
                Add-AzADGroupMember -TargetGroupObjectId $grpAllExt.Id -MemberObjectId $user.Id
            }
            if ($grpAllUsersDefTeam -and $grpAllUsersDefTeam.UserPrincipalName -notcontains $user.UserPrincipalName)
            {
                Write-Output "Adding external user $($user.UserPrincipalName) to default team"
                Add-AzADGroupMember -TargetGroupObjectId $grpDefTeam.Id -MemberObjectId $user.Id
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
