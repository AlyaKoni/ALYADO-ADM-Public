#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    14.11.2019 Konrad Brunner       Initial Version
    18.10.2021 Konrad Brunner       Move to Az
    10.02.2022 Konrad Brunner       fixed Add-AdAppCredential by replacing with REST call
    01.06.2023 Konrad Brunner       fixed again Add-AdAppCredential by removing REST call, implemented new managed identity concept
    06.02.2026 Konrad Brunner       Added powershell documentation
    04.05.2026 Konrad Brunner       More robust updates
    08.07.2026 Konrad Brunner       Better app cert handling
    01.09.2026 Konrad Brunner       Better app cert removal handling
    10.09.2026 Konrad Brunner       Robust credential handling: create once with generated KeyId, use cmdlet output, read-only polling, removal only for own RunAs cert (name or old thumbprint), verbose logging
    10.09.2026 Konrad Brunner       Calm logging for transient Graph removal errors: INFO line with retry instead of ERROR output, full error details only after the final attempt
    11.09.2026 Konrad Brunner       Replaced Remove-AzADAppCredential with surgical Graph removeKey REST call (the cmdlet does a blind read-modify-write over the whole keyCredentials collection which can WIPE ALL credentials on stale reads), post-removal verification with self-healing re-add
    11.09.2026 Konrad Brunner       Pure Az approach (Graph REST removed again): previous-generation credentials are removed at the START of a run against long-converged keys only (race-free by design), current automation certificate credential preserved by thumbprint, defensive Graph token handling in the mail path

#>

<#
.SYNOPSIS
Automatically renews the Azure Automation Run As account certificate and updates all associated Azure resources and applications.

.DESCRIPTION
The script connects to Azure using a system-assigned managed identity, validates the existing Run As account certificate for the Automation Account, and if necessary, generates a new self-signed certificate. It updates the certificate in Azure Key Vault, the Automation Account, and the associated Azure AD application. If any part of the operation fails, it sends an email notification using Microsoft Graph with details about the error.

.INPUTS
None. All configuration values are defined as variables within the script.

.OUTPUTS
Console output detailing each operation and any encountered errors. If an error occurs, an error email is also sent.

.EXAMPLE
PS> .\runbook03.ps1

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

# Defaults
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
$Global:ErrorActionPreference = "Stop"
$Global:ProgressPreference = "SilentlyContinue"
$VerbosePreference = "Continue"
$ProgressPreference = "Continue"

# Runbook
$AlyaResourceGroupName = "##AlyaResourceGroupName##"
$AlyaAutomationAccountName = "##AlyaAutomationAccountName##"
$AlyaRunbookName = "##AlyaRunbookName##"

# RunAsAccount
$AlyaApplicationId = "##AlyaApplicationId##"
$AlyaTenantId = "##AlyaTenantId##"
$AlyaCertificateKeyVaultName = "##AlyaCertificateKeyVaultName##"
$AlyaCertificateSecretName = "##AlyaCertificateSecretName##"
$AlyaSubscriptionId = "##AlyaSubscriptionId##"

# Mail settings
$AlyaFromMail = "##AlyaFromMail##"
$AlyaToMail = "##AlyaToMail##"

# Other settings
$AlyaGraphEndpoint = "##AlyaGraphEndpoint##"
$AzureCertifcateAssetName = "##AlyaCertifcateAssetName##"

# Login
Write-Output "Login to Az using system-assigned managed identity"
Disable-AzContextAutosave -Scope Process | Out-Null
try {
    $AzureContext = (Connect-AzAccount -Identity).Context
}
catch {
    throw "There is no system-assigned user identity. Aborting."; 
    exit 99
}
$AzureContext = Set-AzContext -Subscription $AlyaSubscriptionId -DefaultProfile $AzureContext

try {

    # Check AzureAutomationCertificate
    $RunAsCert = Get-AutomationCertificate -Name "AzureRunAsCertificate"
    Write-Output ("Existing certificate will expire at " + $RunAsCert.NotAfter)
    <#
	if ($RunAsCert.NotAfter -gt (Get-Date).AddMonths(3))
	{
		Write-Output ("Nothing to do!")
		Exit(0)
	}
	#>

    # Find the application
    Write-Output ("Getting application $($AlyaApplicationId)")
    $Filter = "AppId eq '" + $AlyaApplicationId + "'"
    $AzAdApplication = Get-AzADApplication -Filter $Filter
    if (-Not $AzAdApplication) { throw "Application with id $($AlyaApplicationId) not found" }

    $AzureCertificateName = $AlyaAutomationAccountName + $AzureCertifcateAssetName
    # Removing previous-generation RunAs credentials (start-of-run cleanup)
    #
    # Deletion strategy - pure Az and race-free by design:
    # Old credentials are removed HERE, at the START of a rotation run, long after they
    # were created. Remove-AzADAppCredential internally rewrites the WHOLE keyCredentials
    # collection (GET app, filter out the target KeyId, PATCH the app with the rest).
    # Running it directly after adding a fresh credential is a race against Graph
    # replication: a stale internal read can miss the fresh key and the PATCH then WIPES
    # the entire collection (observed in production on 10.09.2026: the app ended up with
    # ZERO credentials), or it rewrites the collection with stale content (zombie
    # effects). Against long-converged keys the same call is deterministic and safe -
    # therefore this script only ever removes PREVIOUS generations, never a credential
    # it just created. The credential replaced by this run stays on the app until the
    # NEXT run removes it (documented one-generation overlap).
    #
    # Safety guards:
    # - The credential matching the CURRENT automation certificate (thumbprint compare)
    #   is preserved unconditionally - it is the current-generation RunAs credential.
    # - Only credentials with DisplayName "CN=$AzureCertificateName" are candidates.
    #   Foreign certificates and client secrets are never touched.
    # - If the current credential cannot be identified, NO removal happens at all.
    Write-Output "Checking for previous-generation RunAs credentials to remove"
    $assetThumbprintBase64 = ""
    try { $assetThumbprintBase64 = [System.Convert]::ToBase64String($RunAsCert.GetCertHash()) } catch { Write-Output ("WARNING: could not determine automation certificate thumbprint: " + $_.Exception.Message) }
    Write-Output ("Thumbprint (base64) of the current automation certificate: " + $assetThumbprintBase64)
    $rawCleanup = @(Get-AzADAppCredential -ApplicationId $AzAdApplication.AppId)
    $cleanupList = @()
    foreach ($rawItem in $rawCleanup) { $cleanupList += @($rawItem) }
    Write-Output ("Credentials visible at start: " + $cleanupList.Count)
    $preserveKeyId = $null
    $previousGenKeyIds = @()
    foreach ($actCert in $cleanupList) {
        $parsedKeyId = "$($actCert.KeyId)" -as [Guid]
        $keyIdString = "<unparsable KeyId>"
        if ($null -ne $parsedKeyId) { $keyIdString = $parsedKeyId.ToString() }
        $ckiString = ""
        try {
            if ($actCert.CustomKeyIdentifier -is [byte[]]) { $ckiString = [System.Convert]::ToBase64String($actCert.CustomKeyIdentifier) }
            elseif ($null -ne $actCert.CustomKeyIdentifier) { $ckiString = "$($actCert.CustomKeyIdentifier)" }
        } catch { $ckiString = "" }
        Write-Output ("  START: KeyId=" + $keyIdString + " DisplayName=" + $actCert.DisplayName + " Type=" + $actCert.Type + " Start=" + $actCert.StartDateTime + " End=" + $actCert.EndDateTime + " Thumbprint=" + $ckiString)
        if ($null -eq $parsedKeyId) {
            Write-Output ("WARNING: credential with unparsable KeyId (System.Object[] case) - it will never be removed. Raw object follows:")
            try { Write-Output ($actCert | ConvertTo-Json -Depth 5) } catch { Write-Output ($actCert | Out-String) }
            continue
        }
        if ($assetThumbprintBase64 -ne "" -and $ckiString -eq $assetThumbprintBase64) {
            $preserveKeyId = $parsedKeyId
            Write-Output ("  -> current automation certificate credential - preserved")
            continue
        }
        if ($actCert.DisplayName -eq "CN=$AzureCertificateName") {
            $previousGenKeyIds += $keyIdString
            Write-Output ("  -> previous-generation RunAs credential - marked for removal")
        } else {
            Write-Output ("  -> foreign or unknown credential - never touched")
        }
    }
    if ($null -eq $preserveKeyId) {
        Write-Output "WARNING: could not identify the current automation certificate credential by thumbprint - skipping ALL removals this run (safety first)"
        $previousGenKeyIds = @()
    }
    $cleanupFailures = 0
    foreach ($oldKeyIdString in $previousGenKeyIds) {
        Write-Output ("Removing previous-generation certificate " + $oldKeyIdString)
        $removed = $false
        $maxRemoveAttempts = 3
        for ($removeAttempt = 1; $removeAttempt -le $maxRemoveAttempts; $removeAttempt++) {
            try {
                Remove-AzADAppCredential -ApplicationId $AzAdApplication.AppId -KeyId ([Guid]$oldKeyIdString)
                $removed = $true
                Write-Output ("Removed previous-generation certificate " + $oldKeyIdString + " (attempt " + $removeAttempt + ")")
                break
            } catch {
                if ($removeAttempt -lt $maxRemoveAttempts) {
                    Write-Output ("INFO: removal of " + $oldKeyIdString + " was not accepted on attempt " + $removeAttempt + " (" + $_.Exception.Message + ") - known transient effect, retrying in 10 seconds...")
                    Start-Sleep -Seconds 10
                } else {
                    Write-Output ("ERROR: removing " + $oldKeyIdString + " failed on the final attempt " + $removeAttempt + ": " + $_.Exception.Message)
                    Write-Output ("ERROR details: " + ($_ | Out-String))
                }
            }
        }
        if (-not $removed) { $cleanupFailures++ }
    }
    if ($previousGenKeyIds.Count -eq 0) {
        Write-Output "No previous-generation RunAs credential was present - nothing was removed"
    }
    # Cleanup verification. Safe here: the preserved credential (this session's identity)
    # was NOT removed, so the Az session stays fully functional during verification.
    if ($previousGenKeyIds.Count -gt 0) {
        $stillThere = $false
        $preserveMissingCount = 0
        for ($verifyAttempt = 1; $verifyAttempt -le 6; $verifyAttempt++) {
            Start-Sleep -Seconds 10
            try {
                $rawVerify = @(Get-AzADAppCredential -ApplicationId $AzAdApplication.AppId)
                $verifyList = @()
                foreach ($rawItem in $rawVerify) { $verifyList += @($rawItem) }
            } catch {
                Write-Output ("ERROR: Get-AzADAppCredential failed during cleanup verification: " + $_.Exception.Message)
                continue
            }
            $visibleKeyIds = @()
            foreach ($visCred in $verifyList) {
                $visKeyId = "$($visCred.KeyId)" -as [Guid]
                if ($null -ne $visKeyId) { $visibleKeyIds += $visKeyId.ToString() }
            }
            Write-Output ("Cleanup verification attempt " + $verifyAttempt + " of 6, visible KeyIds: " + ($visibleKeyIds -join ", "))
            if ($visibleKeyIds -contains $preserveKeyId.ToString()) {
                $preserveMissingCount = 0
            } else {
                $preserveMissingCount++
                Write-Output ("WARNING: preserved current-generation credential not visible (sighting " + $preserveMissingCount + " of 2 before abort)")
                if ($preserveMissingCount -ge 2) {
                    throw "FATAL: the preserved current-generation credential disappeared during cleanup - aborting before rotation to avoid locking the automation out"
                }
            }
            $stillThere = $false
            foreach ($oldKeyIdString in $previousGenKeyIds) {
                if ($visibleKeyIds -contains $oldKeyIdString) { $stillThere = $true }
            }
            if (-not $stillThere) { break }
            Write-Output "Previous-generation credential(s) still visible, waiting..."
        }
        if ($stillThere) {
            Write-Output ("WARNING: previous-generation credential(s) still visible after cleanup verification (" + ($previousGenKeyIds -join ", ") + ") - the next rotation run retries the removal")
        }
    }
    if ($cleanupFailures -gt 0) {
        throw ($cleanupFailures.ToString() + " previous-generation credential(s) could not be removed, see errors above")
    }

    # Create RunAs certificate
    Write-Output ("Creating new certificate")
    $SelfSignedCertNoOfMonthsUntilExpired = 6
    $SelfSignedCertPlainPassword = "-" + [Guid]::NewGuid().ToString() + "]"
    $PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($AzureCertificateName + ".pfx")
    $CerPassword = ConvertTo-SecureString $SelfSignedCertPlainPassword -AsPlainText -Force
    Clear-Variable -Name "SelfSignedCertPlainPassword" -Force -ErrorAction SilentlyContinue
    $Cert = New-SelfSignedCertificate -DnsName $AzureCertificateName -CertStoreLocation Cert:\CurrentUser\My `
        -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
        -NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddMonths($SelfSignedCertNoOfMonthsUntilExpired) -HashAlgorithm SHA256
    Export-PfxCertificate -Cert ("Cert:\CurrentUser\My\" + $Cert.Thumbprint) -FilePath $PfxCertPathForRunAsAccount -Password $CerPassword -Force | Write-Verbose
    $CerKeyValue = [System.Convert]::ToBase64String($Cert.GetRawCertData())
    $CerThumbprint = [System.Convert]::ToBase64String($Cert.GetCertHash())
    $CerThumbprintString = $Cert.Thumbprint
    $CerStartDate = $Cert.NotBefore
    $CerEndDate = $Cert.NotAfter

    # Updating certificate in key vault 
    Write-Output "Updating certificate in key vault"
    $AzureKeyVaultCertificate = Import-AzKeyVaultCertificate -VaultName $AlyaCertificateKeyVaultName -Name $AlyaCertificateSecretName -FilePath $PfxCertPathForRunAsAccount -Password $CerPassword
    $AzureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $AlyaCertificateKeyVaultName -Name $AlyaCertificateSecretName

    # Update the certificate in the Automation account with the new one 
    Write-Output "Updating automation account certificate"
    $retries = 10
    do {
        try {
            $AutomationCertificate = Get-AzAutomationCertificate -ResourceGroupName $AlyaResourceGroupName -AutomationAccountName $AlyaAutomationAccountName -Name $AzureCertifcateAssetName -ErrorAction SilentlyContinue
            if (-Not $AutomationCertificate) {
                Write-Warning "  Automation Certificate not found. Creating the Automation Certificate $AzureCertifcateAssetName"
                New-AzAutomationCertificate -ResourceGroupName $AlyaResourceGroupName -AutomationAccountName $AlyaAutomationAccountName -Name $AzureCertifcateAssetName -Path $PfxCertPathForRunAsAccount -Password $CerPassword -Exportable:$true
            }
            else {
                if ($AutomationCertificate.Thumbprint -ne $CerThumbprintString -or
                    $AutomationCertificate.ExpiryTime -le $CerEndDate.AddHours(-2)) {
                    Write-Output "  Updating the Automation Certificate"
                    Set-AzAutomationCertificate -ResourceGroupName $AlyaResourceGroupName `
                        -AutomationAccountName $AlyaAutomationAccountName -Name $AzureCertifcateAssetName `
                        -Path $PfxCertPathForRunAsAccount -Password $CerPassword -Exportable:$true
                }
                else {
                    Write-Output ("Automation Certificate updated successfully or was already up to date.")
                    break
                }
            }
        }
        catch {
            Write-Output $_.Exception.Message
            Write-Output "Error updating certificate, retrying in 10 seconds..."
        }
        $retries--
        if ($retries -le 0) {
            throw "Failed to update Automation Certificate after multiple retries"
        }
        Start-Sleep -Seconds 10
    } while ($true)

    # Checking application credential
    Write-Output "Checking application credential"

    # Snapshot of the existing credentials BEFORE the new one is created.
    # Get-AzADAppCredential can (depending on Az version) return a nested array, which
    # leads to "Cannot convert System.Object[] to System.Guid" errors on KeyId. Therefore
    # everything is flattened into a plain list and every KeyId is parsed defensively.
    # Note: deliberately NOT using [Guid]::TryParse with [ref] anywhere - the ref binder
    # fails when the referenced variable is $null (runtime error on Windows PowerShell 5.1
    # AND pwsh 7, invisible to syntax checks). "-as [Guid]" converts safely instead.
    $rawBefore = @(Get-AzADAppCredential -ApplicationId $AzAdApplication.AppId)
    $before = @()
    foreach ($rawItem in $rawBefore) { $before += @($rawItem) }
    Write-Output ("Credentials visible before update: " + $before.Count)
    foreach ($oldCred in $before) {
        $parsedOldKeyId = "$($oldCred.KeyId)" -as [Guid]
        $oldKeyIdString = "<unparsable KeyId>"
        if ($null -ne $parsedOldKeyId) { $oldKeyIdString = $parsedOldKeyId.ToString() }
        $oldCkiString = ""
        try {
            if ($oldCred.CustomKeyIdentifier -is [byte[]]) { $oldCkiString = [System.Convert]::ToBase64String($oldCred.CustomKeyIdentifier) }
            elseif ($null -ne $oldCred.CustomKeyIdentifier) { $oldCkiString = "$($oldCred.CustomKeyIdentifier)" }
        } catch { $oldCkiString = "" }
        Write-Output ("  BEFORE: KeyId=" + $oldKeyIdString + " DisplayName=" + $oldCred.DisplayName + " Type=" + $oldCred.Type + " Start=" + $oldCred.StartDateTime + " End=" + $oldCred.EndDateTime + " Thumbprint=" + $oldCkiString)
    }

    $newKeyId = [Guid]::NewGuid()
    Write-Output ("Generated KeyId for the new credential: " + $newKeyId.ToString())
    Write-Output ("Thumbprint (base64) of the new certificate: " + $CerThumbprint)
    $creds = New-Object Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphKeyCredential
    $creds.DisplayName = "CN=$AzureCertificateName"
    $creds.CustomKeyIdentifier = $Cert.GetCertHash()
    $creds.Key = $Cert.GetRawCertData()
    $creds.KeyId = $newKeyId.ToString()
    $creds.Type = "AsymmetricX509Cert"
    $creds.Usage = "Verify"
    $creds.StartDateTime = $CerStartDate
    $creds.EndDateTime = $CerEndDate

    # IMPORTANT: the credential is created EXACTLY ONCE. Never re-create it inside a retry
    # loop: Graph replication can be delayed and blind retries produce duplicate
    # credentials. All retries below are READ-ONLY polling.
    $createdOutput = @()
    $createFailed = $false
    try {
        Write-Output "Calling New-AzADAppCredential (single attempt)..."
        $createdOutput = @(New-AzADAppCredential -ApplicationId $AzAdApplication.AppId -KeyCredentials $creds)
        Write-Output ("New-AzADAppCredential returned " + $createdOutput.Count + " object(s)")
        foreach ($createdItem in $createdOutput) {
            Write-Output ("  OUTPUT: " + ($createdItem | Out-String))
        }
    } catch {
        $createFailed = $true
        Write-Output ("ERROR: New-AzADAppCredential failed: " + $_.Exception.Message)
        Write-Output ("ERROR details: " + ($_ | Out-String))
        try { Write-Output ("ERROR exception as json: " + ($_.Exception | ConvertTo-Json -Depth 5)) } catch { Write-Output "ERROR: could not serialize the exception" }
        Write-Output "NOTE: the credential may still have been created server side, continuing with read-only verification"
    }

    # Determine the effective KeyId of the new credential, preferring the cmdlet output
    $effectiveKeyId = $null
    foreach ($createdItem in $createdOutput) {
        try {
            $parsedOutputKeyId = "$($createdItem.KeyId)" -as [Guid]
            if ($null -ne $parsedOutputKeyId) {
                $effectiveKeyId = $parsedOutputKeyId
                Write-Output ("Effective KeyId taken from New-AzADAppCredential output: " + $effectiveKeyId.ToString())
            } else {
                Write-Output ("WARNING: New-AzADAppCredential output contained no parsable KeyId: " + ($createdItem | Out-String))
            }
        } catch {
            Write-Output ("WARNING: could not read KeyId from New-AzADAppCredential output: " + $_.Exception.Message)
        }
        if ($null -ne $effectiveKeyId) { break }
    }

    # Read-only polling until the new credential becomes visible. It is matched by the
    # generated KeyId OR by the certificate thumbprint (CustomKeyIdentifier), since the
    # service may assign its own KeyId.
    $found = $false
    $after = @()
    $maxPollAttempts = 6
    $pollIntervalSeconds = 10
    for ($pollAttempt = 1; $pollAttempt -le $maxPollAttempts; $pollAttempt++) {
        Start-Sleep -Seconds $pollIntervalSeconds
        Write-Output ("Polling attempt " + $pollAttempt + " of " + $maxPollAttempts + " for the new credential...")
        try {
            $rawAfter = @(Get-AzADAppCredential -ApplicationId $AzAdApplication.AppId)
        } catch {
            Write-Output ("ERROR: Get-AzADAppCredential failed during polling: " + $_.Exception.Message)
            Write-Output ("ERROR details: " + ($_ | Out-String))
            continue
        }
        $after = @()
        foreach ($rawItem in $rawAfter) { $after += @($rawItem) }
        Write-Output ("  Credentials visible now: " + $after.Count)
        foreach ($actCert in $after) {
            $parsedKeyId = "$($actCert.KeyId)" -as [Guid]
            $keyIdString = "<unparsable KeyId>"
            if ($null -ne $parsedKeyId) { $keyIdString = $parsedKeyId.ToString() }
            $ckiString = ""
            try {
                if ($actCert.CustomKeyIdentifier -is [byte[]]) { $ckiString = [System.Convert]::ToBase64String($actCert.CustomKeyIdentifier) }
                elseif ($null -ne $actCert.CustomKeyIdentifier) { $ckiString = "$($actCert.CustomKeyIdentifier)" }
            } catch { $ckiString = "" }
            Write-Output ("  VISIBLE: KeyId=" + $keyIdString + " DisplayName=" + $actCert.DisplayName + " Type=" + $actCert.Type + " Start=" + $actCert.StartDateTime + " End=" + $actCert.EndDateTime + " Thumbprint=" + $ckiString)
            if ($null -eq $parsedKeyId) {
                Write-Output ("WARNING: credential entry with unparsable KeyId detected (this is the System.Object[] case). Raw object follows:")
                try { Write-Output ($actCert | ConvertTo-Json -Depth 5) } catch { Write-Output ($actCert | Out-String) }
                continue
            }
            if ($parsedKeyId -eq $newKeyId) {
                $effectiveKeyId = $parsedKeyId
                $found = $true
                Write-Output ("New credential found (matched by generated KeyId " + $newKeyId.ToString() + ")")
            } elseif ($ckiString -eq $CerThumbprint -and $actCert.DisplayName -eq "CN=$AzureCertificateName") {
                $effectiveKeyId = $parsedKeyId
                $found = $true
                Write-Output ("New credential found (matched by thumbprint), effective KeyId: " + $effectiveKeyId.ToString())
            }
        }
        if ($found) { break }
        Write-Output "New credential not visible yet, waiting before next attempt..."
    }

    if (-not $found) {
        if ($null -ne $effectiveKeyId) {
            Write-Output ("WARNING: new credential never became visible via Get-AzADAppCredential, but the output of New-AzADAppCredential provided KeyId " + $effectiveKeyId.ToString() + " - trusting the output")
        } elseif ($createFailed) {
            Write-Output "ERROR: credential creation failed and nothing new became visible"
            Write-Output ("Last visible credential KeyIds: " + (($after | ForEach-Object { "$($_.KeyId)" }) -join ", "))
            throw "New-AzADAppCredential failed and no new credential was found. No second creation attempt is made on purpose (duplicate avoidance). See log above."
        } else {
            Write-Output "ERROR: New-AzADAppCredential reported no error, but the new credential never became visible and no KeyId was returned"
            Write-Output ("Last visible credential KeyIds: " + (($after | ForEach-Object { "$($_.KeyId)" }) -join ", "))
            throw "Created credential was not found after polling. No second creation attempt is made on purpose (duplicate avoidance). See log above."
        }
    } else {
        Write-Output ("New credential verified, effective KeyId: " + $effectiveKeyId.ToString())
    }

    # Final state log. Safe here: this runbook authenticates via the system-assigned
    # removals happened at the START of this run against long-converged keys, and the
    # credential this session authenticates with was preserved - the Az session stays
    # fully functional until the very end.
    Write-Output "Final credential state:"
    try {
        $rawFinal = @(Get-AzADAppCredential -ApplicationId $AzAdApplication.AppId)
        $final = @()
        foreach ($rawItem in $rawFinal) { $final += @($rawItem) }
        $foundNew = $false
        foreach ($finCred in $final) {
            $finKeyId = "$($finCred.KeyId)" -as [Guid]
            $finKeyIdString = "<unparsable KeyId>"
            if ($null -ne $finKeyId) { $finKeyIdString = $finKeyId.ToString() }
            $finCki = ""
            try {
                if ($finCred.CustomKeyIdentifier -is [byte[]]) { $finCki = [System.Convert]::ToBase64String($finCred.CustomKeyIdentifier) }
                elseif ($null -ne $finCred.CustomKeyIdentifier) { $finCki = "$($finCred.CustomKeyIdentifier)" }
            } catch { $finCki = "" }
            Write-Output ("  FINAL: KeyId=" + $finKeyIdString + " DisplayName=" + $finCred.DisplayName + " Type=" + $finCred.Type + " Start=" + $finCred.StartDateTime + " End=" + $finCred.EndDateTime + " Thumbprint=" + $finCki)
            if ($null -ne $finKeyId -and $finKeyId -eq $effectiveKeyId) { $foundNew = $true }
        }
        if (-not $foundNew) {
            Write-Output ("WARNING: new credential " + $effectiveKeyId.ToString() + " is not visible in the final list (possible replication delay)")
        }
    } catch {
        Write-Output ("ERROR: final state log failed: " + $_.Exception.Message)
    }
    Write-Output "NOTE: the credential that was current before this run intentionally remains on the app - it is removed by the NEXT rotation run (race-free one-generation overlap by design)."

    Write-output "Done"
}
catch {
    Write-Error $_ -ErrorAction Continue
    try { Write-Error ($_ | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}

    # Login back
    Write-Output "Login back to Az using system-assigned managed identity"
    try { Disconnect-AzAccount }catch {}
    $AzureContext = (Connect-AzAccount -Identity).Context
    $AzureContext = Set-AzContext -Subscription $AlyaSubscriptionId -DefaultProfile $AzureContext

    # Getting MSGraph Token
    Write-Output "Getting MSGraph Token"
    # Defensive token handling: -AsSecureString is not available on older Az.Accounts
    # versions (parameter binding errors observed in the Automation environment), and
    # newer versions return a SecureString even without the switch. Handle both.
    $tokenPlain = ""
    $tokenType = "Bearer"
    try {
        $tokenObj = Get-AzAccessToken -ResourceUrl $AlyaGraphEndpoint -TenantId $AlyaTenantId
        if ($tokenObj.Token -is [System.Security.SecureString]) {
            $tokenPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenObj.Token))
        } else {
            $tokenPlain = "$($tokenObj.Token)"
        }
        if ($null -ne $tokenObj.Type -and "$($tokenObj.Type)" -ne "") { $tokenType = "$($tokenObj.Type)" }
    } catch {
        Write-Output ("ERROR: could not acquire Graph token for the error mail: " + $_.Exception.Message)
    }

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
        Message         = @{
            Subject      = $subject
            Body         = @{ ContentType = $contentType; Content = $content }
            ToRecipients = @( @{ EmailAddress = @{ Address = $AlyaToMail } } )
        }
        saveToSentItems = $false
    }
    $body = ConvertTo-Json $payload -Depth 99 -Compress
    $HeaderParams = @{
        'Accept'        = "application/json;odata=nometadata"
        'Content-Type'  = "application/json"
        'Authorization' = "$($tokenType) $($tokenPlain)"
    }
    Clear-Variable -Name "tokenPlain" -Force -ErrorAction Continue
    $Result = ""
    $StatusCode = ""
    do {
        try {
            $Uri = "$AlyaGraphEndpoint/beta/users/$($AlyaFromMail)/sendMail"
            Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "POST" -ContentType "application/json" -Body $body
        }
        catch {
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

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCREmNRpXseZJin
# heH2fI8DxEbI9FrlvdPE8z2fqdYy86CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIG9I5wFx
# /Eu4MEfMq+9kSoRiUByV8bil6ZJpli3IbBDRMA0GCSqGSIb3DQEBAQUABIICAKM5
# ud4pB49ZE9xF+YaUjzffavWq5Tjv4/RBhtoBXxbhhcb2M32uZzvYVM18JUkRc4r3
# dlzRs8EhSLree6ufLikiqwG5gcDZWveerg9FIgNgzk97CjiHQkhjXJ0wRzQiTZ5O
# 1V0aPLyk8W6EkOFNu/2SuVlSkdWMVFA7h9gi8rAWxcp0GcD574HEpuValEYm1v5A
# R6YzRPpSQZthK2lB4ZV6S56wp0l9jkMh3ZmLFjalYTdTseFOYWOXfmc/VKUwJu8W
# CgRs2bkYUZx1Lf38cBZMSbGg9p0UjzExTsCPzwkVzrSbRasrkZ6d9t2g41mJGTlT
# xKHX3dlEXYvfFN3hKIljvUeZdmvlKy81QgiQBciyT4KC6/Vv4LjP3cdxE1ejeLJ/
# 2kyakyp/pQoxR50RUp4IkXJtMWPR+eYyKdYCBNb9TA/LTfrOdrhddsQv9POTXnz8
# 0gNzi/fcPSYkkO7N2Qkf7wZziQh/BuXn90lsULwLnpn9dJhFqWsGAEmf5pthKTCo
# XJ2a9XoEswWTxmKHiEte+6B3YkdvjRMJtEHa3q3hv39Enb3Jn/yClnfb8pzx84pU
# /sAQG6TwMwyqAUWSRp/UZzuJPOD2FyhTnLsY6zMSFLbMzy8Y+ZQQu6Lj4z61hDQY
# Jl/tEPAW+6SdXsa4FoQiK3zrnFfxywV21IRDKfaKoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCDi4LqG8RP4P9jdTc12estv4Q6h3fe4TJieFm4Wt89BCQIUC+Co
# Jp3Y5la/+E49RLr/Mao9GkIYDzIwMjYwOTEyMDcyODA3WjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDAAdVGiESY76PegF7CPiJbC2NxQQvvljyXHIAe0bjohDU8UGjBTgr6d+pn5
# RFqBsiIwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAkLlVL6VXxcnTuqDSmmMi0Xl+9E2nNw8yHVGNgLCo+TX0
# f2sKg0GVMHmoOogTPPrrRwdD2TapLy4TjC6kIjgWyk8qyKKTWm086icaa0J4+6gE
# PQytM1DHo79NH561bDf+Gn1JV9Cr5hZI655yzmwbKQO9QA4Z4WDQA0LMsXKtzjIY
# 0GoUbapC9rR8yKRwZNtIvEoMY/fEvvkaEjZyDJQ91q4dTAlGYHBSCHDGLN+hjrLr
# uA1FERZ7zGTLJafF5kkjsmUuMiqLBiRCTxR7RLmnSIXbBhEn+Alc+mOtSPjpbuk+
# gzLxF7a/UAUpVfGP2iDoGCzc3D0jZ3by8tNQ4GIjGETsTwWiXZ3zcuPk+QIopxZI
# pQDZ8ngwUqgNMCA6G8LVmcFYu9jSE2hIEX16cei4Mi6sqWP9Bf1wACy8VlDwb3rV
# /zTSuTnd+xgc5I9X1y1js8haPDSHp3YsNndOwuPZVIO+zBhPrrQEbTMPB6lmxzpN
# jbdqZNyO4Qq9gww6Fduo
# SIG # End signature block
