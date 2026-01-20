#Requires -Version 4.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2019-2026

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
    20.12.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [switch]$GatterOnly,
    [string]$ReattachToReportsDir = $null,
	[switch]$ProceedAlways
)

<#
	
	==================================================
	Script to inplace upgrade a windows server to 2022
	==================================================
	
	This script works with the following directory structure on a share:
	\\server\$mediaShareRoot
		Media
			Windows Server 20xx $mediaLang
			Windows Server 2019 $mediaLang
			Windows Server 2022 $mediaLang
		Reports
			$compName
				$timeStr <- ReattachToReportsDir
		Scripts
			ThisScript

#>

# Members
Write-Host "Members" -ForegroundColor Cyan
$mypath = $MyInvocation.MyCommand.Path
$scriptsDir = $PSScriptRoot
Push-Location "$PSScriptRoot\.."
$mediaShareRoot = $pwd.ProviderPath
Pop-Location 
$compName = ($env:COMPUTERNAME).ToLower()
$compNameFqdn = ($env:COMPUTERNAME+"."+$env:USERDNSDOMAIN).ToLower()
$reportRootDir = [System.IO.Path]::Combine($mediaShareRoot, "Reports")
$serverDir = [System.IO.Path]::Combine($reportRootDir, $compName)
$timeStr = (Get-Date).ToString("yyyyMMddHHmmssfff")
$reportServerDir = [System.IO.Path]::Combine($reportRootDir, $compName)
$reportDir = [System.IO.Path]::Combine($reportServerDir, $timeStr)

if ($ReattachToReportsDir)
{
    if (-Not $ReattachToReportsDir.Contains("\"))
    {
        $reportDir = [System.IO.Path]::Combine($reportServerDir, $ReattachToReportsDir)
    }
    else
    {
    	$reportDir = $ReattachToReportsDir
    }
	$rd = Get-Item -Path $reportDir
    if ($rd.Parent.Name -ne $compName)
    {
        throw "Wrong reattachToReportsDir applied!"
    }
}

if (-Not (Test-Path $reportRootDir))
{
	New-Item -Path $reportRootDir -ItemType Directory -Force
}
if (-Not (Test-Path $reportServerDir))
{
	New-Item -Path $reportServerDir -ItemType Directory -Force
}
if (-Not (Test-Path $reportDir))
{
	New-Item -Path $reportDir -ItemType Directory -Force
}

Start-Transcript -IncludeInvocationHeader -Path "$reportDir\Transcript-$timeStr.txt" -Force
sl $reportDir

# Functions
function Select-Item()
{
    Param(
	    $list,
	    $message = "Please select an item",
	    [ValidateSet("Single","Multiple","None")]
	    $outputMode = "Single"
    )
	$sel = $list | Out-GridView -Title $message -OutputMode $outputMode
	return $sel
}
function SelectDcName()
{
	$list = Get-ADDomainController -Filter * | Select-Object Name, Domain, Forest, OperationMasterRoles
	$sel = Select-Item -list $list
	return $sel.Name
}

if (-Not $ReattachToReportsDir)
{
	# Gattering computer information
	Write-Host "Gattering computer information" -ForegroundColor Cyan
	Get-Partition | Out-File -FilePath "$reportDir\partitions.txt" -Encoding utf8
	Get-Disk | Out-File -FilePath "$reportDir\disks.txt" -Encoding utf8
	systeminfo.exe | Out-File -FilePath "$reportDir\systeminfo.txt" -Encoding utf8
	ipconfig /all | Out-File -FilePath "$reportDir\ipconfig.txt" -Encoding utf8
	dxdiag /t | Out-File -FilePath "$reportDir\dxdiag.txt" -Encoding utf8
	Get-WindowsFeature | Out-File -FilePath "$reportDir\windowsFeature.txt" -Encoding utf8
	Get-Service | Out-File -FilePath "$reportDir\services.txt" -Encoding utf8
	dir env: | Out-File -FilePath "$reportDir\env.txt" -Encoding utf8
	Get-Process -IncludeUserName | Select-Object UserName, ProcessName | Out-File -FilePath "$reportDir\processes.txt" -Encoding utf8
	Dism /Online /Cleanup-Image /ScanHealth | Out-File -FilePath "$reportDir\dismScanHealth.txt" -Encoding utf8
	Dism /Online /Cleanup-Image /CheckHealth | Out-File -FilePath "$reportDir\dismCheckHealth.txt" -Encoding utf8
	sfc.exe /scannow | Out-File -FilePath "$reportDir\sfcscan.txt" -Encoding utf8
	bcdedit | Out-File -FilePath "$reportDir\bcdedit.txt" -Encoding utf8

	$isDc = (Get-WindowsFeature -Name "AD-Domain-Services").Installed
	if ($isDc)
	{
		dcdiag /s:$compName | Out-File -FilePath "$reportDir\dcdiag.txt" -Encoding utf8
		dcdiag /s:$compName /test:dns | Out-File -FilePath "$reportDir\dcdiagDns.txt" -Encoding utf8
		repadmin /showrepl | Out-File -FilePath "$reportDir\repadminShowrepl.txt" -Encoding utf8
		repadmin /replsum | Out-File -FilePath "$reportDir\repadminReplsum.txt" -Encoding utf8
	}

	$isAdfs = (Get-WindowsFeature -Name "ADFS-Federation").Installed
	if ($isAdfs)
	{
		# Exporting ADFS configuration
		Write-Host "Exporting ADFS configuration" -ForegroundColor Cyan
		#TODO C:\Windows\ADFS\Export-FederationConfiguration.ps1
		#add-pssnapin "Microsoft.adfs.powershell"
		Get-AdfsFarmInformation | Out-File -FilePath "$reportDir\adfsFarmInformation.txt" -Encoding utf8
		Get-ADFSCertificate | Out-File -FilePath "$reportDir\adfsCertificates.txt" -Encoding utf8
		$certs = Get-ADFSCertificate
		$mypwd = ConvertTo-SecureString -String $compName -Force -AsPlainText
		foreach($cert in $certs)
		{
			Write-Host "Exporting Cert $($cert.Thumbprint)"
			Get-ChildItem -Path "cert:\*\$($cert.Thumbprint)" -Recurse | Export-PfxCertificate -FilePath "$reportDir\adfsCert$($cert.Thumbprint).pfx" -Password $mypwd
		}
		copy "$($env:SystemRoot)\ADFS\\Microsoft.IdentityServer.Servicehost.exe.config" "$reportDir\adfs-Microsoft.IdentityServer.Servicehost.exe.config"
		Get-ADFSProperties | Out-File ".\adfsProperties.txt"
		setspn -L $compName | Out-File -FilePath "$reportDir\adfsSpns.txt" -Encoding utf8
		$filter = 'Name=' + "'adfssrv'" + ''
		$service = Get-CimInstance -namespace "root\cimv2" -class Win32_Service -Filter $filter
		$service | Format-List -Property * | Out-File -FilePath "$reportDir\adfsService.txt" -Encoding utf8
		Get-ADFSEndpoint | Out-File -FilePath "$reportDir\adfsEndpoints.txt" -Encoding utf8
		Get-ADFSClaimDescription | Out-File -FilePath "$reportDir\adfsClaimtypes.txt" -Encoding utf8
		Get-ADFSClaimsProviderTrust | Out-File -FilePath "$reportDir\adfsCptrusts.txt" -Encoding utf8
		Get-ADFSRelyingPartyTrust | Out-File -FilePath "$reportDir\adfsRptrusts.txt" -Encoding utf8
		Get-ADFSAttributeStore | Out-File -FilePath "$reportDir\adfsAtrstores.txt" -Encoding utf8
	}

	# Storing last upgrade logs
	if (Test-Path "C:\$WINDOWS.~BT")
	{
		robocopy /mir "C:\$WINDOWS.~BT" "$reportDir\WINDOWSBT"
	}

	# Health check dxdiag
	Write-Host "Health check dxdiag" -ForegroundColor Cyan
	#TODO check unsigned drivers (what to do?)
		Write-Host "  TODO"

	# Health check sfc
	Write-Host "Health check sfc" -ForegroundColor Cyan
	$check = (Get-Content -Path "$reportDir\sfcscan.txt" -Encoding $AlyaUtf8Encoding -Raw).Replace("`0", "")
	if (-Not ($check -like "*Der Windows-Ressourcenschutz hat keine Integrit?tsverletzungen gefunden.*" -or $check -like "*Windows Resource Protection did not find any integrity violations.*"))
	{
		Write-Host "sfc.exe has reported an error. Please see $reportDir\sfcscan.txt" -ForegroundColor Red
		Write-Host "Please mount installation media and run:" -ForegroundColor Red
		Write-Host "  Dism /Online /Cleanup-Image /RestoreHealth /Source:D:\sources\install.wim /LimitAccess" -ForegroundColor Red
		Write-Host "And restart the script" -ForegroundColor Red
		if (-Not $ProceedAlways) {Stop-Transcript; exit 1}
	}
	else
	{
		Write-Host "  Passed"
	}

	# Health check Dism ScanHealth
	Write-Host "Health check Dism ScanHealth" -ForegroundColor Cyan
	$check = Get-Content -Path "$reportDir\dismScanHealth.txt" -Encoding $AlyaUtf8Encoding -Raw
	if (-Not ($check -like "*Es wurde keine Komponentenspeicherbesch?digung erkannt.*" -or $check -like "*No component store corruption detected.*")) 
	{
		Write-Host "Dism ScanHealth has reported an error. Please see $reportDir\dismScanHealth.txt" -ForegroundColor Red
		Write-Host "Please run:" -ForegroundColor Red
		Write-Host "  Dism /Online /Cleanup-Image /CheckHealth" -ForegroundColor Red
		Write-Host "  Dism /Online /Cleanup-Image /RestoreHealth /Source:D:\sources\install.wim /LimitAccess" -ForegroundColor Red
		Write-Host "And restart the script" -ForegroundColor Red
		if (-Not $ProceedAlways) {Stop-Transcript; exit 2}
	}
	else
	{
		Write-Host "  Passed"
	}

	# Health check Dism CheckHealth
	Write-Host "Health check Dism CheckHealth" -ForegroundColor Cyan
	$check = Get-Content -Path "$reportDir\dismCheckHealth.txt" -Encoding $AlyaUtf8Encoding -Raw
	if (-Not ($check -like "*Es wurde keine Komponentenspeicherbesch?digung erkannt.*" -or $check -like "*No component store corruption detected.*"))
	{
		Write-Host "Dism CheckHealth has reported an error. Please see $reportDir\dismCheckHealth.txt" -ForegroundColor Red
		Write-Host "Please run:" -ForegroundColor Red
		Write-Host "  Dism /Online /Cleanup-Image /RestoreHealth /Source:D:\sources\install.wim /LimitAccess" -ForegroundColor Red
		Write-Host "And restart the script" -ForegroundColor Red
		if (-Not $ProceedAlways) {Stop-Transcript; exit 3}
	}
	else
	{
		Write-Host "  Passed"
	}
}

# Reading systeminfo
Write-Host "Reading systeminfo" -ForegroundColor Cyan
$sysInfo = Get-Content -Path "$reportDir\systeminfo.txt" -Encoding $AlyaUtf8Encoding
$OsName = ($sysInfo | Where-Object { $_ -like "*Betriebssystemname:*" -or $_ -like "*OS Name:*" }).Split(":")[1].Trim()
$OsVersion = ($sysInfo | Where-Object { $_ -like "*Betriebssystemversion:*" -or $_ -like "*OS Version:*" }).Split(":")[1].Trim()
$OsConfiguration = ($sysInfo | Where-Object { $_ -like "*Betriebssystemkonfiguration:*" -or $_ -like "*OS Configuration:*" }).Split(":")[1].Trim()
$OsType = ($sysInfo | Where-Object { $_ -like "*Systemtyp:*" -or $_ -like "*System Type:*" }).Split(":")[1].Trim()
$OsLocale = ($sysInfo | Where-Object { $_ -like "*Systemgebietsschema:*" -or $_ -like "*System Locale:*" }).Split(":")[1].Split(";")[0].Trim()
$OsDomain = ($sysInfo | Where-Object { $_ -like "*Dom?ne:*" -or $_ -like "*Domain:*" }).Split(":")[1].Trim()
$OsPartition = Get-Partition | Where-Object { $_.DriveLetter -eq $env:SystemDrive.Replace(":", "") }

$OsCode = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language -Name InstallLanguage).InstallLanguage
switch($OsCode)
{
	"0409" { $OsLocale = "en-US" }
	"0809" { $OsLocale = "en-GB" }
	"2055" { $OsLocale = "de-CH" }
	"0C07" { $OsLocale = "de-AT" }
	"0407" { $OsLocale = "de-DE" }
	default {
	throw "Don't know language $OsCode"
	}
}
$OsLocale | Out-File -FilePath "$reportDir\osLocale.txt" -Encoding utf8

$BootMode = bcdedit | Select-String "path.*efi"
if ($null -eq $BootMode) {
            $OsBootMode = "Legacy"
}else {
            $OsBootMode = "UEFI"
}
$OsBootMode | Out-File -FilePath "$reportDir\osBootMode.txt" -Encoding utf8

# Defining upgrade path
Write-Host "Defining upgrade path" -ForegroundColor Cyan
$mediaEdition = $null
$mediaShare = [System.IO.Path]::Combine($mediaShareRoot, "Media")
$mediaLang = $OsLocale.Split("-")[0].ToUpper()
$atpOffboarding = $null
switch ($OsName)
{
	"Microsoft Windows Server 2008 R2 Standard" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2012 R2 $mediaLang")
		$mediaEdition = "Windows Server 2012 R2 SERVERSTANDARD"
	}
	"Microsoft Windows Server 2012 Standard" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2012 R2 $mediaLang")
		$mediaEdition = "Windows Server 2012 R2 SERVERSTANDARD"
	}
	"Microsoft Windows Server 2012 R2 Standard" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2019 $mediaLang")
		$mediaEdition = "Windows Server 2019 SERVERSTANDARD"
        $atpOffboarding = "Server-2012-2016"
	}
	"Microsoft Windows Server 2016 Standard" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2022 $mediaLang")
		$mediaEdition = "Windows Server 2022 SERVERSTANDARD"
        $atpOffboarding = "Server-2012-2016"
	}
	"Microsoft Windows Server 2019 Standard" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2022 $mediaLang")
		$mediaEdition = "Windows Server 2022 SERVERSTANDARD"
        $atpOffboarding = "Server-2019-2022"
	}
	"Microsoft Windows Server 2022 Standard" {
        $atpOffboarding = "Server-2019-2022"
	}
	"Microsoft Windows Server 2008 R2 Datacenter" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2012 R2 $mediaLang")
		$mediaEdition = "Windows Server 2012 R2 SERVERDATACENTER"
	}
	"Microsoft Windows Server 2012 Datacenter" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2012 R2 $mediaLang")
		$mediaEdition = "Windows Server 2012 R2 SERVERDATACENTER"
	}
	"Microsoft Windows Server 2012 R2 Datacenter" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2019 $mediaLang")
		$mediaEdition = "Windows Server 2019 SERVERDATACENTER"
        $atpOffboarding = "Server-2012-2016"
	}
	"Microsoft Windows Server 2016 Datacenter" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2022 $mediaLang")
		$mediaEdition = "Windows Server 2022 SERVERDATACENTER"
        $atpOffboarding = "Server-2012-2016"
	}
	"Microsoft Windows Server 2019 Datacenter" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2022 $mediaLang")
		$mediaEdition = "Windows Server 2022 SERVERDATACENTER"
        $atpOffboarding = "Server-2019-2022"
	}
	"Microsoft Windows Server 2022 Datacenter" {
        $atpOffboarding = "Server-2019-2022"
	}
	default { throw "Unknown OS name!" }
}
$mediaWimFile = [System.IO.Path]::Combine($mediaShare, "sources")
$mediaWimFile = [System.IO.Path]::Combine($mediaWimFile, "install.wim")
$SetupLogFile = [System.IO.Path]::Combine($reportDir, "setupLog.txt")
$mediaShare | Out-File -FilePath "$reportDir\mediaShare.txt" -Encoding utf8
$mediaEdition | Out-File -FilePath "$reportDir\mediaEdition.txt" -Encoding utf8

if ($GatterOnly)
{
	Write-Host "GatterOnly switch applied. Stopping now the script."
	Write-Host "Please relaunch with:"
	Write-Host "$mypath -reattachToReportsDir $reportDir"
	Stop-Transcript; exit
}

if ($mediaEdition -ne $null)
{
	# Checking vim file
	if (-Not (Test-Path $mediaWimFile))
	{
		Write-Warning "Please relaunch this script with:"
		Write-Warning "$mypath -reattachToReportsDir $reportDir"
		throw "Can't not find the wim file $mediaWimFile"
	}

	# Checking UEFI boot
	if ($mediaEdition -like "*2022*" -and $OsBootMode -eq "Legacy")
	{ 
		Write-Warning "Please relaunch this script with:"
		Write-Warning "$mypath -reattachToReportsDir $reportDir"
		throw "You need to enable UEFI boot mode!"
	}
	
	$hasDefenderEndpoint = Get-Service -Name SENSE -ErrorAction SilentlyContinue
    if ($hasDefenderEndpoint)
	{
		Write-Host "Upgrade with Defender for Endpoint is not supported. Needs to be uninstalled!" -ForegroundColor Cyan
        
        $alreadyOffboarded = $false
        if ($hasDefenderEndpoint.Status -eq "Stopped")
        {
            Write-Warning "The SENSE service is in stopped state. Have you already offboarded?"
            $title    = "Confirm"
            $question = "Defender for Endpoint already offboarded?"
            $choices  = "&Yes", "&No"
            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
            if ($decision -eq 0) {
                $alreadyOffboarded = $true
            }
        }
        if (-Not $alreadyOffboarded)
        {
		    $hasDefenderEndpoint | Out-File -FilePath "$reportDir\hadDefenderEndpoint.txt" -Encoding utf8

            if (-Not $atpOffboarding)
            {
                Write-Warning "Your operating system is not supported by this script to offboard Defender for Endpoint. Please uninstall it manually."
		        Write-Warning "Please uninstall Defender for Endpoint and relaunch this script with:"
            }
            else
            {
                $atpScript = $null
                $scripts = Get-Item -Path "$scriptsDir\WindowsDefenderATPOffboardingScript_$($atpOffboarding)_valid_until_*.cmd"
                foreach($script in $scripts)
                {
                    $dateStr = $script.Name.Replace("WindowsDefenderATPOffboardingScript_$($atpOffboarding)_valid_until_", "").Replace(".cmd", "")
                    $scriptValidity = [DateTime]::ParseExact($dateStr, "yyyy-MM-dd", [CultureInfo]::InvariantCulture)
                    if ($scriptValidity -gt (Get-Date).AddDays(-25))
                    {
                        $atpScript = $script
                        break
                    }
                }
		        if (-Not $atpScript)
		        {
			        Write-Warning "You need to provide the Offboarding script for Defender for Endpoint!"
			        Write-Warning "Please go to https://security.microsoft.com/preferences2/offboarding and download the script."
			        Write-Warning "Save it to:"
			        Write-Warning "$scriptsDir\WindowsDefenderATPLocalOffboardingScript_$($atpOffboarding)_valid_until_yyyy-MM-dd.cmd"
			        Write-Warning ""
			        Write-Warning "Please relaunch this script with:"
			        Write-Warning "$mypath -reattachToReportsDir $reportDir"
			        Stop-Transcript; exit
		        }
                Write-Host "Please start an elevated command prompt and run following command:" -ForegroundColor Green
		        Write-Host "$($atpScript.FullName)" -ForegroundColor Green
                pause
    		    Write-Warning "Please reboot and relaunch this script with:"
            }
		    Write-Warning "$mypath -reattachToReportsDir $reportDir"
		    Stop-Transcript; exit
        }
	}
    
	if ($isDc)
	{
		# Checking domain controller roles
		Write-Host "Checking domain controller roles" -ForegroundColor Cyan
		Get-ADDomainController -Filter * | Select-Object Name, Domain, Forest, OperationMasterRoles | Format-List | Out-File -FilePath "$reportDir\domainControllers.txt" -Encoding utf8
		Get-ADDomainController -Filter * | Select-Object Name, Domain, Forest, OperationMasterRoles
		$dom = Get-ADDomain
		$for = Get-ADForest
		if ($dom.InfrastructureMaster.ToLower() -eq $compNameFqdn -or $dom.InfrastructureMaster.ToLower() -eq $compName)
		{
			if (-Not $otherDcFqdn) { $otherDcFqdn = SelectDcName }
			Write-Warning "This DC is InfrastructureMaster. Moving it to last DC $otherDcFqdn"
			Move-ADDirectoryServerOperationMasterRole -OperationMasterRole InfrastructureMaster -Identity $otherDcFqdn -Force -Confirm:$false
			"InfrastructureMaster" | Out-File -FilePath "$reportDir\domainControllerRolesMoved.txt" -Append -Force
		}
		if ($dom.RIDMaster.ToLower() -eq $compNameFqdn -or $dom.RIDMaster.ToLower() -eq $compName)
		{
			if (-Not $otherDcFqdn) { $otherDcFqdn = SelectDcName }
			Write-Warning "This DC is RIDMaster. Moving it to last DC $otherDcFqdn"
			Move-ADDirectoryServerOperationMasterRole -OperationMasterRole RIDMaster -Identity $otherDcFqdn -Force -Confirm:$false
			"RIDMaster" | Out-File -FilePath "$reportDir\domainControllerRolesMoved.txt" -Append -Force
		}
		if ($dom.PDCEmulator.ToLower() -eq $compNameFqdn -or $dom.PDCEmulator.ToLower() -eq $compName)
		{
			if (-Not $otherDcFqdn) { $otherDcFqdn = SelectDcName }
			Write-Warning "This DC is PDCEmulator. Moving it to last DC $otherDcFqdn"
			Move-ADDirectoryServerOperationMasterRole -OperationMasterRole PDCEmulator -Identity $otherDcFqdn -Force -Confirm:$false
			"PDCEmulator" | Out-File -FilePath "$reportDir\domainControllerRolesMoved.txt" -Append -Force
		}
		if ($for.SchemaMaster.ToLower() -eq $compNameFqdn -or $for.SchemaMaster.ToLower() -eq $compName)
		{
			if (-Not $otherDcFqdn) { $otherDcFqdn = SelectDcName }
			Write-Warning "This DC is SchemaMaster. Moving it to last DC $otherDcFqdn"
			Move-ADDirectoryServerOperationMasterRole -OperationMasterRole SchemaMaster -Identity $otherDcFqdn -Force -Confirm:$false
			"SchemaMaster" | Out-File -FilePath "$reportDir\domainControllerRolesMoved.txt" -Append -Force
		}
		if ($for.DomainNamingMaster.ToLower() -eq $compNameFqdn -or $for.DomainNamingMaster.ToLower() -eq $compName)
		{
			if (-Not $otherDcFqdn) { $otherDcFqdn = SelectDcName }
			Write-Warning "This DC is DomainNamingMaster. Moving it to last DC $otherDcFqdn"
			Move-ADDirectoryServerOperationMasterRole -OperationMasterRole DomainNamingMaster -Identity $otherDcFqdn -Force -Confirm:$false
			"DomainNamingMaster" | Out-File -FilePath "$reportDir\domainControllerRolesMoved.txt" -Append -Force
		}    
	}

	# Checking domain controller schema
	if ($isDc)
	{
		$requiredSchemaVersion = 66
		if ($mediaEdition -like "*2016*") { $requiredSchemaVersion = 88 }
		if ($mediaEdition -like "*2019*") { $requiredSchemaVersion = 88 }
		if ($mediaEdition -like "*2022*") { $requiredSchemaVersion = 88 }
		$schemaVersion = $null
		$schemDn = "CN=Schema,CN=Configuration,DC=rbzh,DC=ch"
		$adObj = Get-AdObject -Identity $schemDn -Properties *
		$schemaVersion = $adObj.objectVersion
		if ($schemaVersion -lt $requiredSchemaVersion)
		{
			#repadmin /syncall /AdeP
			cmd /c "$mediaShare\support\adprep\adprep.exe" /forestprep
			cmd /c "$mediaShare\support\adprep\adprep.exe" /domainprep
		}
	}

    # Needs update
	<#
    # Creating autounattend.xml
    Write-Host "Creating autounattend.xml" -ForegroundColor Cyan
    $AutounattendFile = [System.IO.Path]::Combine($reportDir, "autounattend.xml")
    $Autounattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm=http://schemas.microsoft.com/WMIConfig/2002/State; xmlns:xsi=http://www.w3.org/2001/XMLSchema-instance>
            <ComplianceCheck>
                <DisplayReport>OnError</DisplayReport>
            </ComplianceCheck>
            <UpgradeData>
                <Upgrade>true</Upgrade>
                <WillShowUI>OnError</WillShowUI>
            </UpgradeData>
            <UserData>
                <AcceptEula>true</AcceptEula>
            </UserData>
            <ImageInstall>
                <OSImage>
                    <InstallFrom>
                        <MetaData wcm:action="add">
                            <Key>/IMAGE/NAME</Key>
                            <Value>$($mediaEdition)</Value>
                        </MetaData>
                        <Path>$($mediaWimFile)</Path>
                    </InstallFrom>
                    <InstallTo>
                        <DiskID>$($OsPartition.DiskNumber)</DiskID>
                        <PartitionID>$($OsPartition.PartitionNumber)</PartitionID>
                    </InstallTo>
                </OSImage>
            </ImageInstall>
            <LogPath>$($SetupLogFile)</LogPath>
        </component>
    </settings>
</unattend>
"@
    $Autounattend | Set-Content -Path $AutounattendFile -Encoding UTF8 -Force
	#>
	
	# Stopping services
	$isSccm = Get-Service -Name "SMS_EXECUTIVE" -ErrorAction SilentlyContinue
	if ($isSccm)
	{
		Get-Service | Where-Object {$_.DisplayName -like "SMS*"} | Stop-Service -Force
        Start-Sleep -Seconds 20
		Get-Service | Where-Object {$_.DisplayName -like "SMS*"} | Stop-Service -Force
	}
	
	$isMsSql = Get-Service -Name "SQLBrowser" -ErrorAction SilentlyContinue
	if ($isSccm)
	{
		Get-Service | Where-Object {$_.DisplayName -like "SQL*"} | Stop-Service -Force
        Start-Sleep -Seconds 20
		Get-Service | Where-Object {$_.DisplayName -like "SQL*"} | Stop-Service -Force
	}
	
	# Launching update
	Write-Host "Launching update" -ForegroundColor Cyan
	$setupFile = [System.IO.Path]::Combine($mediaShare, "setup.exe")
	if (-Not (Test-Path $mediaWimFile))
	{
		Write-Warning "Please relaunch this script with:"
		Write-Warning "$mypath -reattachToReportsDir $reportDir"
		throw "Can't not find the setup file $setupFile"
	}
	
	Write-Host "OsName: $($OsName)"
	Write-Host "OsVersion: $($OsVersion)"
	Write-Host "OsConfiguration: $($OsConfiguration)"
	Write-Host "OsType: $($OsType)"
	Write-Host "OsLocale: $($OsLocale)"
	Write-Host "OsDomain: $($OsDomain)"
	
	Push-Location $mediaShare
	& "$setupFile"
	#& "$setupFile" /unattend:$AutounattendFile
	Pop-Location 

	<#
    # Done
    Write-Host "Done" -ForegroundColor Cyan
    Write-Warning "Please restart server and relaunch this script"
    pause
    #Restart-Computer -Force
	#>
}
else
{
    # Update to 2022 done

    # Reading first run data
	Write-Host "Reading first run data" -ForegroundColor Cyan
	$childs = Get-ChildItem -Path $reportServerDir
	$firstRun = Get-Date
	$firstReportDir = $null
	try
	{
		foreach ($child in $childs)
		{
			if ([DateTime]::ParseExact($child.Name, "yyyyMMddHHmmssfff", [CultureInfo]::InvariantCulture) -lt $firstRun)
			{
				$firstRun = [DateTime]::ParseExact($child.Name, "yyyyMMddHHmmssfff", [CultureInfo]::InvariantCulture)
			}
		}
		$firstReportDir = [System.IO.Path]::Combine($reportServerDir, $firstRun.ToString("yyyyMMddHHmmssfff"))
	}
	catch
	{
		foreach ($child in $childs)
		{
			if ([DateTime]::ParseExact($child.Name, "yyyyMMddhhmmssfff", [CultureInfo]::InvariantCulture) -lt $firstRun)
			{
				$firstRun = [DateTime]::ParseExact($child.Name, "yyyyMMddhhmmssfff", [CultureInfo]::InvariantCulture)
			}
		}
		$firstReportDir = [System.IO.Path]::Combine($reportServerDir, $firstRun.ToString("yyyyMMddhhmmssfff"))
	}
	if ($firstReportDir -eq $null)
	{
		throw "Not able to find first run directory!"
	}
	$firstServices = Get-Content -Path "$firstReportDir\services.txt" -Encoding $AlyaUtf8Encoding
	$firstProcesses = Get-Content -Path "$firstReportDir\processes.txt" -Encoding $AlyaUtf8Encoding
	$actualServices = Get-Content -Path "$reportDir\services.txt" -Encoding $AlyaUtf8Encoding
	$actualProcesses = Get-Content -Path "$reportDir\processes.txt" -Encoding $AlyaUtf8Encoding

	if (Test-Path "$firstReportDir\hadDefenderEndpoint.txt")
	{
		Write-Host "Defender for Endpoint was previously installed. Reinstalling!" -ForegroundColor Cyan
		if (-Not (Test-Path "$scriptsDir\WindowsDefenderATPLocalOnboardingScript.cmd"))
		{
			Write-Warning "You need to provide the Onboarding script for Defender for Endpoint!"
			Write-Warning "Please go to https://security.microsoft.com/preferences2/onboarding and download the scripts."
			Write-Warning "Save it to:"
			Write-Warning "$scriptsDir\WindowsDefenderATPLocalOnboardingScript.cmd"
			Write-Warning ""
			Write-Warning "Please relaunch this script with:"
			Write-Warning "$mypath -reattachToReportsDir $reportDir"
			Stop-Transcript; exit
		}
        Write-Host "Please start an elevated command prompt and run following command:" -ForegroundColor Green
		Write-Host "$scriptsDir\WindowsDefenderATPLocalOnboardingScript.cmd" -ForegroundColor Green
        pause
	}

	if ($isDc)
	{
		#Move dc roles back
		Write-Host "Checking domain controller roles" -ForegroundColor Cyan
		$movedRoles = Get-Content -Path "$firstReportDir\domainControllerRolesMoved.txt" -Encoding $AlyaUtf8Encoding -ErrorAction SilentlyContinue
		foreach($movedRole in $movedRoles)
		{
			switch($movedRole) #TODO check if a move from remote works
			{
				"InfrastructureMaster" {
					Move-ADDirectoryServerOperationMasterRole -OperationMasterRole InfrastructureMaster -Identity $compName -Force -Confirm:$false
				}
				"RIDMaster" {
					Move-ADDirectoryServerOperationMasterRole -OperationMasterRole RIDMaster -Identity $compName -Force -Confirm:$false
				}
				"PDCEmulator" {
					Move-ADDirectoryServerOperationMasterRole -OperationMasterRole PDCEmulator -Identity $compName -Force -Confirm:$false
				}
				"SchemaMaster" {
					Move-ADDirectoryServerOperationMasterRole -OperationMasterRole SchemaMaster -Identity $compName -Force -Confirm:$false
				}
				"DomainNamingMaster" {
					Move-ADDirectoryServerOperationMasterRole -OperationMasterRole DomainNamingMaster -Identity $compName -Force -Confirm:$false
				}
			}
		}
		Get-ADDomainController -Filter * | Select-Object Name, Domain, Forest, OperationMasterRoles
	}

	# Checking services
	Write-Host "Checking services" -ForegroundColor Cyan
	foreach($firstService in $firstServices)
	{
		$firstParts = $firstService.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
		$fnd = $false
		$ste = $true
		foreach($actualService in $actualServices)
		{
			$actualParts = $actualService.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
			if ($actualParts[1] -eq $firstParts[1])
			{
				$fnd = $true
				if ($actualParts[0] -ne $firstParts[0]) { $ste = $false }
				break
			}
		}
		if (-Not $fnd)
		{
			$ignore = ""
			if ($firstParts[1] -eq "AeLookupSvc") {$ignore = " CAN BE IGNROED!"}
			Write-Warning "Service $($firstParts[1]) not found after migration$ignore"
		}
		else
		{
			if (-Not $ste)
			{
				$serv = Get-Service -Name $firstParts[1]
				if ($serv.StartType -eq "Automatic")
				{
					$ignore = ""
					if ($firstParts[1] -eq "blabla") {$ignore = " CAN BE IGNROED!"}
					Write-Warning "Service $($firstParts[1]) does not have correct run state after migration$ignore"
				}
			}
		}
		if ($firstParts[1] -eq "COMSysApp") { break }
	}

    # Checking processes
	Write-Host "Checking processes" -ForegroundColor Cyan
	$firstProcs = @()
	foreach($firstProcesse in $firstProcesses)
	{
		$tmp = $firstProcesse.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
		if ($tmp.Count -gt 0)
		{
			$firstProcs += $tmp[$tmp.Count - 1]
		}
	}
	$firstProcs = $firstProcs | Select-Object -Unique
	$actualProcs = @()
	foreach($actualProcesse in $actualProcesses)
	{
		$tmp = $actualProcesse.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
		if ($tmp.Count -gt 0)
		{
			$actualProcs += $tmp[$tmp.Count - 1]
		}
	}
	$actualProcs = $actualProcs | Select-Object -Unique
	foreach($firstProc in $firstProcs)
	{
		if ($actualProcs -notcontains $firstProc)
		{
			Write-Warning "Process $($firstProc) not found after migration"
		}
	}
	
	# DONE
	Write-Host "Update to 2022 DONE!" -ForegroundColor Green
	"" | Set-Content -Path "$reportServerDir\Done.txt"
}

Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDqhTIEZebXztXP
# Yvqy2+Q5zBepGEZF/5HI34/bXurMXaCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKBIWHWY/nxlAOQc
# ZEeWC6iEG/sZAcNuiRJXMz1sORm9MA0GCSqGSIb3DQEBAQUABIICAH0n8gS+9q9k
# uqBx4GeK5dnhVSFZ7Vpecju/H0d8HL0mGNCg6zO8sVUyEKW4NbJcLR454/1/zvwf
# qqjZvCj0cDjwzjYwle+3X4lQT6S3+Ky7syuIU4SAY/HNAIUdrVfSvcZRnPYOi56H
# mojC5QeqT/wQHAsE2S7N8YI66zwa4phV+aM4CIrISKxsA937s+7ctJt9lwthbQPY
# aSRIHipcJurk5MWEKI1A8aNOgHKo7RMpvSg3JdbqtaVYYnDZMNx156F0pp+v2MVT
# mDBEfQnI9oP0iTEGnwx11Ulqxns9OQ/74aCeDGoBXUWxxDpq7zp73WWcnuCG9ZQY
# SOJbDYFEZ8TfRS/Bu/pGz2L5h2FxFt/weE9ujy6kC8gASq6vYEoN4dY17gJZjIaH
# sxZnd/Uq9M012TNwP0HHH17W2rEbS0ZSSfXPUtePShux+oRB4N8f0p5kAIfPcd0w
# fH3PyIeHzwcPMZx3RQO7UuB+7AZk52/UQyhP62bFS9CD7HhfZRdIXlhnNRe3upe/
# tWi7L7eZhDHwI7377scsP/sPmwwmfOXyugYDx1DzLzH27UOUwV9/M4TuFJX/5hAP
# W8TB8wmXifjf0S2UAAUGOfkFIIP6phIajSLbtz/HB/vQuhWTREb2yQncuTPB2a5w
# mqjIbM7qa5/sxyiolN5cUeDrU/sLnsbloYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCD4j3Sxuqhy/fDd5W9swL/L5S/t4kj0RtMOHnxJePO51gIUb0Secq+L0d+A
# Q4OPEGJnK7S5FuMYDzIwMjYwMTIwMTAwMjAyWjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
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
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# IN4Xo4/Xp2Y9x9khirJ7MXCktUK5yjBrLyahPGbYWUIXMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAASTVX0KLXccf
# u+93kYhrfElK09bGkB/fUTqDRE9K0Q6ZeINrk1JHeWpSPcdfVyJJXQB1iS6DWtAh
# XV9KLoSCeRWbuFrr+VCHDA/3N9i4K7d9rD8W8OenzfaepdKmm+v4ks++I+iU6n5W
# XmV4yERBuTT2K12Rb1qqmBZDMmvs1OL6PQoSkuwcTYR8tHyuk6eChpQVPP9Xj1eh
# ta1kyJXVJJTv8rUZS+XpoE6RYAwhS8QONAqCVdzr8pDn76fcTkCIW8J3hTrmY0D9
# UvgnbUbsKwe+OM0sNBXljYPF3+LYnN8Guy33sRDyD01iGQTX3WHdyhwW3vd2atVY
# p8TpKH/qV1Qv37WkJAMeYzEHMIe715qOP5nerW24PV7AA6ZBpYhgLXWS6Uoav3xA
# 4dH7ZCVADFor2enAzFEXh7zK4ddBQRZB5GoCHY0s6+y8oFETXEwOdskTRk/GaRNO
# Y8KDfFRTwEKB6/cQsu6Iqj//UkHTucpI+Gi1j/1m3FJn4p+jF5RD
# SIG # End signature block
