#Requires -Version 2.0

# Starting Get-Data
Write-Host "Starting Get-Data"
$root = $PSScriptRoot

# Starting Transscript
Write-Host "Starting Transscript"
$TimeString = (Get-Date).ToString("yyyyMMddHHmmssfff")
if (-not (Test-Path "$root\logs"))
{
    New-Item -Path "$root\logs" -ItemType Directory -Force | Out-Null
}
Start-Transcript -Path "$root\logs\Get-Data-$($TimeString).log" | Out-Null
(Get-Date).ToString("yyyyMMddHHmmssfff")

# Checking module
Write-Host "Checking module"
$mod = Get-Module -Name "ImportExcel" -ListAvailable
if (-Not $mod) {
    Write-Warning "Module ImportExcel not found. Installing in scope CurrentUser"
    Install-Module "ImportExcel" -Scope CurrentUser -AllowClobber
}
Import-Module "ImportExcel" -ErrorAction SilentlyContinue

# Members
if (-Not $Credentials) {
    $Credentials = Get-Credential -Message "Login for SharePoint On-Premises"
}

# Configurations
. "$root\..\SharedSNAPIN.ps1"
if (-not (Test-Path "$root\data"))
{
    New-Item -Path "$root\data" -ItemType Directory -Force | Out-Null
}

# Getting mappings
Write-Host "Getting site mapping"
if (-not (Test-Path "$root\..\2Migrate\Mapping\SiteMapping.xlsx")) {
    Write-Error "Missing SiteMapping.xlsx file in $root\..\2Migrate\Mapping. Please create it first."
    Stop-Transcript
    exit
}
$SiteMappings = Import-Excel "$root\..\2Migrate\Mapping\SiteMapping.xlsx" -WorksheetName "SiteMapping" -ErrorAction Stop

# Processing
Write-Host "Processing"
# $allData = @{}

try {
    foreach ($SiteMapping in $SiteMappings) {
        try {

            # Cleaning map
            Write-Host "Getting data $($SiteMapping.OPSite)/$($SiteMapping.OPList)"
            $srcSiteUrl = $SiteMapping.OPSite
            $srcListName = $SiteMapping.OPList

            $srcSiteFileName = $srcSiteUrl -replace "[^a-zA-Z0-9]", "" 
            $srcListFileName = $srcListName -replace "[^a-zA-Z0-9]", "" 
            $srcFileNameItems = "$root\data\$($srcSiteFileName)_$($srcListFileName)"
                                    
            #if (Test-Path "$srcFileNameItems-items.xml") { continue }

            $xmlHeaders = @{"Accept"="application/atom+xml";"Content-Type"="application/json;odata=verbose"}
            $jsonHeaders = @{"Accept"="application/json;odata=verbose";"Content-Type"="application/json;odata=verbose"}

            $url = "$srcSiteUrl/_api/web/lists/GetByTitle('$srcListName')"
            $listResp = Invoke-WebRequest -UseBasicParsing -uri $url -Method GET -Headers $jsonHeaders -Credential $Credentials
            $listResp.Content | Set-Content -Path "$srcFileNameItems-config.json" -Force
            # $listResp = Invoke-WebRequest -UseBasicParsing -uri $url -Method GET -Headers $xmlHeaders -Credential $Credentials
            # $listResp.Content | Set-Content -Path "$srcFileNameItems-config.xml" -Force

            $url = "$srcSiteUrl/_api/web/lists/GetByTitle('$srcListName')/fields?`$top=999999"
            $listResp = Invoke-WebRequest -UseBasicParsing -uri $url -Method GET -Headers $jsonHeaders -Credential $Credentials
            $listResp.Content | Set-Content -Path "$srcFileNameItems-fields.json" -Force
            # $listResp = Invoke-WebRequest -UseBasicParsing -uri $url -Method GET -Headers $xmlHeaders -Credential $Credentials
            # $listResp.Content | Set-Content -Path "$srcFileNameItems-fields.xml" -Force

            $url = "$srcSiteUrl/_api/web/lists/GetByTitle('$srcListName')/items?`$top=999999&`$expand=File,Folder"
            $listResp = Invoke-WebRequest -UseBasicParsing -uri $url -Method GET -Headers $jsonHeaders -Credential $Credentials
            $listResp.Content | Set-Content -Path "$srcFileNameItems-items.json" -Force
            # $listResp = Invoke-WebRequest -UseBasicParsing -uri $url -Method GET -Headers $xmlHeaders -Credential $Credentials
            # $listResp.Content | Set-Content -Path "$srcFileNameItems-items.xml" -Force

        }
        catch {
            Write-Error "Error processing $($SiteMapping.OLSite)/$($SiteMapping.OLList): $_" -ErrorAction Continue
            # $allData += [PSCustomObject]@{
            #     ResultType = "Exception"
            #     OLSite     = $SiteMapping.OLSite
            #     OLList     = $SiteMapping.OLList
            #     ItemID     = $null
            #     Data       = $_.Exception.Message
            # }
        }
    }
}
catch {
    Write-Warning "Error: $_"
}

# Stopping Transcript
(Get-Date).ToString("yyyyMMddHHmmssfff")
Stop-Transcript
