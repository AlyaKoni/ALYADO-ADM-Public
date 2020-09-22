#Requires -Version 3.0

<#
    Copyright (c) Alya Consulting, 2019, 2020

    This file is part of the Alya Base Configuration.
    The Alya Base Configuration is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
	Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
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
    14.11.2019 Konrad Brunner       Initial Version

#>

# Source from https://github.com/microsoft/powerapps-tools/tree/master/Administration/AdminInADay/SetupScripts/GenerateAppsAndFlows

function Get-AudienceForHostName
{
    [CmdletBinding()]
    Param(
        [string] $Uri
    )
    $hostMapping = @{
        "management.azure.com" = "https://management.azure.com/";
        "api.powerapps.com" = "https://service.powerapps.com/";
        "tip1.api.powerapps.com" = "https://service.powerapps.com/";
        "tip2.api.powerapps.com" = "https://service.powerapps.com/";
        "graph.windows.net" = "https://graph.windows.net/";
        "api.bap.microsoft.com" = "https://service.powerapps.com/";
        "tip1.api.bap.microsoft.com" = "https://service.powerapps.com/";
        "tip2.api.bap.microsoft.com" = "https://service.powerapps.com/";
        "api.flow.microsoft.com" = "https://service.flow.microsoft.com/";
        "tip1.api.flow.microsoft.com" = "https://service.flow.microsoft.com/";
        "tip2.api.flow.microsoft.com" = "https://service.flow.microsoft.com/";
    }
    $uriObject = New-Object System.Uri($Uri)
    $audhost = $uriObject.Host
    if ($hostMapping[$audhost] -ne $null)
    {
        return $hostMapping[$audhost];
    }
    Write-Verbose "Unknown host $audhost. Using https://management.azure.com/ as a default";
    return "https://management.azure.com/";
}

function Invoke-Request(
    [CmdletBinding()]

    [Parameter(Mandatory=$True)]
    [string] $Uri,

    [Parameter(Mandatory=$True)]
    [string] $Method,

    [object] $Body = $null,

    [Hashtable] $Headers = @{},

    [switch] $ParseContent,

    [switch] $ThrowOnFailure
)
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $audience = Get-AudienceForHostName -Uri $Uri
    $token = Get-JwtToken -Audience $audience
    $Headers["Authorization"] = "Bearer $token";
    $Headers["User-Agent"] = "PowerShell cmdlets 1.0";
    try {
        if ($Body -eq $null -or $Body -eq "")
        {
            $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -Method $Method -UseBasicParsing
        }
        else 
        {
            $jsonBody = ConvertTo-Json $Body -Depth 20
            $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -Method $Method -ContentType "application/json" -Body $jsonBody -UseBasicParsing
        }
        if ($ParseContent)
        {
            if ($response.Content)
            {
                return ConvertFrom-Json $response.Content;
            }
        }
        return $response
    } catch {
        $response = $_.Exception.Response
        if ($_.ErrorDetails)
        {
            $errorResponse = ConvertFrom-Json $_.ErrorDetails;
            $code = $response.StatusCode
            $message = $errorResponse.Error.Message
            Write-Verbose "Status Code: '$code'. Message: '$message'" 
        }
        if ($ThrowOnFailure)
        {
            throw;
        }
        else 
        {
            return $response
        }
    }
}

function Configure-ImportResourcesObject(
    $Resources,
    $EnvironmentName = $null,
    [bool]$DefaultToExportSuggestions = $false,
    [bool] $NewApp = $false,
    [string] $ResourceName
)
{
    $includedResourceIds = @()
    $includedSuggestedResourceIds = @()
    $includedResources = $Resources
    $numResources = 0
    $env = Get-AdminPowerAppEnvironment -EnvironmentName $EnvironmentName
    $environmentDisplayName = $env.DisplayName
    $selectedCommonDataServiceOption = $null
    foreach ($resource in Get-Member -InputObject $includedResources -MemberType NoteProperty)
    {
        $numResources = $numResources + 1 
        $property = 'Name'
        $propertyvalue = $resource.$property
        If($includedResources.$propertyvalue.id -ne $null -and $includedResources.$propertyvalue.id -ne "")
        {
            $includedResourceIds = $includedResourceIds + $includedResources.$propertyvalue.id
        }
        If(!$includedSuggestedResourceIds.$propertyvalue.suggestedId)
        {
            $includedSuggestedResourceIds = $includedSuggestedResourceIds + $includedSuggestedResourceIds.$propertyvalue.suggestedId
        }
        $type = $null
        if ($includedResources.$propertyvalue.type -eq "Microsoft.PowerApps/apps")
        {
            $result = $null
            $selection = $null

            if($NewApp)
            {
                $type = "New"
                $includedResources.$propertyvalue.details.displayName = $ResourceName
            }
            else 
            {
                $type = "Update"
                $selectedResource = $result.selectedResource
                $includedResources.$propertyvalue | Add-Member -MemberType NoteProperty -name id -value $selectedResource.id
                $includedResources.$propertyvalue | Add-Member -MemberType NoteProperty -name name -value $selectedResource.name
            }          
        }
        if ($includedResources.$propertyvalue.type -eq "Microsoft.Flow/flows")
        {
            $result = $null
            $selection = $null

            if($NewApp)
            {
                $type = "New"
                $includedResources.$propertyvalue.details.displayName = $ResourceName
            }
            else 
            {
                $type = "Update"
                $selectedResource = $result.selectedResource
                $includedResources.$propertyvalue | Add-Member -MemberType NoteProperty -name id -value $selectedResource.id
                $includedResources.$propertyvalue | Add-Member -MemberType NoteProperty -name name -value $selectedResource.name
            }
        }
        if ($includedResources.$propertyvalue.type -eq "Microsoft.PowerApps/apis")
        {
            if ($includedResources.$propertyvalue.name -eq $null)
            {
                if (-Not $NewApp) 
                {
                    $type = "Existing"
                    $selectedResource = $result.selectedResource
                    $includedResources.$propertyvalue | Add-Member -MemberType NoteProperty -name id -value $selectedResource.id
                    $includedResources.$propertyvalue | Add-Member -MemberType NoteProperty -name name -value $selectedResource.name
                }
            }
            else {                
                $type = "Existing"
            }
        }
        if ($includedResources.$propertyvalue.type -eq "Microsoft.PowerApps/apis/connections")
        {
            if (-Not $NewApp) 
            {
                $type = "Existing"
                $selectedResource = $result.selectedResource
                $includedResources.$propertyvalue | Add-Member -MemberType NoteProperty -name id -value $selectedResource.id
                $includedResources.$propertyvalue | Add-Member -MemberType NoteProperty -name name -value $selectedResource.name
            }
        }
        if ($includedResources.$propertyvalue.type -eq "Microsoft.CommonDataModel/environments/namespaces/enumerations" -or $includedResources.$propertyvalue.type -eq "Microsoft.CommonDataModel/environments/namespaces/entities")
        { 
            if ($includedResources.$propertyvalue.configurableBy -eq "User")
            {
                if($DefaultToExportSuggestions -and ($includedResources.$propertyvalue.suggestedCreationType -ne $null))
                {
                    $type = $includedResources.$propertyvalue.suggestedCreationType
                }
                else {
                    If($selectedCommonDataServiceOption -eq $null)
                    {
                        $selectedCommonDataServiceOption = "Overwrite"
                        $type = $selectedCommonDataServiceOption
                    }
                    else {
                        $type = $selectedCommonDataServiceOption
                    }
                }
            }
            else {
                $type =  $includedResources.$propertyvalue.suggestedCreationType
            }
        }
        If($type)
        {    
            If($includedResources.$propertyvalue.suggestedCreationType)
            {
                $includedResources.$propertyvalue.suggestedCreationType = $type
            }
            else
            {
                $includedResources.$propertyvalue | Add-Member -MemberType NoteProperty -name suggestedCreationType -value $type
            }
            $includedResources.$propertyvalue | Add-Member -MemberType NoteProperty -name selectedCreationType -value $type
        }
    }
    $responseObject = @{
        resources = $includedResources
        resourceIds = $includedResourceIds
        suggestedResourceIds = $includedSuggestedResourceIds
    } 
    return $responseObject
}

function Upload-FileToBlogStorage(
    [string] $EnvironmentName,
    [string] $FilePath,
    [string] $ApiVersion = "2016-11-01"
)
{
    try {
        $fileBinary = [IO.File]::ReadAllBytes($FilePath);
        $encoding = [System.Text.Encoding]::GetEncoding("iso-8859-1");
        $file = $encoding.GetString($fileBinary)
    } catch {
        Write-Host "Failed to read the file"
        throw
    }
    $generateResourceStorageUrl = "https://management.azure.com/providers/Microsoft.BusinessAppPlatform/environments/" + $EnvironmentName + "/generateResourceStorage`?api-version=" + $ApiVersion
    $generateResourceStorageResponse = Invoke-Request -Uri $generateResourceStorageUrl -Method POST -ParseContent -ThrowOnFailure
    $originalBlobUri = $generateResourceStorageResponse.sharedAccessSignature
    $uri = [System.Uri] $originalBlobUri 
    $filename = "filename.zip"
    $uriHost = $uri.Host
    $uriPath = $uri.AbsolutePath
    $uriQuery = $uri.Query
    $tempBlobUri = "https://$uriHost$uriPath/$fileName$uriQuery"
    $commitBlobUri =  "$tempBlobUri&comp=blocklist"
    $uploadBlobUri = "$tempBlobUri&comp=block"
    $BlockId = "BlockId"
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($BlockId)
    $EncodedBlockId =[Convert]::ToBase64String($Bytes)
    $uploadBlobUri =  "$uploadBlobUri&blockid=$EncodedBlockId"
    try {
        $uploadFiletoBLog = Invoke-WebRequest -Uri $uploadBlobUri -Method Put -ContentType "application/json" -Body $file -UseBasicParsing
        $commitBody = "<?xml version=`"1.0`" encoding=`"utf-8`"?><BlockList><Latest>$EncodedBlockId</Latest></BlockList>"
        $commitFiletoBLog = Invoke-WebRequest -Uri $commitBlobUri -Method Put -ContentType "application/json" -Body $commitBody -UseBasicParsing
    } catch {
        Write-Host "Failed to upload the file to blob storage"
        throw
    }
    return $tempBlobUri
}

function Get-ImportPackageResources(
    [string] $EnvironmentName,
    [string] $ImportPackageBlobUri,
    [string] $ApiVersion = "2016-11-01"
)
{
    $listParametersUri = "https://management.azure.com/providers/Microsoft.BusinessAppPlatform/environments/" + $EnvironmentName + "/listImportParameters`?api-version=" + $ApiVersion
    $listParametersBody = @{ 
        packageLink = @{
            value = $ImportPackageBlobUri
        } 
    }
    $listParametersResponse = Invoke-Request -Uri $listParametersUri -Method POST -Body $listParametersBody -ThrowOnFailure
    $statusUri= $listParametersResponse.Headers['Location']
    while($listParametersResponse.StatusCode -ne 200) 
    {
        Start-Sleep -s 5
        $listParametersResponse = Invoke-Request -Uri $statusUri -Method GET -ThrowOnFailure
    }
    $parsedListParametersResponse = ConvertFrom-Json $listParametersResponse.Content
    return $parsedListParametersResponse
}

function Import-Package(
    [string] $EnvironmentName,
    [string] $ImportPackageFilePath,
    [string] $ApiVersion = "2016-11-01",
    [bool] $DefaultToExportSuggestions = $false,
    [bool] $NewApp = $false,
    [string] $ResourceName
)
{
    $blobUri = Upload-FileToBlogStorage -EnvironmentName $EnvironmentName -FilePath $ImportPackageFilePath -ApiVersion $ApiVersion
    $parsedListParametersResponse = Get-ImportPackageResources -EnvironmentName $EnvironmentName -ImportPackageBlobUri $blobUri -ApiVersion $ApiVersion
    $includedResources = Configure-ImportResourcesObject -resources $parsedListParametersResponse.properties.resources -EnvironmentName $EnvironmentName -DefaultToExportSuggestions $DefaultToExportSuggestions -NewApp $NewApp -ResourceName $ResourceName
    $validateImportPackageUri = "https://management.azure.com/providers/Microsoft.BusinessAppPlatform/environments/" + $EnvironmentName + "/validateImportPackage`?api-version=" + $ApiVersion
    $validateImportPackageBody = @{ 
        details = $parsedListParametersResponse.properties.details
        packageLink = $parsedListParametersResponse.properties.packageLink
        resources = $includedResources.resources
    }
    $validateImportPackageResponse = Invoke-Request -Uri $validateImportPackageUri -Method POST -Body $validateImportPackageBody -ThrowOnFailure
    $parsedValidateImportResponse = ConvertFrom-Json $validateImportPackageResponse.Content
    if(($parsedValidateImportResponse.errors).Length -gt 0)
    {
        Write-Host "Package failed validation with the following errors \n" + $parsedValidateImportResponse.errors
        throw
    }
    $importPackageUri = "https://management.azure.com/providers/Microsoft.BusinessAppPlatform/environments/" + $EnvironmentName + "/importPackage`?api-version=" + $ApiVersion
    $importPackageResponse = Invoke-Request -Uri $importPackageUri -Method POST -Body $validateImportPackageBody -ThrowOnFailure
    $importStatusUri= $importPackageResponse.Headers['Location']
    while($importPackageResponse.StatusCode -ne 200) 
    {
        Start-Sleep -s 5
        $importPackageResponse = Invoke-Request -Uri $importStatusUri -Method GET -ThrowOnFailure
    }
    $parsedImportPackageResponse = ConvertFrom-Json $importPackageResponse.Content
    if(($parsedImportPackageResponse.properties.errors).Length -gt 0)
    {
        Write-Host "Package failed import with the following errors " + $parsedImportPackageResponse.properties.errors
    }
    return $parsedImportPackageResponse
}
