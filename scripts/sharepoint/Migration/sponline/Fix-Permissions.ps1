#Requires -Version 3.0

Start-Transcript -Path "$PSScriptRoot\..\logs\Fix-Permissions-$(get-date -Format 'yyyyMMddhhmmss').txt"

Write-Output "Enviroment setup"
$webApplication = "webAppName1"
$migrateAll = $false
$sharepointUrl = "https://alyaconsulting.sharepoint.com"
$sharepointAdminUrl = "https://alyaconsulting-admin.sharepoint.com"
$sharepointSitesUrl = "$($sharepointUrl)/sites"
$sharePointEnvSuffix = ""
$sharepointAdmins = ("konrad.brunner@alyaconsulting.ch", "admin@alyaconsulting.onmicrosoft.com", "AlyaSpAdmin@alyaconsulting.ch")

# Getting csom if not already present
function DownloadAndInstallCSOM($dir, $nuget, $nuvrs)
{
	$fileName = "$PSScriptRoot\$nuget_" + $nuvrs + ".nupkg"
	Invoke-WebRequest -Uri $nusrc.href -OutFile $fileName
	if (-not (Test-Path $fileName))
	{
		Write-Error "Was not able to download $nuget which is a prerequisite for this script"
		break
	}
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($fileName, "$PSScriptRoot\$dir")
    Remove-Item $fileName
}

function PrepareCSOM($dir, $nuget)
{
    $resp = Invoke-WebRequest -SkipHttpErrorCheck –Uri "https://www.nuget.org/packages/$nuget"
    $nusrc = ($resp).Links | Where-Object { $_.outerText -eq "Manual download" -or $_."data-track" -eq "outbound-manual-download"}
    $nuvrs = $nusrc.href.Substring($nusrc.href.LastIndexOf("/") + 1, $nusrc.href.Length - $nusrc.href.LastIndexOf("/") - 1)
    if (-not (Test-Path "$PSScriptRoot\$dir\lib\net45"))
    {
        DownloadAndInstallCSOM -dir $dir -nuget $nuget -nuvrs $nuvrs
    }
    else
    {
        # Checking CSOM version, updating if required
        $nuspec = [xml](Get-Content "$PSScriptRoot\$dir\$nuget.nuspec")
        if ($nuspec.package.metadata.version -ne $nuvrs)
        {
            Write-Host "There is a newer CSOM package available. Downloading and installing it."
            Remove-Item -Recurse -Force "$PSScriptRoot\$dir"
            DownloadAndInstallCSOM -dir $dir -nuget $nuget -nuvrs $nuvrs
        }
    }
}

if (-not $global:credLS4D) { $global:credLS4D = Get-Credential -Message "Enter Sharepoint password:" }
PrepareCSOM -dir "_csomOnline" -nuget "Microsoft.SharePointOnline.CSOM"
Add-Type -Path "$PSScriptRoot\_csomOnline\lib\net45\Microsoft.SharePoint.Client.dll"
Add-Type -Path "$PSScriptRoot\_csomOnline\lib\net45\Microsoft.SharePoint.Client.Runtime.dll"
$creds = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($global:credLS4D.UserName, $global:credLS4D.Password)

#Reading input data
if (-Not (Test-Path "$PSScriptRoot\OnPremPermissions$($webApplication)$($webEnv).csv"))
{
    Write-Output "Reading onprem permissions"
    & "$PSScriptRoot\getPermissions$($webApplication)$($webEnv).ps1" -onprem $true
}
if (-Not (Test-Path "$PSScriptRoot\OnlinePermissions$($webApplication)$($webEnv).csv"))
{
    Write-Output "Reading online permissions"
    & "$PSScriptRoot\getPermissions$($webApplication)$($webEnv).ps1" -onprem $false
}

Write-Output "Reading csv files"
$onpremPerms = Import-Csv -Path "$PSScriptRoot\OnPremPermissions$($webApplication)$($webEnv).csv" -Encoding UTF8
$onlinePerms = Import-Csv -Path "$PSScriptRoot\OnlinePermissions$($webApplication)$($webEnv).csv" -Encoding UTF8

# Calcluating changes and fixing
Write-Output "Compairing"
$migSites = Import-Csv -Delimiter "," -encoding UTF8 $PSScriptRoot\..\setupSites.csv
if ([string]::IsNullOrEmpty($migSites[0].DstCol))
{
	$migSites = Import-Csv -Delimiter ";" -encoding UTF8 $PSScriptRoot\..\setupSites.csv
}
if ([string]::IsNullOrEmpty($migSites[0].DstCol))
{
	Write-Error "Wrong delimiter found."
	exit
}

$migSites | Where-Object { ( $migrateAll -or $_.Command.ToLower() -eq "copy" ) -and $_.WebApplication -eq $webApplication } | Foreach-Object {

    if ([string]::IsNullOrEmpty($_.DstUrl))
    {
	    $fullUrl = "$($sharepointSitesUrl)/$($_.DstCol)$($sharePointEnvSuffix)"
    	$alias = "$($_.DstCol)$($sharePointEnvSuffix)"
    }
    else
    {
	    $fullUrl = "$($sharepointSitesUrl)/$($_.DstCol)$($sharePointEnvSuffix)-$($_.DstUrl)"
    	$alias = "$($_.DstCol)$($sharePointEnvSuffix)-$($_.DstUrl)"
    }
	$fullSrcUrl = "https://$($webApplication).alyaconsulting.ch$($_.SrcUrl)"
	Write-Output "  Site $($fullUrl)"
	Write-Output "   with data from $($fullSrcUrl)"

    foreach($permType in ("Web", "List"))
    {

        $onpremWebs = $onpremPerms | Where-Object { $_.Type -eq $permType -and $_.Site -eq $fullSrcUrl } | Select-Object -ExpandProperty Web -Unique
        foreach ($onpremWeb in $onpremWebs)
        {
            $onlineWeb = $onpremWeb
            if ($_.SrcUrl.length -gt 0) {
                $onlineWeb = $onlineWeb.Replace($_.SrcUrl,"")
            }
            if ($onlineWeb -eq "/") {
                $onlineWeb = ""
            }
            $onlineWeb = "/sites/" + $alias + $onlineWeb
	        Write-Output "   Web $($onlineWeb) Type $($permType)"
        
            $onpremChkPerms = $onpremPerms | Where-Object { $_.Type -eq $permType -and $_.Site -eq $fullSrcUrl -and $_.Web -eq $onpremWeb }
            $onlineChkPerms = $onlinePerms | Where-Object { $_.Type -eq $permType -and $_.Site -eq $fullUrl -and $_.Web -eq $onlineWeb }

            switch($permType)
            {

                "Web" {
                    $onpremWebMmbrs = $onpremChkPerms | Select-Object -ExpandProperty Member -Unique
                    $onlineWebMmbrs = $onlineChkPerms | Select-Object -ExpandProperty Member -Unique
                    foreach ($onlineWebMmbr in $onlineWebMmbrs)
                    {
                        if ($onlineWebMmbr.StartsWith("Besitzer von")) {continue}
                        if ($onlineWebMmbr.StartsWith("Mitglieder von")) {continue}
                        if ($onlineWebMmbr.StartsWith("Besucher von")) {continue}
                        if ($onlineWebMmbr.StartsWith("Excel Services Viewers")) {continue}
                        if ($onlineWebMmbr.StartsWith("Excel Services-Viewer")) {continue}
                        if ($onlineWebMmbr.StartsWith("Brunner Konrad")) {continue}
                        if ($onlineWebMmbr.StartsWith("Hierarchie-Manager")) {continue}
                        if ($onlineWebMmbr.StartsWith("Designer")) {continue}
                        if ($onlineWebMmbr.StartsWith("Genehmigende Personen")) {continue}
                        if ($onlineWebMmbr.StartsWith("Übersetzungsmanager")) {continue}
                        if ($onlineWebMmbr.StartsWith("Personen mit eingeschränkten Leserechten")) {continue}

                        $fnd = $false
                        foreach ($onpremWebMmbr in $onpremWebMmbrs)
                        {
                            if ($onlineWebMmbr -like "*$($onpremWebMmbr)*")
                            {
                                $fnd = $true
                                break
                            }
                        }
                        if (-Not $fnd)
                        {
                            Write-Host "       Deleting member $($onlineWebMmbr)"
                        }
                    }
                }
                "List" {
                    $listTitles = $onpremChkPerms | Select-Object -ExpandProperty List -Unique

                    foreach ($listTitle in $listTitles)
                    {
	                    Write-Output "     List $($listTitle)"
                        $onpremListPerms = $onpremChkPerms | Where-Object { $_.List -eq $listTitle }
                        $onlineListPerms = $onlineChkPerms | Where-Object { $_.List -eq $listTitle }

                        $onpremListMmbrs = $onpremListPerms | Select-Object -ExpandProperty Member -Unique
                        $onlineListMmbrs = $onlineListPerms | Select-Object -ExpandProperty Member -Unique

                        foreach ($onlineListMmbr in $onlineListMmbrs)
                        {
                            if ($onlineListMmbr.StartsWith("Besitzer von")) {continue}
                            if ($onlineListMmbr.StartsWith("Mitglieder von")) {continue}
                            if ($onlineListMmbr.StartsWith("Besucher von")) {continue}
                            if ($onlineListMmbr.StartsWith("Excel Services Viewers")) {continue}
                            if ($onlineListMmbr.StartsWith("Excel Services-Viewer")) {continue}
                            if ($onlineListMmbr.StartsWith("Brunner Konrad")) {continue}
                            if ($onlineListMmbr.StartsWith("Hierarchie-Manager")) {continue}
                            if ($onlineListMmbr.StartsWith("Designer")) {continue}
                            if ($onlineListMmbr.StartsWith("Genehmigende Personen")) {continue}
                            if ($onlineListMmbr.StartsWith("Übersetzungsmanager")) {continue}
                            if ($onlineListMmbr.StartsWith("Mitglieder (ohne Löschen)")) {continue}
                            if ($onlineListMmbr.StartsWith("StratFM-Mitglieder-site1internal")) {continue}
                            if ($onlineListMmbr.StartsWith("Personen mit eingeschränkten Leserechten")) {continue}

                            $fnd = $false
                            foreach ($onpremListMmbr in $onpremListMmbrs)
                            {
                                if ($onlineListMmbr -like "*$($onpremListMmbr)*")
                                {
                                    $fnd = $true
                                    break
                                }
                            }
                            if (-Not $fnd)
                            {
                                Write-Host "       Deleting member $($onlineListMmbr)"

                                $ctx = New-Object Microsoft.SharePoint.Client.ClientContext($sharepointUrl+$onlineWeb)
                                $ctx.credentials = $creds
                                $ctx.load($ctx.Web)
                                $ctx.load($ctx.Web.Lists)
                                $ctx.executeQuery()
                                foreach($list in $ctx.Web.Lists)
                                {
                                    $ctx.load($list)
                                    $ctx.load($list.RootFolder)
                                    $ctx.executeQuery()
                                    if ($list.RootFolder.ServerRelativeUrl -eq $onlineListPerms[0].Url)
                                    {
                                        $listroleAssignments=$list.RoleAssignments
                                        $ctx.Load($listroleAssignments)
                                        $ctx.ExecuteQuery()

                                        $ass = $null
                                        foreach($listRoleAssignment in $listroleAssignments)
                                        {                            
                                            $ctx.Load($listroleAssignment.Member)
                                            $ctx.ExecuteQuery()
                                            if ($listRoleAssignment.Member.Title -eq $onlineListMmbr)
                                            {
                                                $ass = $listRoleAssignment
                                                break
                                            }
                                        }
                                        if ($ass)
                                        {
                                            $listRoleAssignment.DeleteObject()
                                            $ctx.ExecuteQuery()
                                        }
                                        break
                                    }
                                }
                            }
                        }
                    }                    
                }
            }
        }
    }
}

Stop-Transcript
