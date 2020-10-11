#Requires -Version 2.0
#Requires -Modules Microsoft.Online.Sharepoint.PowerShell

Start-Transcript -Path "$PSScriptRoot\..\logs\Fix-Structure-$(get-date -Format 'yyyyMMddhhmmss').txt"

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
    $resp = Invoke-WebRequest –Uri "https://www.nuget.org/packages/$nuget"
    $nusrc = ($resp).Links | where { $_.outerText -eq "Manual download" -or $_."data-track" -eq "outbound-manual-download"}
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
$credsOnline = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($global:credLS4D.UserName, $global:credLS4D.Password)
$credsOnPrem = New-Object System.Net.NetworkCredential($global:credLS4D.UserName, $global:credLS4D.Password)

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

function Process-Folder($folderOnPrem, $folderOnline, $webUrlOnPrem, $webUrlOnline, $fullSrcUrl, $siteSrcUrl, $fullDstUrl, $siteDstUrl)
{
    Write-Host "     Folder: $($folderOnPrem.ServerRelativeUrl)"
    $ctxOnPrem.load($folderOnPrem)
    $ctxOnPrem.load($folderOnPrem.Folders)
    $ctxOnPrem.load($folderOnPrem.Files)
    $ctxOnPrem.executeQuery()
    $ctxOnline.load($folderOnline)
    $ctxOnline.load($folderOnline.Folders)
    $ctxOnline.load($folderOnline.Files)
    $ctxOnline.executeQuery()

    foreach($sfolder in $folderOnPrem.Folders)
    {
        $oFolder = $folderOnline.Folders | where { $_.Name -eq $sfolder.Name }
        if (-Not $oFolder -Or $oFolder.ServerObjectIsNull)
        {
            $onlineFolder = $sfolder.ServerRelativeUrl
            if ($siteSrcUrl.length -gt 0) {
                $onlineFolder = $onlineFolder.Replace($siteSrcUrl,"")
            }
            if ($onlineFolder -eq "/") {
                $onlineFolder = ""
            }
            $onlineFolder = $fullDstUrl + $onlineFolder

            $fnd = New-Object System.Object
            $fnd | Add-Member -MemberType NoteProperty -Name "Type" -Value "Folder"
            $fnd | Add-Member -MemberType NoteProperty -Name "OnPrem" -Value $sfolder.ServerRelativeUrl
            $fnd | Add-Member -MemberType NoteProperty -Name "Online" -Value $onlineFolder
            $fnd | Add-Member -MemberType NoteProperty -Name "Web" -Value $web.ServerRelativeUrl
            $fnd | Add-Member -MemberType NoteProperty -Name "Error" -Value "Missing"
            $global:foundItems += $fnd
        }
        else
        {
            Process-Folder -folderOnPrem $sfolder -folderOnline $oFolder -webUrlOnPrem $webUrlOnPrem -webUrlOnline $webUrlOnline  -fullSrcUrl $fullSrcUrl -siteSrcUrl $siteSrcUrl -fullDstUrl $fullDstUrl -siteDstUrl $siteDstUrl
        }
    }

    foreach($file in $folderOnPrem.Files)
    {
        $oFile = $folderOnline.Files | where { $_.Name -eq $file.Name }
        if (-Not $oFile -Or $oFile.ServerObjectIsNull)
        {
            $onlineFile = $file.ServerRelativeUrl
            if ($siteSrcUrl.length -gt 0) {
                $onlineFile = $onlineFile.Replace($siteSrcUrl,"")
            }
            if ($onlineFile -eq "/") {
                $onlineFile = ""
            }
            $onlineFile = $fullDstUrl + $onlineFile

            $fnd = New-Object System.Object
            $fnd | Add-Member -MemberType NoteProperty -Name "Type" -Value "File"
            $fnd | Add-Member -MemberType NoteProperty -Name "OnPrem" -Value $file.ServerRelativeUrl
            $fnd | Add-Member -MemberType NoteProperty -Name "Online" -Value $onlineFile
            $fnd | Add-Member -MemberType NoteProperty -Name "Error" -Value "Missing"
            $global:foundItems += $fnd
        }
    }
}

function RunWeb($onpremWeb, $onlineWeb, $fullSrcUrl, $fullDstUrl, $siteSrcUrl, $siteDstUrl)
{
    Write-Host " Web: $($onpremWeb.ServerRelativeUrl)"
    
    $ctxOnPrem.load($onpremWeb.Lists)
    $ctxOnPrem.executeQuery()
    $ctxOnline.load($onlineWeb.Lists)
    $ctxOnline.executeQuery()

    foreach($list in $web.Lists)
    {
        $ctxOnPrem.load($list)
        $ctxOnPrem.load($list.RootFolder)
        $ctxOnPrem.executeQuery()
        Write-Host "   List: $($list.Title)"

        if (-Not $list.RootFolder.ServerRelativeUrl.Contains("/_catalogs") -and -Not $list.RootFolder.ServerRelativeUrl.Contains("/Style Library") -and $list.BaseType -eq "DocumentLibrary")
        {
            $olist = $onlineWeb.Lists | where { $_.Title -eq $list.Title }
            if (-Not $olist -Or $olist.ServerObjectIsNull)
            {
                $onlineList = $list.RootFolder.ServerRelativeUrl
                if ($siteSrcUrl.length -gt 0) {
                    $onlineList = $onlineList.Replace($siteSrcUrl,"")
                }
                if ($onlineList -eq "/") {
                    $onlineList = ""
                }
                $onlineList = $fullDstUrl + $onlineList

                $fnd = New-Object System.Object
                $fnd | Add-Member -MemberType NoteProperty -Name "Type" -Value "List"
                $fnd | Add-Member -MemberType NoteProperty -Name "OnPrem" -Value $list.RootFolder.ServerRelativeUrl
                $fnd | Add-Member -MemberType NoteProperty -Name "Online" -Value $onlineList
                $fnd | Add-Member -MemberType NoteProperty -Name "Error" -Value "Missing"
                $global:foundItems += $fnd
            }
            else
            {
                $ctxOnline.load($olist)
                $ctxOnline.load($olist.RootFolder)
                $ctxOnline.executeQuery()

                Process-Folder -folderOnPrem $list.RootFolder -folderOnline $olist.RootFolder -webUrlOnPrem $web.ServerRelativeUrl -webUrlOnline $oweb.ServerRelativeUrl  -fullSrcUrl $fullSrcUrl -siteSrcUrl $siteSrcUrl -fullDstUrl $fullDstUrl -siteDstUrl $siteDstUrl
            }

        }
    }

    $ctxOnPrem.load($onpremWeb.Webs)
    $ctxOnPrem.executeQuery()
    $ctxOnline.load($onlineWeb.Webs)
    $ctxOnline.executeQuery()
    foreach($web in $onpremWeb.Webs)
    {
        $oWeb = $onlineWeb.Webs | where { $_.Title -eq $web.Title }
        if (-Not $oweb -Or $oweb.ServerObjectIsNull)
        {
            $onlineWeb = $web.ServerRelativeUrl
            if ($siteSrcUrl.length -gt 0) {
                $onlineWeb = $onlineWeb.Replace($siteSrcUrl,"")
            }
            if ($onlineWeb -eq "/") {
                $onlineWeb = ""
            }
            $onlineWeb = $fullDstUrl + $onlineWeb

            $fnd = New-Object System.Object
            $fnd | Add-Member -MemberType NoteProperty -Name "Type" -Value "Web"
            $fnd | Add-Member -MemberType NoteProperty -Name "OnPrem" -Value $web.ServerRelativeUrl
            $fnd | Add-Member -MemberType NoteProperty -Name "Online" -Value $onlineWeb
            $fnd | Add-Member -MemberType NoteProperty -Name "Error" -Value "Missing"
            $global:foundItems += $fnd
        }
        else
        {
            RunWeb -onpremWeb $web -onlineWeb $oWeb -fullSrcUrl $fullSrcUrl -siteSrcUrl $siteSrcUrl -fullDstUrl $fullDstUrl -siteDstUrl $siteDstUrl
        }
    }
}

$global:foundItems = @()
$migSites | where { $migrateAll -or ($_.Command.ToLower() -eq "copy" -and $_.WebApplication -eq $webApplication) } | foreach {
    if ([string]::IsNullOrEmpty($_.DstUrl))
    {
	    $fullDstUrl = "$($sharepointSitesUrl)/$($_.DstCol)$($sharePointEnvSuffix)"
    	$alias = "$($_.DstCol)$($sharePointEnvSuffix)"
    }
    else
    {
	    $fullDstUrl = "$($sharepointSitesUrl)/$($_.DstCol)$($sharePointEnvSuffix)-$($_.DstUrl)"
    	$alias = "$($_.DstCol)$($sharePointEnvSuffix)-$($_.DstUrl)"
    }
	$fullSrcUrl = "https://$($webApplication).alyaconsulting.ch$($_.SrcUrl)"

    Write-Host "OnPrem: $($fullSrcUrl)"
    $ctxOnPrem = New-Object Microsoft.SharePoint.Client.ClientContext($fullSrcUrl)
    $ctxOnPrem.credentials = $credsOnPrem
    $ctxOnPrem.load($ctxOnPrem.Web)
    $ctxOnPrem.executeQuery()

    Write-Host "Online: $($fullDstUrl)"
    $ctxOnline = New-Object Microsoft.SharePoint.Client.ClientContext($fullDstUrl)
    $ctxOnline.credentials = $credsOnline
    $ctxOnline.load($ctxOnline.Web)
    $ctxOnline.executeQuery()

    RunWeb -onpremWeb $ctxOnPrem.Web -onlineWeb $ctxOnline.Web -fullSrcUrl "https://$($webApplication).alyaconsulting.ch" -siteSrcUrl $_.SrcUrl -fullDstUrl $fullDstUrl -siteDstUrl "/sites/$alias"
}
$global:foundItems | Export-Csv -NoTypeInformation -Path "MissingStructure$($webApplication)$($webEnv).csv" -Encoding UTF8 -Force -Confirm:$false
