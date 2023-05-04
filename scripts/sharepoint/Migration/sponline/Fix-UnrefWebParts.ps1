#Requires -Version 2.0
#Requires -Modules Microsoft.Online.Sharepoint.PowerShell

Start-Transcript -Path "$PSScriptRoot\..\logs\Fix-UnrefWebParts-$(get-date -Format 'yyyyMMddhhmmss').txt"

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

function Process-Folder ($folder,$webUrl,$serverUrl)
{
    Write-Host "     Folder: $($folder.ServerRelativeUrl)"
    $ctx.load($folder)
    $ctx.load($folder.Folders)
    $ctx.load($folder.Files)
    $ctx.executeQuery()

    foreach($sfolder in $folder.Folders)
    {
        Process-Folder -folder $sfolder -webUrl $web.ServerRelativeUrl -serverUrl $serverUrl
    }

    foreach($file in $folder.Files)
    {

        if ($file.ServerRelativeUrl.ToLower().EndsWith(".aspx"))
        {
        $ctx.load($file)
        $ctx.Load($file.ListItemAllFields)
        $ctx.executeQuery()
            $wikiField = $file.ListItemAllFields["WikiField"]
            if ($wikiField)
            {
                Write-Output "       Page $($file.ServerRelativeUrl)"
                $webPartManager = $file.GetLimitedWebPartManager([System.Web.UI.WebControls.WebParts.PersonalizationScope]::Shared)
                $ctx.Load($webPartManager)
                $ctx.Load($webPartManager.WebParts)
                $ctx.ExecuteQuery()
                foreach($webPart in $webPartManager.WebParts)
                {
                    $ctx.Load($webPart.WebPart)
                    $ctx.ExecuteQuery()

                    Write-Output "        WP $($webPart.WebPart.Title)"
                    if (-Not $wikiField.ToLower().Contains($webPart.Id.ToString().ToLower()))
                    {
                        Write-Output "          *** not referenced"
                        $fnd = New-Object System.Object
                        $fnd | Add-Member -MemberType NoteProperty -Name "Site" -Value $serverUrl
                        $fnd | Add-Member -MemberType NoteProperty -Name "Web" -Value $webUrl
                        $fnd | Add-Member -MemberType NoteProperty -Name "Folder" -Value $folder.ServerRelativeUrl
                        $fnd | Add-Member -MemberType NoteProperty -Name "Page" -Value $file.ServerRelativeUrl
                        $fnd | Add-Member -MemberType NoteProperty -Name "WPTitle" -Value $webPart.WebPart.Title
                        $fnd | Add-Member -MemberType NoteProperty -Name "WPId" -Value $webPart.Id
                        $global:foundItems += $fnd

                        $webPart.DeleteWebPart()
                        $ctx.ExecuteQuery()
                    }
                }
            }
        }
    }
}

function RunWeb($web,$serverUrl)
{
    Write-Host " Web: $($web.ServerRelativeUrl)"
    
    $ctx.load($web.Lists)
    $ctx.executeQuery()

    foreach($list in $web.Lists)
    {
        $ctx.load($list)
        $ctx.load($list.RootFolder)
        $ctx.executeQuery()
        Write-Host "   List: $($list.Title)"

        if (-Not $list.RootFolder.ServerRelativeUrl.Contains("/_catalogs") -and -Not $list.RootFolder.ServerRelativeUrl.Contains("/Style Library") -and $list.BaseType -eq "DocumentLibrary")
        {
            Process-Folder -folder $list.RootFolder -webUrl $web.ServerRelativeUrl -serverUrl $serverUrl
        }
    }

    $ctx.load($web.Webs)
    $ctx.executeQuery()
    foreach($sweb in $web.Webs)
    {
        $ctx.load($sweb)
        $ctx.executeQuery()

        RunWeb -web $sweb -serverUrl $serverUrl
    }
}

$global:foundItems = @()
$migSites | Where-Object { $migrateAll -or ($_.Command.ToLower() -eq "copy" -and $_.WebApplication -eq $webApplication) } | Foreach-Object {
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

    Write-Host "Site: $($fullDstUrl)"
    $ctx = New-Object Microsoft.SharePoint.Client.ClientContext($fullDstUrl)
    $ctx.credentials = $creds
    $ctx.load($ctx.Web)
    $ctx.executeQuery()
    RunWeb -web $ctx.Web -serverUrl $fullDstUrl
}
$global:foundItems | Export-Csv -NoTypeInformation -Path "UnrefWebParts$($webApplication)$($webEnv).csv" -Encoding UTF8 -Force -Confirm:$false
