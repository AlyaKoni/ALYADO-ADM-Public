#Requires -Version 3.0
Start-Transcript -Path "FindUserDocuments.log" -Force -Confirm:$false

$siteUrls = @(
"https://site1internal.alyaconsulting.ch",
"https://site1internal.alyaconsulting.ch/sites/site001",
"https://site1internal.alyaconsulting.ch/sites/site002",
"https://site1internal.alyaconsulting.ch/sites/site003",
"https://site1internal.alyaconsulting.ch/sites/site004",
"https://site1internal.alyaconsulting.ch/sites/site005",
"https://site1internal.alyaconsulting.ch/sites/site006",
"https://site2internal.alyaconsulting.ch",
"https://site2internal.alyaconsulting.ch/sites/site001",
"https://site2internal.alyaconsulting.ch/sites/site002",
"https://site2internal.alyaconsulting.ch/sites/site003",
"https://site2internal.alyaconsulting.ch/sites/site004",
"https://site2internal.alyaconsulting.ch/sites/site005",
"https://site2internal.alyaconsulting.ch/sites/site006"
)

$users = @(
"Hans Muster",
"Peter Beispiel"
)

# Getting csom if not already present
function DownloadAndInstallCSOM()
{
	$fileName = "$PSScriptRoot\Microsoft.SharePoint2016.CSOM_" + $nuvrs + ".nupkg"
	Invoke-WebRequest -Uri $nusrc.href -OutFile $fileName
	if (-not (Test-Path $fileName))
	{
		Write-Error "Was not able to download Microsoft.SharePoint2016.CSOM which is a prerequisite for this script"
		break
	}
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($fileName, "$PSScriptRoot\_csom")
    Remove-Item $fileName
}
$resp = Invoke-WebRequest –Uri "https://www.nuget.org/packages/Microsoft.SharePoint2016.CSOM"
$nusrc = ($resp).Links | where { $_.outerText -eq "Manual download" -or $_."data-track" -eq "outbound-manual-download"}
$nuvrs = $nusrc.href.Substring($nusrc.href.LastIndexOf("/") + 1, $nusrc.href.Length - $nusrc.href.LastIndexOf("/") - 1)
if (-not (Test-Path "$PSScriptRoot\_csom\lib\net45"))
{
    DownloadAndInstallCSOM
}
else
{
    # Checking CSOM version, updating if required
    $nuspec = [xml](Get-Content "$PSScriptRoot\_csom\Microsoft.SharePoint2016.CSOM.nuspec")
    if ($nuspec.package.metadata.version -ne $nuvrs)
    {
        Write-Output "There is a newer CSOM package available. Downloading and installing it."
        Remove-Item -Recurse -Force "$PSScriptRoot\_csom"
        DownloadAndInstallCSOM
    }
}
Add-Type -Path "$PSScriptRoot\_csom\lib\net45\Microsoft.SharePoint.Client.dll"
Add-Type -Path "$PSScriptRoot\_csom\lib\net45\Microsoft.SharePoint.Client.Runtime.dll"

# Getting credentials
$loginname = "konrad.brunner@alyaconsulting.ch"
if (-Not $global:pwd) {$global:pwd = Read-Host -AsSecureString}

# Functions
function CheckWeb($web, $site)
{
    Write-Host " Web: $($web.ServerRelativeUrl)"
    $ctx.load($web.Webs)
    $ctx.load($web.Lists)
    $ctx.executeQuery()

    foreach($list in $web.Lists)
    {
        $ctx.Load($list.RootFolder)
        $ctx.ExecuteQuery()
        Write-Host "  List: $($list.RootFolder.ServerRelativeUrl)"
        $query = New-Object Microsoft.SharePoint.Client.CamlQuery
        $query.ViewXml = "<View><RowLimit>5000</RowLimit></View>"
        $items = @()
        Write-Host "   " -NoNewline
        do
        {
            $listItems = $list.getItems($query)
            $ctx.Load($listItems)
            $ctx.ExecuteQuery()
            $query.ListItemCollectionPosition = $listItems.ListItemCollectionPosition
            Write-Host "." -NoNewline
            foreach($item in $listItems)
            {
                Try
                {
                    $items += $item
                }
                Catch [System.Exception]
                {
                    Write-Host $_.Exception.Message
                }
            }
        }
        While($query.ListItemCollectionPosition -ne $null)
        Write-Host "d " -NoNewline
        Write-Host "   $($items.length) items"
        foreach($item in $items)
        {
            if ($item["ContentTypeId"] -like "0x010100F3EECCA2F7B4334E9042AB36C7C9452A*")
            {
                Write-Host "   Item: $($item['ID']), Editor: $($item['Editor'].Lookupvalue), Title: $($item['Title'])"
                foreach($user in $users)
                {
                    if ($item["Editor"].Lookupvalue -like "*$($user)*" -or $item["Author"].Lookupvalue -like "*$($user)*")
                    {
                        Write-Host "    ***FOUND***"
                        $fnd = New-Object System.Object
                        $fnd | Add-Member -MemberType NoteProperty -Name "Site" -Value $site
                        $fnd | Add-Member -MemberType NoteProperty -Name "Web" -Value $web.ServerRelativeUrl
                        $fnd | Add-Member -MemberType NoteProperty -Name "List" -Value $list.RootFolder.ServerRelativeUrl
                        $fnd | Add-Member -MemberType NoteProperty -Name "ID" -Value $item['ID']
                        $fnd | Add-Member -MemberType NoteProperty -Name "Title" -Value $item['Title']
                        $fnd | Add-Member -MemberType NoteProperty -Name "Editor" -Value $item['Editor'].Lookupvalue
                        $fnd | Add-Member -MemberType NoteProperty -Name "Author" -Value $item['Author'].Lookupvalue
                        $global:foundItems += $fnd
                    }
                }
            }
        }
    }

    # Go through all webs
    foreach($sweb in $web.Webs)
    {
        CheckWeb -web $sweb -site $site
        
    }
}

# Walking sites
$global:foundItems = @()
foreach($siteUrl in $siteUrls)
{

    # Login
    Write-Host "Site: $($siteUrl)"
    $ctx = New-Object Microsoft.SharePoint.Client.ClientContext($siteUrl)
    $ctx.Credentials = New-Object System.Net.NetworkCredential($loginname, $global:pwd)
    $ctx.load($ctx.Web)
    $ctx.executeQuery()

    CheckWeb -web $ctx.Web -site $siteUrl
}
$global:foundItems | Export-Csv -NoTypeInformation -Path "FindUserDocuments.csv" -Encoding UTF8 -Force -Confirm:$false

Stop-Transcript
