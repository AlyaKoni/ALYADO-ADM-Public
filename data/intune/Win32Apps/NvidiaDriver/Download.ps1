$driverVersion = $null
$windowsArchitecture = "64bit"
$windowsVersion1 = "win10-win11"
$windowsVersion2 = "win10"
$useNSDdriver = $true
$useDCHdriver = $true

if (-Not $driverVersion)
{
    # Get following values from https://www.nvidia.de/Download/index.aspx?lang=de
    # psid: Product Series ID (GeForce 10 Series: 101) 
    # pfid: Product ID (e.g. GeForce GTX 1080 Ti: 845)
    # osid: Operating System ID (e.g. Windows 10 64-bit: 57)
    # lid: Language ID (e.g. English (US): 1)

    #$ParentID = 11 from "https://www.nvidia.de/Download/API/lookupValueSearch.aspx"
    #$psid = 106 from "https://www.nvidia.de/Download/API/lookupValueSearch.aspx?TypeID=2&ParentID=$ParentID"
    #$pfid from "https://www.nvidia.de/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=$psid"
    #$osid from "https://www.nvidia.de/Download/API/lookupValueSearch.aspx?TypeID=4&ParentID=$psid"

    $psid = 124
    $pfid = 720
    $osid = 57
    $lid = 9
    $lang = "en-us"
    $rpf = 1
    $ctk = 0

    $link = Invoke-WebRequestIndep -Uri "https://www.nvidia.com/Download/processDriver.aspx?psid=$psid&pfid=$pfid&rpf=$rpf&osid=$osid&lid=$lid&lang=en-us&ctk=0" -Method GET -UseBasicParsing
    $link = Invoke-WebRequestIndep -Uri $link.Content -Method GET -UseBasicParsing
    $link = ($link.Links | Where-Object { $_.outerHTML.Contains("lnkDwnldBtn") }).href

    $link -match '/(\d+?\.\d+?)/' | Out-Null
    $driverVersion = $matches[1]
    Write-Host "Latest driver version: $driverVersion"
}

$versionFile = Join-Path $PSScriptRoot "version.json"
$versionObj = @{}
$versionObj.version = $driverVersion
$versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Encoding UTF8 -Force

if ($useDCHdriver)
{
    if ($useNSDdriver)
    {
        $dflt_url = "https://international.download.nvidia.com/Windows/$driverVersion/$driverVersion-desktop-$windowsVersion1-$windowsArchitecture-international-nsd-dch-whql.exe"
        $df10_url = "https://international.download.nvidia.com/Windows/$driverVersion/$driverVersion-desktop-$windowsVersion2-$windowsArchitecture-international-nsd-dch-whql.exe"
        $dFile = "$PSScriptRoot\$driverVersion-desktop-$windowsVersion-$windowsArchitecture-international-nsd-dch-whql.exe"
    }
    else
    {
        $dflt_url = "https://international.download.nvidia.com/Windows/$driverVersion/$driverVersion-desktop-$windowsVersion1-$windowsArchitecture-international-dch-whql.exe"
        $df10_url = "https://international.download.nvidia.com/Windows/$driverVersion/$driverVersion-desktop-$windowsVersion2-$windowsArchitecture-international-dch-whql.exe"
        $dFile = "$PSScriptRoot\$driverVersion-desktop-$windowsVersion-$windowsArchitecture-international-dch-whql.exe"
    }
}
else
{
    if ($useNSDdriver)
    {
        $dflt_url = "https://international.download.nvidia.com/Windows/$driverVersion/$driverVersion-desktop-$windowsVersion1-$windowsArchitecture-international-nsd-whql.exe"
        $df10_url = "https://international.download.nvidia.com/Windows/$driverVersion/$driverVersion-desktop-$windowsVersion2-$windowsArchitecture-international-nsd-whql.exe"
        $dFile = "$PSScriptRoot\$driverVersion-desktop-$windowsVersion-$windowsArchitecture-international-nsd-whql.exe"
    }
    else
    {
        $dflt_url = "https://international.download.nvidia.com/Windows/$driverVersion/$driverVersion-desktop-$windowsVersion1-$windowsArchitecture-international-whql.exe"
        $df10_url = "https://international.download.nvidia.com/Windows/$driverVersion/$driverVersion-desktop-$windowsVersion2-$windowsArchitecture-international-whql.exe"
        $dFile = "$PSScriptRoot\$driverVersion-desktop-$windowsVersion-$windowsArchitecture-international-whql.exe"
    }
}

if (-Not (Test-Path $dFile))
{
    try
    {
        Invoke-WebRequest -Uri $dflt_url -Method Get -UseBasicParsing -OutFile $dFile
    }
    catch {
        Write-Warning "win10/11 driver download failed. Trying win10"
    }
    if (-Not (Test-Path $dFile))
    {
        try
        {
            Invoke-WebRequest -Uri $df10_url -Method Get -UseBasicParsing -OutFile $dFile
        }
        catch {}
    }
    if (-Not (Test-Path $dFile))
    {
        if ($useDCHdriver -and $useNSDdriver)
        {
            throw "Driver download failed. Please try non DCH or non NSD driver"
        }
        else
        {
            if ($useDCHdriver)
            {
                throw "Driver download failed. Please try non DCH driver"
            }
            else
            {
                if ($useNSDdriver)
                {
                    throw "Driver download failed. Please try non NSD driver"
                }
                else
                {
                    throw "Driver download failed"
                }
            }
        }
    }
}
$7zip = $null
if ((Test-path HKLM:\SOFTWARE\7-Zip\) -eq $true)
{
    $7zpath = Get-ItemProperty -path  HKLM:\SOFTWARE\7-Zip\ -Name Path
    $7zpath = $7zpath.Path
    $7zpathexe = $7zpath + "7z.exe"
    if ((Test-Path $7zpathexe) -eq $true)
    {
        $7zip = $7zpathexe
    }    
}
elseif (-Not $7zip -and (Test-Path -PathType Container "C:\Programme\7-Zip"))
{
    $7zip = "C:\Program Files\7-Zip\7z.exe"
}
elseif (-Not $7zip -and (Test-Path -PathType Container "C:\Programme (x86)\7-Zip"))
{
    $7zip = "C:\Program Files\7-Zip\7z.exe"
}
elseif (-Not $7zip -and (Test-Path -PathType Container "C:\Program Files\7-Zip"))
{
    $7zip = "C:\Program Files\7-Zip\7z.exe"
}
elseif (-Not $7zip -and (Test-Path -PathType Container "C:\Program Files (x86)\7-Zip"))
{
    $7zip = "C:\Program Files\7-Zip\7z.exe"
}

if ($7zip)
{
    & $7zip x -aos $dFile Display.Driver HDAudio MSVCRT NVI2 NVPCF PhysX PPC EULA.txt ListDevices.txt setup.cfg setup.exe -o"$PSScriptRoot\Content"
}
else
{
    Write-Error "Not able to find 7zip to extract driver package!" -ErrorAction Continue
    Write-Error "Please install 7zip." -ErrorAction Continue
    exit 2
}

Remove-Item -Path $dFile -Force

# setup.exe -s -clean -noreboot -noeula

