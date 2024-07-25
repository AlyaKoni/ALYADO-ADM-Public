Add-Type -AssemblyName System.Web
$tenant = $null
$tenants = @()
foreach($par in (Get-ChildItem HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts)) {
    $tenantId = $null
    $tenantName = $null
    $serviceEndpointUri = $null
    if (-Not $par.Name.EndsWith("Personal"))
    {
        $tenantId = Get-ItemPropertyValue -Path $par.PSPath -Name "ConfiguredTenantId" -ErrorAction SilentlyContinue
        $tenantName = Get-ItemPropertyValue -Path $par.PSPath -Name "DisplayName" -ErrorAction SilentlyContinue
        $serviceEndpointUri = Get-ItemPropertyValue -Path $par.PSPath -Name "ServiceEndpointUri" -ErrorAction SilentlyContinue
    }
    $userFolder = Get-ItemPropertyValue -Path $par.PSPath -Name "UserFolder" -ErrorAction SilentlyContinue
	$userEmail = Get-ItemPropertyValue -Path $par.PSPath -Name "UserEmail" -ErrorAction SilentlyContinue
	$cid = Get-ItemPropertyValue -Path $par.PSPath -Name "cid" -ErrorAction SilentlyContinue
    $bname = $par.PSChildName
    $tenants += @{
        tenantId = $tenantId
        tenantName = $tenantName
        serviceEndpointUri = $serviceEndpointUri
        userFolder = $userFolder
        userEmail = $userEmail
        businessName = $bname
        cid = $cid
    }
}
if ($tenants.Count -eq 0) {
    Write-Warning "No OneDrive configuration found. Please sync one SharePoint site and restart script."
    exit
}
if ($tenants.Count -gt 1) {
	$tenantName = $tenants.tenantName | Out-GridView -Title "Pleas select the tenant" -OutputMode Single
    if (-not $tenantName) {
        Write-Warning "No tenant selected."
        exit
    }
    $tenant = $tenants | Where-Object { $_.tenantName -eq $tenantName }
}
else {
    $tenant = $tenants[0]
}

$iniFile = "$($env:LOCALAPPDATA)\Microsoft\OneDrive\settings\$($tenant.businessName)\$($tenant.cid).ini"
$iniContent = Get-Content -Path $iniFile -Encoding unicode
Write-Host "`$odopens = @(" -ForegroundColor DarkCyan
$first = $true
foreach($line in $iniContent) {
    $values = @()
    if ($line.Contains("libraryScope =")) {
        $prts = $line.Split(" ")
        $addTo = -1
        foreach($prt in $prts) {
            if ($addTo -eq -1 -and -Not $prt.Contains("`"")) {
                $values += $prt
                $addTo = -1
            } else {
                if ($addTo -eq -1 -and $prt.StartsWith("`"") -and $prt.EndsWith("`"")) {
                    $values += $prt
                    $addTo = -1
                } else {
                    if ($addTo -gt -1) {
                        $values[$addTo] += " " + $prt
                        if ($prt.EndsWith("`"")) { $addTo = -1 }
                    } else {
                        $values += $prt
                        $addTo = $values.Length - 1
                    }
                }
            }
        }
    }
    if ($values.Count -gt 14) {
        $title = $values[5].Trim("`"")
        $list = $values[6].Trim("`"")
        $uri = $values[8].Trim("`"")
        $siteId = $values[10].Trim("`"")
        $webId = $values[11].Trim("`"")
        $listId = $values[12].Trim("`"")
        #$path = $values[14].Trim("`"")
        $mail = [System.Web.HttpUtility]::UrlEncode($tenant.userEmail)
        if (-Not $uri.Contains("/personal/")) {
            if (-Not $first) {
                Write-Host "," -ForegroundColor DarkYellow
            }
            $first = $false
            Write-Host "    #$title - $list - $uri" -ForegroundColor DarkGreen
            $title = [System.Web.HttpUtility]::UrlEncode($title)
            $list = [System.Web.HttpUtility]::UrlEncode($list)
            $uri = [System.Web.HttpUtility]::UrlEncode($uri)
            Write-Host "    `"odopen://sync?siteId=%7b$siteId%7d&webId=%7b$webId%7d&listId=%7b$listId%7d&userEmail=$mail&webUrl=$uri&webTitle=$title&listTitle=$list&scope=OPENLIST`"" -ForegroundColor DarkYellow -NoNewline
        }
    }
}
Write-Host "`n)" -ForegroundColor DarkCyan
Write-Host "foreach (`$odopen in `$odopens) {" -ForegroundColor DarkCyan
Write-Host "    Start-Process `$odopen" -ForegroundColor DarkCyan
Write-Host "    Start-Sleep -Seconds 10" -ForegroundColor DarkCyan
Write-Host "}" -ForegroundColor DarkCyan

