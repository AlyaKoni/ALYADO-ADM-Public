$apps = (Get-Content -Path "$PsScriptRoot\Configuration\Applications\intuneApplications.json" -Raw -Encoding UTF8 | ConvertFrom-Json).value
$apps = $apps | Where-Object { $_.isAssigned -eq $true }
$apps | Foreach-Object { 
    $_.PSObject.Properties.Remove("id")
    $_.PSObject.Properties.Remove("createdDateTime")
    $_.PSObject.Properties.Remove("lastModifiedDateTime")
    $_.PSObject.Properties.Remove("isAssigned")
    $_.PSObject.Properties.Remove("dependentAppCount")
    $_.PSObject.Properties.Remove("supersedingAppCount")
    $_.PSObject.Properties.Remove("supersededAppCount")
    $_.PSObject.Properties.Remove("usedLicenseCount")
    $_.PSObject.Properties.Remove("totalLicenseCount")
    $_.PSObject.Properties.Remove("isPrivate")
    $_.PSObject.Properties.Remove("isSystemApp")
    $_.PSObject.Properties.Remove("supportsOemConfig")
    $_.PSObject.Properties.Remove("appAvailability")
    $_.PSObject.Properties.Remove("version")
    $_.PSObject.Properties.Remove("publishingState")
    $_.PSObject.Properties.Remove("committedContentVersion")
    $_.PSObject.Properties.Remove("uploadState")
}
$apps | Where-Object { $_."@odata.type" -eq "#microsoft.graph.androidManagedStoreApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-androidManagedStoreApps.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#microsoft.graph.managedAndroidStoreApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-managedAndroidStoreApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#microsoft.graph.managedIOSStoreApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-managedIOSStoreApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#microsoft.graph.iosStoreApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-iosStoreApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#microsoft.graph.microsoftStoreForBusinessApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-microsoftStoreForBusinessApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#microsoft.graph.macOSMdatpApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-macOSMdatpApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#microsoft.graph.macOSOfficeSuiteApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-macOSOfficeSuiteApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#microsoft.graph.macOSMicrosoftEdgeApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-macOSMicrosoftEdgeApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#microsoft.graph.webApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-webApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#microsoft.graph.win32LobApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-win32LobApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#microsoft.graph.officeSuiteApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-officeSuiteApp.json" -encoding UTF8 -Force
$apps | Where-Object { $_."@odata.type" -eq "#microsoft.graph.windowsMicrosoftEdgeApp"} | ConvertTo-Json -Depth 50 | Set-Content -Path "$PsScriptRoot\exp-windowsMicrosoftEdgeApp.json" -encoding UTF8 -Force
