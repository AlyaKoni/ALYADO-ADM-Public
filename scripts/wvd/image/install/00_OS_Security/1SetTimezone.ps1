Get-TimeZone -ListAvailable | Where-Object { $_.Id -like "*Euro*" }
Set-Timezone -Id "W. Europe Standard Time"
