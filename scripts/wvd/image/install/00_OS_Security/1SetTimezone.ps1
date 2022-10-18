Get-TimeZone -ListAvailable | where { $_.Id -like "*Euro*" }
Set-Timezone -Id "W. Europe Standard Time"
