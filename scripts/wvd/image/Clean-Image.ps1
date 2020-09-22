(Get-AppxPackage | where {$_.PackageFullName -like "Microsoft.LanguageExperiencePack*"}) | Remove-AppxPackage
Get-AppxPackage | where {$_.PackageFullName -like "AdobeNotificationClient_*"} | Remove-AppxPackage
Get-AppxPackage | where {$_.PackageFullName -like "Adobe.CC.XD_*"} | Remove-AppxPackage
Get-AppxPackage | where {$_.PackageFullName -like "Adobe.Fresco_*" } | Remove-AppxPackage
