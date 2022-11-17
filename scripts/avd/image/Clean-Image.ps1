<#

Get-AppxPackage | where {$_.PackageFullName -like "Microsoft.LanguageExperiencePack*"}
Get-AppxPackage | where {$_.PackageFullName -like "AdobeNotificationClient_*"}
Get-AppxPackage | where {$_.PackageFullName -like "Adobe.CC.XD_*"}
Get-AppxPackage | where {$_.PackageFullName -like "Adobe.Fresco_*" }
Get-AppxPackage | where {$_.PackageFullName -like "InputApp_*" }
Get-AppxPackage | where {$_.PackageFullName -like "Microsoft.PPIProjection_*" }

Get-AppxPackage -AllUsers | where {$_.PackageFullName -like "Microsoft.LanguageExperiencePack*"}
Get-AppxPackage -AllUsers | where {$_.PackageFullName -like "AdobeNotificationClient_*"}
Get-AppxPackage -AllUsers | where {$_.PackageFullName -like "Adobe.CC.XD_*"}
Get-AppxPackage -AllUsers | where {$_.PackageFullName -like "Adobe.Fresco_*" }
Get-AppxPackage -AllUsers | where {$_.PackageFullName -like "InputApp_*" }
Get-AppxPackage -AllUsers | where {$_.PackageFullName -like "Microsoft.PPIProjection_*" }

#>

Get-AppxPackage -AllUsers | where {$_.PackageFullName -like "Microsoft.LanguageExperiencePack*"} | Remove-AppxPackage
Get-AppxPackage -AllUsers | where {$_.PackageFullName -like "AdobeNotificationClient_*"} | Remove-AppxPackage
Get-AppxPackage -AllUsers | where {$_.PackageFullName -like "Adobe.CC.XD_*"} | Remove-AppxPackage
Get-AppxPackage -AllUsers | where {$_.PackageFullName -like "Adobe.Fresco_*" } | Remove-AppxPackage
Get-AppxPackage -AllUsers | where {$_.PackageFullName -like "InputApp_*" } | Remove-AppxPackage
Get-AppxPackage -AllUsers | where {$_.PackageFullName -like "Microsoft.PPIProjection_*" } | Remove-AppxPackage

& "$Env:SystemRoot\system32\sysprep\sysprep.exe" /generalize /oobe /shutdown
