<#

Get-AppxPackage | Where-Object {$_.PackageFullName -like "Microsoft.LanguageExperiencePack*"}
Get-AppxPackage | Where-Object {$_.PackageFullName -like "AdobeNotificationClient_*"}
Get-AppxPackage | Where-Object {$_.PackageFullName -like "Adobe.CC.XD_*"}
Get-AppxPackage | Where-Object {$_.PackageFullName -like "Adobe.Fresco_*" }
Get-AppxPackage | Where-Object {$_.PackageFullName -like "InputApp_*" }
Get-AppxPackage | Where-Object {$_.PackageFullName -like "Microsoft.PPIProjection_*" }

Get-AppxPackage -AllUsers | Where-Object {$_.PackageFullName -like "Microsoft.LanguageExperiencePack*"}
Get-AppxPackage -AllUsers | Where-Object {$_.PackageFullName -like "AdobeNotificationClient_*"}
Get-AppxPackage -AllUsers | Where-Object {$_.PackageFullName -like "Adobe.CC.XD_*"}
Get-AppxPackage -AllUsers | Where-Object {$_.PackageFullName -like "Adobe.Fresco_*" }
Get-AppxPackage -AllUsers | Where-Object {$_.PackageFullName -like "InputApp_*" }
Get-AppxPackage -AllUsers | Where-Object {$_.PackageFullName -like "Microsoft.PPIProjection_*" }

#>

Get-AppxPackage -AllUsers | Where-Object {$_.PackageFullName -like "Microsoft.LanguageExperiencePack*"} | Remove-AppxPackage
Get-AppxPackage -AllUsers | Where-Object {$_.PackageFullName -like "AdobeNotificationClient_*"} | Remove-AppxPackage
Get-AppxPackage -AllUsers | Where-Object {$_.PackageFullName -like "Adobe.CC.XD_*"} | Remove-AppxPackage
Get-AppxPackage -AllUsers | Where-Object {$_.PackageFullName -like "Adobe.Fresco_*" } | Remove-AppxPackage
Get-AppxPackage -AllUsers | Where-Object {$_.PackageFullName -like "InputApp_*" } | Remove-AppxPackage
Get-AppxPackage -AllUsers | Where-Object {$_.PackageFullName -like "Microsoft.PPIProjection_*" } | Remove-AppxPackage

cmd /c "$Env:SystemRoot\system32\sysprep\sysprep.exe" /generalize /oobe /shutdown
