Install-Module "Microsoft.Graph.Authentication" -Scope CurrentUser
Install-Module "LAPS" -Scope CurrentUser
Connect-MgGraph -Scopes "Device.Read.All","DeviceLocalCredential.Read.All","DeviceManagementManagedDevices.Read.All"
Get-LapsAADPassword -DeviceIds $env:COMPUTERNAME -IncludePasswords -AsPlainText
