Get-ADDomain
Set-ADAccountPassword -Identity cloud.test -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "XXXX" -Force)
Get-ADGroup  -Filter "samAccountName -like '*XXXXX*'" -Properties *
(Get-ADGroup XXXX -Properties *).Members
Get-ADUser  -Filter "samAccountName -eq 'XXXXX'" -Properties *
Get-ADUser  -Filter "samAccountName -like '*XXXXX*'" -Properties *
Get-ADUser -Filter { UserPrincipalName -like '*' -and ObjectClass -eq "user" -and Enabled -eq $true }
(Get-ADUser -Filter "samAccountName -like '*XXXXX*'" -Properties *).UserPrincipalName
Set-ADUser -Identity $user.samAccountName -UserPrincipalName 'first.last@alyaconsulting.ch'
Start-ADSyncSyncCycle -PolicyType Delta
(Get-ADRootDSE ).namingContexts
