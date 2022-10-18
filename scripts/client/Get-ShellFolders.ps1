$FD = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions'
(Get-ItemProperty (Get-ChildItem $FD).PSPath).name | sort
