if (-Not $PSScriptRoot)
{
	$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
}
$RootDir = $PSScriptRoot
$Dirs = Get-ChildItem -Path $RootDir
foreach($Dir in $Dirs)
{
	if ($Dir.GetType().Name -eq "FileInfo") {continue;}
    $Guid = "{"+[Guid]::NewGuid().ToString().ToUpper()+"}"
    Write-Host "Dir: $($Dir.Name)   NewName: $($Guid)"
    Rename-Item -Path $Dir.FullName -NewName $Guid -Force
}
