if (-Not $PSScriptRoot)
{
	$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
}
$RootDir = $PSScriptRoot
$Dirs = Get-ChildItem -Path $RootDir
foreach($Dir in $Dirs)
{
	if ($Dir.GetType().Name -eq "FileInfo") {continue;}
    $Rep = [XML](Get-Content -Path ($Dir.FullName+"\gpreport.xml") -Encoding UTF8)
    $Name = $Rep.GPO.Name.Trim()
    Write-Host "Dir: $($Dir.Name)   NewName: $($Name)"
    Rename-Item -Path $Dir.FullName -NewName $Name -Force
}
