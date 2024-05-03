$root = $PSScriptRoot

$7zip = $null
if ((Test-path HKLM:\SOFTWARE\7-Zip\) -eq $true)
{
    $7zpath = Get-ItemProperty -path  HKLM:\SOFTWARE\7-Zip\ -Name Path
    $7zpath = $7zpath.Path
    $7zpathexe = $7zpath + "7z.exe"
    if ((Test-Path $7zpathexe) -eq $true)
    {
        $7zip = $7zpathexe
    }    
}
elseif (-Not $7zip -and (Test-Path -PathType Container "C:\Programme\7-Zip"))
{
    $7zip = "C:\Program Files\7-Zip\7z.exe"
}
elseif (-Not $7zip -and (Test-Path -PathType Container "C:\Programme (x86)\7-Zip"))
{
    $7zip = "C:\Program Files\7-Zip\7z.exe"
}
elseif (-Not $7zip -and (Test-Path -PathType Container "C:\Program Files\7-Zip"))
{
    $7zip = "C:\Program Files\7-Zip\7z.exe"
}
elseif (-Not $7zip -and (Test-Path -PathType Container "C:\Program Files (x86)\7-Zip"))
{
    $7zip = "C:\Program Files\7-Zip\7z.exe"
}
$7zip

function Process($parentDir)
{
    $dirs = Get-ChildItem -Path $parentDir -Directory
    $cnt = 0
    foreach($dir in $dirs)
    {
        $cnt++
        Rename-Item -Path $dir.FullName -NewName $cnt
        Process -parentDir $dir.FullName.Replace($dir.Name, $cnt)
    }
    $files = Get-ChildItem -Path $parentDir -File
    foreach($file in $files)
    {
        if ($file.Name.EndsWith(".dmg") -or $file.Name.EndsWith(".pkg"))
        {
            $cnt++
            $dir = Join-Path $parentDir $cnt
            New-Item -Path $dir -ItemType Directory
            & $7zip x -aos "$($file.FullName)" -o"$dir"
            if ($parentDir -ne $root)
            {
                Remove-Item -Path $file.FullName
            }
            Process -parentDir $dir
        }
    }
}

Process -parentDir $root