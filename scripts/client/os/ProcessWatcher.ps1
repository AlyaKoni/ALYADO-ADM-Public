#PowerShell.exe -windowstyle hidden -File "C:\Alya\OneDrive - Alya Consulting Inh. Konrad Brunner\Desktop\SystemWatcher.ps1"

$ErrorActionPreference = "Stop"

try
{

    $ignoreProcesses = @("Teams")
    $oldProcs = Get-Process
    $file = New-TemporaryFile
    $header = "Type;Time;ProcessName;PID;MainWindowTitle;SessionId;LoadUserProfile;FileName;WindowStyle;ExitTime;StartTime;TotalProcessorTime;Description;Path;Product;ProductVersion"
    $header | Add-Content -Path ($file.FullName+".csv") -Force

    Write-Host "Reporting to $file"

    function Get-ServiceNameByProcessId($procName, $procId)
    {
        if ($procName -eq "svchost")
        {
            $services = tasklist /svc /fi "imagename eq $procName.exe"
            foreach($srvc in $services)
            {
                $pn = $srvc.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)[0]
                $pi = $srvc.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)[1]
                $sn = $srvc.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)[2]
                if ($pn -eq "$procName.exe" -and $pi -eq $procId)
                {
                   return $sn
                }
            }
        }
        else
        {
            return $procName
        }
    }

    function Get-ReportObject($proc,$type)
    {
        $PName = $proc.ProcessName
        if ($type -ne "Stop")
        {
            if ($proc.ProcessName -eq "svchost")
            {
                $PName = $proc.ProcessName+"|"+(Get-ServiceNameByProcessId -procName "svchost" -procId $proc.Id)
            }
        }
        return [PSCustomObject]@{
            Type = $type
            Time = Get-Date
            ProcessName = $PName
            PID = $proc.Id
            MainWindowTitle = $proc.MainWindowTitle
            SessionId = $proc.SessionId
            LoadUserProfile = $proc.StartInfo.LoadUserProfile
            FileName = $proc.StartInfo.FileName
            WindowStyle = $proc.StartInfo.WindowStyle
            ExitTime = $proc.ExitTime
            StartTime = $proc.StartTime
            TotalProcessorTime = $proc.TotalProcessorTime
            Description = $proc.Description
            Path = $proc.Path
            Product = $proc.Product
            ProductVersion = $proc.ProductVersion
        }
    }

    while ($true)
    {
        $newProcs = Get-Process
        foreach($proc in $newProcs)
        {
            $fnd = $oldProcs | where { $_.Id -eq $proc.Id }
            if (-Not $fnd)
            {
                if ($ignoreProcesses -notcontains $proc.ProcessName)
                {
                    $obj = Get-ReportObject -proc $proc -type "Start"
                    $obj | Add-Content -Path $file -Force
                    $obj | ConvertTo-Csv -Delimiter ";" -NoTypeInformation | Select -Last 1 | Add-Content -Path ($file.FullName+".csv") -Force
                }
            }
        }
        foreach($proc in $oldProcs)
        {
            $fnd = $newProcs | where { $_.Id -eq $proc.Id }
            if (-Not $fnd)
            {
                if ($ignoreProcesses -notcontains $proc.ProcessName)
                {
                    $obj = Get-ReportObject -proc $proc -type "Stop"
                    $obj | Add-Content -Path $file -Force
                    $obj | ConvertTo-Csv -Delimiter ";" -NoTypeInformation | Select -Last 1 | Add-Content -Path ($file.FullName+".csv") -Force
                }
            }
        }
        $oldProcs = $newProcs
        Start-Sleep -Seconds 5
    }

}
catch
{
    $_.Exception
    Start-Sleep -Seconds 60
    exit 1
}