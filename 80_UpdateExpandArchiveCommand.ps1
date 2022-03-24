pushd $PSScriptRoot\..

$template = @"
`$cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
if (`$cmdTst)
{
    AAA
}
else
{
    BBB
}
"@
foreach($script in (Get-ChildItem -Include "*.ps1" -Recurse))
{
    if ($script.Name -eq "80_UpdateExpandArchiveCommand.ps1") { continue }
    $contentOrig = $script | Get-Content -Encoding UTF8 -Raw -Force
    if ([string]::IsNullOrEmpty($contentOrig))
    {
        Write-Warning "EMPTY $($script.FullName)"
        continue
    }
    $contentOrig = $contentOrig.Trim()
    $content = $contentOrig
    $lastIndex = 0
    $hadError = $false
    try
    {
        do
        {
            $index = $content.IndexOf("Expand-Archive", $lastIndex)
            if ($index -eq -1) { $index = $content.IndexOf("expand-archive", $lastIndex) }
            if ($index -eq -1) { $index = $content.IndexOf("Expand-archive", $lastIndex) }
            if ($index -eq -1) { $index = $content.IndexOf("expand-Archive", $lastIndex) }
            if ($index -gt -1)
            {
                $fnd = $false
                $lineStart = $index
                do
                {
                    $lineStart--
                    $fnd = $content.Substring($lineStart, 1) -eq "`n"
                } while (-Not $fnd)
                $lineStart++
                $lineEnd = $content.IndexOf("`n", $index) -1
                $orig = $content.Substring($lineStart, $lineEnd - $lineStart).Trim()
                if ($orig.IndexOf("#AlyaAutofixed") -gt -1) { 
                    $content = $contentOrig
                    $lastIndex = -1
                    break
                }
                $orig = $orig + " #AlyaAutofixed"
                $rows = $template.Split("`n")
                for ($i = 0; $i -lt $rows.Length; $i++)
                {
                    $rows[$i] = "".PadLeft(($index - $lineStart), " ") + $rows[$i]
                    $rows[$i] = $rows[$i].Replace("AAA", $orig.Replace("-OutputPath", "-DestinationPath")).Replace("BBB", $orig.Replace("-DestinationPath", "-OutputPath"))
                }
                $tmpl = $rows -join "`n"
                $content = $content.Substring(0, $lineStart) + $tmpl + $content.Substring($lineEnd, $content.Length - $lineEnd)
                $index = $index + $tmpl.Length
            }
            $lastIndex = $index
        } while ($lastIndex -gt -1)
    }
    catch
    {
        $hadError = $true
        throw
    }
    if (-Not $hadError)
    {
        $content = $content.Trim()
        if ($contentOrig -ne $content)
        {
            Write-Host "DONE  $($script.FullName)"
            $content | Set-Content -Path $script.FullName -Encoding UTF8 -Force
        }
    }
    else
    {
        Write-Warning "ERROR $($script.FullName)"
    }
}

popd
