$dom = "google.com"
$server = "8.8.8.8"

function Rsolve-Spf($spf)
{
    Write-Host "Resolving $spf"
    $recs = Resolve-DnsName -Type TXT -Server $server -Name $spf
    foreach($rec in $recs)
    {
        if ($rec.Strings -like "*v=spf*")
        {
            $strs = $rec.Strings.Split()
            foreach($str in $strs)
            {
                if ($str -ne "v=spf1" -and $str -ne "~all" -and $str -ne "-all")
                {
                    if ($str -like "include:*")
                    {
                        $inc = $str.Replace("include:","")
                        Rsolve-Spf -spf $inc
                    }
                    else
                    {
                        if ($str -eq "mx" -or $str -eq "+mx")
                        {
                            $mxs = Resolve-DnsName -Type MX -Server $server -Name $spf
                            foreach($mx in $mxs)
                            {
                                $ips = Resolve-DnsName -Type A -Server $server -Name $mx.NameExchange
                                foreach($ip in $ips)
                                {
                                    if ($ip.DataLength -eq 4)
                                    {
                                        $ip = $ip.IPAddress + "/32"
                                        Write-Host "  Found ip4 $ip"
                                        $script:ipv4 += $ip
                                    }
                                    else
                                    {
                                        $ip = $ip.IPAddress
                                        Write-Host "  Found ip6 $ip"
                                        $script:ipv6 += $ip + "/32"
                                    }
                                }
                            }
                        }
                        elseif ($str -eq "a" -or $str -eq "+a")
                        {
                            $ips = Resolve-DnsName -Type A -Server $server -Name $spf
                            foreach($ip in $ips)
                            {
                                if ($ip.DataLength -eq 4)
                                {
                                    $ip = $ip.IPAddress + "/32"
                                    Write-Host "  Found ip4 $ip"
                                    $script:ipv4 += $ip
                                }
                                else
                                {
                                    $ip = $ip.IPAddress
                                    Write-Host "  Found ip6 $ip"
                                    $script:ipv6 += $ip + "/32"
                                }
                            }
                        }
                        elseif ($str.StartsWith("ip4:") -or $str.StartsWith("+ip4:"))
                        {
                            $ip = $str.Replace("+ip4:","").Replace("ip4:","")
                            Write-Host "  Found ip4 $ip"
                            $script:ipv4 += $ip
                        }
                        elseif ($str.StartsWith("ip6:") -or $str.StartsWith("+ip6:"))
                        {
                            $ip = $str.Replace("+ip6:","").Replace("ip6:","")
                            Write-Host "  Found ip6 $ip"
                            $script:ipv6 += $ip
                        }
                        else
                        {
                            Write-Warning "Please handle $str"
                        }
                    }
                }
            }
        }
    }
}

Write-Host "Getting SPF mail hosters from domain $dom on server $server"
$script:ipv4 = @()
$script:ipv6 = @()
Rsolve-Spf -spf $dom
Write-Host "`nIP v4 ranges:"
$script:ipv4
Write-Host "`nIP v6 ranges:"
$script:ipv6
