#Requires -Version 2

<#
    Copyright (c) Alya Consulting, 2019-2024

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    Die Alya Basis Konfiguration ist eine Freie Software: Sie können sie unter den
    Bedingungen der GNU General Public License, wie von der Free Software
    Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veröffentlichten Version, weiter verteilen und/oder modifizieren.
    Die Alya Basis Konfiguration wird in der Hoffnung, dass sie nützlich sein wird,
    aber OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
    https://www.gnu.org/licenses/gpl-3.0.txt


#>

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
