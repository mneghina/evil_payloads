
$ts=Get-Date -Format "yyyyMMdd_HHmmss"; $outDir = (Test-Path 'C:\Users\Skype\assessment_pt\') ? 'C:\Users\Skype\assessment_pt' : $env:TEMP; $out="$outDir\PassiveEnum_$ts.txt"; 
"=== Passive Network Enumeration ($([Environment]::MachineName)) @ $(Get-Date -Format o) ===" | Out-File -FilePath $out -Encoding UTF8; 
"`n--- IP Configuration ---" | Tee-Object -FilePath $out -Append | Out-Null; 
(Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue) ? (Get-NetIPConfiguration | Format-Table -Auto | Out-String | Out-File $out -Append) : (ipconfig /all | Out-File $out -Append); 
"`n--- Routes ---" | Out-File $out -Append; 
(Get-Command Get-NetRoute -ErrorAction SilentlyContinue) ? (Get-NetRoute | Sort-Object RouteMetric,DestinationPrefix | Format-Table -Auto | Out-String | Out-File $out -Append) : (route print | Out-File $out -Append); 
"`n--- ARP Cache ---" | Out-File $out -Append; 
(Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) ? (Get-NetNeighbor | Format-Table -Auto | Out-String | Out-File $out -Append) : (arp -a | Out-File $out -Append); 
"`n--- TCP Connections (Established) ---" | Out-File $out -Append; 
(Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) ? (Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Format-Table -Auto | Out-String | Out-File $out -Append) : (netstat -ano | Out-File $out -Append); 
"`n--- UDP Endpoints ---" | Out-File $out -Append; 
(Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) ? (Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -Auto | Out-String | Out-File $out -Append) : ("[fallback via netstat above] " | Out-File $out -Append); 
"`n--- Firewall Profiles ---" | Out-File $out -Append; 
(Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) ? (Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,NotifyOnListen,AllowInboundRules,AllowLocalFirewallRules | Format-Table -Auto | Out-String | Out-File $out -Append) : ("[Get-NetFirewallProfile not available]" | Out-File $out -Append); 
"`n--- DNS Client Servers ---" | Out-File $out -Append; 
(Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue) ? (Get-DnsClientServerAddress | Select-Object InterfaceAlias,ServerAddresses | Format-Table -Auto | Out-String | Out-File $out -Append) : ("[Get-DnsClientServerAddress not available]" | Out-File $out -Append); 
"`n--- DNS Global Settings ---" | Out-File $out -Append; 
(Get-Command Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue) ? (Get-DnsClientGlobalSetting | Select-Object SuffixSearchList,DevolutionLevel,UseSuffixWhenRegistering | Format-Table -Auto | Out-String | Out-File $out -Append) : ("[Get-DnsClientGlobalSetting not available]" | Out-File $out -Append); 
"`n--- DNS Cache Snapshot ---" | Out-File $out -Append; 
(ipconfig /displaydns | Out-String | Out-File $out -Append); 
"`n--- WinHTTP Proxy ---" | Out-File $out -Append; 
(netsh winhttp show proxy | Out-File $out -Append); 
"`n--- Network Adapters ---" | Out-File $out -Append; 
(Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) ? (Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress | Format-Table -Auto | Out-String | Out-File $out -Append) : ("[Get-NetAdapter not available]" | Out-File $out -Append); 
"`n--- Default Gateway Reachability (1 ping) ---" | Out-File $out -Append; 
try {
  $gws = (Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue) ? ((Get-NetIPConfiguration).IPv4DefaultGateway + (Get-NetIPConfiguration).IPv6DefaultGateway) : @(); 
  foreach ($gw in ($gws | Where-Object { $_ -and $_.NextHop })) { $addr=$gw.NextHop; $ok = Test-Connection -Count 1 -Quiet -ErrorAction SilentlyContinue -ComputerName $addr; 
    "Gateway $addr : " + ($(if($ok){"Reachable"}else{"Unreachable"})) | Out-File $out -Append 
  } 
} catch { "[gateway check error: $($_.Exception.Message)]" | Out-File $out -Append } ; 
"`n--- Time / NTP (w32tm) ---" | Out-File $out -Append; 
(w32tm /query /configuration | Out-File $out -Append); 
(w32tm /query /status | Out-File $out -Append); 
(w32tm /query /peers | Out-File $out -Append); 
"`n[Output saved to] $out" | Out-File $out -Append; 
Write-Host "Done. Output: $out" -ForegroundColor Green
