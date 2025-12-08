
<# 
    Passive-Network-Enumeration.ps1
    Purpose: Read-only network posture capture from a non-admin PowerShell session.
    Scope: Network & network devices (passive). No scanning, no lateral actions.

    Output: Creates an output folder with a timestamp, saving:
      - Passive-Network-Enumeration.txt (human-readable summary)
      - Passive-Network-Enumeration.json (structured data)
      - Passive-Network-Enumeration.log (command transcript, best-effort)

    Usage:
      PS> .\Passive-Network-Enumeration.ps1
      Optional params:
        -OutDir "C:\Temp\HubEnum" 
        -ResolveHosts @("dc1.contoso.local","switch01.mgmt.local")   # safe, optional
        -SkipDNS                          # skip DNS checks if policy-sensitive
        -SkipTime                         # skip NTP/time sync checks

    Notes:
      - Designed to be safe under ConstrainedLanguageMode (CLM).
      - No admin privileges required.
      - Avoids any active scanning; only local state + optional single-host resolution.
#>

[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path -Path $PWD -ChildPath ("PassiveEnum_" + (Get-Date -Format "yyyyMMdd_HHmmss"))),
    [string[]]$ResolveHosts = @(),
    [switch]$SkipDNS,
    [switch]$SkipTime
)

# ---------- Helpers ----------
function New-SafeFolder {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
        return $true
    } catch { Write-Warning "Failed to create output folder: $($_.Exception.Message)"; return $false }
}

function Get-Safe {
    param([scriptblock]$Block)
    try { & $Block } catch { Write-Warning $($_.Exception.Message); return $null }
}

function Test-CLM {
    # Detect ConstrainedLanguageMode for awareness
    try { return ($ExecutionContext.SessionState.LanguageMode) } catch { return "Unknown" }
}

function Start-SoftTranscript {
    param([string]$Path)
    try {
        # Start-Transcript can be disabled by policy; attempt best-effort
        Start-Transcript -Path $Path -IncludeInvocationHeader -ErrorAction Stop | Out-Null
        return $true
    } catch { Write-Verbose "Transcript unavailable: $($_.Exception.Message)"; return $false }
}

# ---------- Prepare output ----------
$null = New-SafeFolder -Path $OutDir
$txtPath  = Join-Path $OutDir "Passive-Network-Enumeration.txt"
$jsonPath = Join-Path $OutDir "Passive-Network-Enumeration.json"
$logPath  = Join-Path $OutDir "Passive-Network-Enumeration.log"

$transcriptStarted = Start-SoftTranscript -Path $logPath

# ---------- Collect ----------
$results = [ordered]@{}
$results.Timestamp         = (Get-Date).ToString("o")
$results.Hostname          = $env:COMPUTERNAME
$results.User              = $env:USERNAME
$results.Domain            = $env:USERDOMAIN
$results.LanguageMode      = Test-CLM
$results.OS                = Get-Safe { (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture) }

# IP configuration
$results.NetIPConfiguration = Get-Safe { 
    Get-NetIPConfiguration | Select-Object InterfaceAlias, InterfaceDescription, IPv4Address, IPv6Address, DNSServer, DnsSuffix, NetProfile.Name, NetProfile.NetworkCategory
}

# Routes
$results.Routes = Get-Safe {
    Get-NetRoute | Sort-Object RouteMetric, DestinationPrefix |
        Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric, Protocol, Store
}

# ARP cache (Neighbors)
$results.ARP = Get-Safe {
    Get-NetNeighbor -ErrorAction SilentlyContinue | 
        Select-Object ifIndex, InterfaceAlias, IPAddress, LinkLayerAddress, State
}

# Active TCP connections (no probing)
$results.TCPConnections = Get-Safe {
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
}

# UDP endpoints (listing only; UDP is connectionless)
$results.UDPEndpoints = Get-Safe {
    Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, OwningProcess
}

# Process lookup (map PIDs to names for TCP/UDP owners)
$procIndex = @{}
Get-Safe {
    Get-Process | ForEach-Object { $procIndex["$($_.Id)"] = $_.ProcessName }
} | Out-Null
# Attach process names
if ($results.TCPConnections) {
    $results.TCPConnections | ForEach-Object { $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue ($procIndex["$($_.OwningProcess)"]) -Force }
}
if ($results.UDPEndpoints) {
    $results.UDPEndpoints | ForEach-Object { $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue ($procIndex["$($_.OwningProcess)"]) -Force }
}

# Firewall profile state (read-only)
$results.FirewallProfiles = Get-Safe {
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen, AllowInboundRules, AllowLocalFirewallRules
}

# DNS Client server addresses
if (-not $SkipDNS) {
    $results.DNSClientServers = Get-Safe {
        Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses
    }
}

# Optional DNS resolution (single queries provided by user; non-probing by default)
$results.DNSResolution = @()
if (-not $SkipDNS -and $ResolveHosts.Count -gt 0) {
    foreach ($h in $ResolveHosts) {
        $item = [ordered]@{ Host=$h; A=@(); AAAA=@(); Error=$null }
        try {
            $a    = Resolve-DnsName -Name $h -Type A -ErrorAction Stop
            $aaaa = Resolve-DnsName -Name $h -Type AAAA -ErrorAction SilentlyContinue
            $item.A     = ($a | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
            $item.AAAA  = ($aaaa | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
        } catch {
            $item.Error = $_.Exception.Message
        }
        $results.DNSResolution += $item
    }
}

# Default gateway reachability (single ping to gateway; safe)
$results.GatewayReachability = @()
$gateways = @()
try {
    $gateways = ($results.NetIPConfiguration | ForEach-Object { $_.IPv4DefaultGateway, $_.IPv6DefaultGateway } | Where-Object { $_ })
} catch { }
foreach ($gw in $gateways) {
    $gwAddr = $gw.NextHop
    if ($gwAddr) {
        $obj = [ordered]@{ Address=$gwAddr; Status="Unknown"; AvgMs=$null }
        try {
            $p = Test-Connection -Count 1 -Quiet -ComputerName $gwAddr
            $obj.Status = $(if ($p) { "Reachable" } else { "Unreachable" })
            # Optional 3-ping average for latency
            $lat = Test-Connection -Count 3 -ComputerName $gwAddr -ErrorAction SilentlyContinue
            if ($lat) { $obj.AvgMs = [math]::Round(($lat | Measure-Object -Property ResponseTime -Average).Average, 1) }
        } catch { $obj.Status = "Error: $($_.Exception.Message)" }
        $results.GatewayReachability += $obj
    }
}

# WinHTTP system proxy (affects outbound connectivity)
$results.WinHTTPProxy = Get-Safe { 
    netsh winhttp show proxy | Out-String
}

# DNS suffix search list
$results.DNSSuffixList = Get-Safe {
    Get-DnsClientGlobalSetting | Select-Object SuffixSearchList, DevolutionLevel, UseSuffixWhenRegistering
}

# Network adapters status
$results.NetAdapters = Get-Safe {
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress
}

# Time and NTP status (optional; helps spot NTP reachability issues)
if (-not $SkipTime) {
    $results.TimeInfo = [ordered]@{}
    $results.TimeInfo.Clock = Get-Safe { Get-Date | Select-Object * }
    $results.TimeInfo.W32Time = Get-Safe { w32tm /query /configuration | Out-String }
    $results.TimeInfo.W32Status = Get-Safe { w32tm /query /status | Out-String }
    $results.TimeInfo.Peers = Get-Safe { w32tm /query /peers | Out-String }
}

# Current DNS cache snapshot (read-only)
if (-not $SkipDNS) {
    $results.DNSCache = Get-Safe { ipconfig /displaydns | Out-String }
}

# ---------- Write Outputs ----------
# Human-readable summary
$summary = New-Object System.Text.StringBuilder

$append = {
    param($title, $data)
    $null = $summary.AppendLine("`n=== $title ===")
    if ($null -eq $data) {
        $null = $summary.AppendLine("[no data]")
    } elseif ($data -is [string]) {
        $null = $summary.AppendLine($data.TrimEnd())
    } else {
        $null = $summary.AppendLine(($data | Format-Table -AutoSize | Out-String).TrimEnd())
    }
}

& $append "Metadata" ([pscustomobject]$results | Select-Object Timestamp, Hostname, User, Domain, LanguageMode)
& $append "OS" $results.OS
& $append "Network Adapters" $results.NetAdapters
& $append "IP Configuration" $results.NetIPConfiguration
& $append "Routes" $results.Routes
& $append "ARP Cache" $results.ARP
& $append "TCP Connections (Established)" $results.TCPConnections
& $append "UDP Endpoints (Listening/Bound)" $results.UDPEndpoints
& $append "Firewall Profiles" $results.FirewallProfiles
if (-not $SkipDNS) {
    & $append "DNS Client Servers" $results.DNSClientServers
    if ($results.DNSResolution -and $results.DNSResolution.Count -gt 0) {
        $null = $summary.AppendLine("`n=== DNS Resolution (Requested) ===")
        foreach ($r in $results.DNSResolution) {
            $null = $summary.AppendLine("Host: $($r.Host)")
            $null = $summary.AppendLine("  A    : " + (($r.A -join ", ")  ?: "[none]"))
            $null = $summary.AppendLine("  AAAA : " + (($r.AAAA -join ", ") ?: "[none]"))
            if ($r.Error) { $null = $summary.AppendLine("  Error: $($r.Error)") }
        }
    }
    & $append "DNS Cache Snapshot" $results.DNSCache
}
& $append "Gateway Reachability" $results.GatewayReachability
& $append "WinHTTP Proxy" $results.WinHTTPProxy
& $append "DNS Global Settings" $results.DNSSuffixList
if (-not $SkipTime) {
    & $append "Time / NTP Configuration" $results.TimeInfo.W32Time
    & $append "Time / NTP Status" $results.TimeInfo.W32Status
    & $append "Time / NTP Peers" $results.TimeInfo.Peers
}

# Save summary
$summary.ToString() | Out-File -FilePath $txtPath -Encoding UTF8

# Save structured JSON (compress arrays/objects)
$results | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8

# ---------- Finish ----------
if ($transcriptStarted) {
    try { Stop-Transcript | Out-Null } catch { }
}

Write-Host "Passive enumeration complete." -ForegroundColor Green
Write-Host "Text summary:  $txtPath"
Write-Host "JSON output:   $jsonPath"
Write-Host "Transcript:    $logPath"
