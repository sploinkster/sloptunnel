$ErrorActionPreference = "Continue"

$root = "C:\sloptunnel-lab"
$log = Join-Path $root "ics-result.txt"
$stdout = Join-Path $root "ics-vpn.out"
$stderr = Join-Path $root "ics-vpn.err"
$wanMac = "52-54-00-12-34-56"
$lanMac = "52-54-00-65-43-21"

New-Item -ItemType Directory -Force -Path $root | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue $log, $stdout, $stderr

function Add-Log($text) {
  $line = "$(Get-Date -Format o) $text"
  Add-Content -Path $log -Value $line -Encoding ascii
}

function Copy-IfExists($src, $dst) {
  if (Test-Path $src) {
    Copy-Item -Force $src $dst
    return $true
  }
  return $false
}

function Install-Payload {
  $exeInstalled = $false
  $tokenInstalled = $false
  $wintunInstalled = $false
  $candidates = @()

  $scriptPayload = Join-Path $PSScriptRoot "payload"
  if (Test-Path $scriptPayload) {
    $candidates += $scriptPayload
  }
  foreach ($d in Get-PSDrive -PSProvider FileSystem) {
    $candidates += (Join-Path $d.Root "payload")
    $candidates += $d.Root
  }

  foreach ($dir in $candidates | Select-Object -Unique) {
    if (!$dir -or !(Test-Path $dir)) {
      continue
    }
    if (!$exeInstalled) {
      foreach ($name in @("sloptunnel-new.exe", "sloptunnel.exe")) {
        $src = Join-Path $dir $name
        if (Copy-IfExists $src (Join-Path $root "sloptunnel.exe")) {
          Add-Log "installed sloptunnel.exe from $src"
          $exeInstalled = $true
          break
        }
      }
    }
    if (!$tokenInstalled) {
      $src = Join-Path $dir "token.txt"
      if (Copy-IfExists $src (Join-Path $root "token.txt")) {
        Add-Log "installed token.txt from $src"
        $tokenInstalled = $true
      }
    }
    if (!$wintunInstalled) {
      $src = Join-Path $dir "wintun.dll"
      if (Copy-IfExists $src (Join-Path $root "wintun.dll")) {
        Add-Log "installed wintun.dll from $src"
        $wintunInstalled = $true
      }
    }
  }

  if (Test-Path (Join-Path $root "sloptunnel.exe")) {
    $hash = Get-FileHash -Algorithm SHA256 (Join-Path $root "sloptunnel.exe")
    Add-Log "sloptunnel.exe sha256=$($hash.Hash)"
  } else {
    Add-Log "missing sloptunnel.exe after payload install"
  }
  if (!(Test-Path (Join-Path $root "token.txt"))) {
    Add-Log "missing token.txt after payload install"
  }
}

function Get-ResultRoot {
  foreach ($d in Get-PSDrive -PSProvider FileSystem) {
    $marker = Join-Path $d.Root "SLOPTUNNEL_RESULTS.txt"
    if (Test-Path $marker) {
      return $d.Root
    }
  }
  return $null
}

function Copy-Results($name) {
  $resultRoot = Get-ResultRoot
  if (!$resultRoot) {
    return
  }
  Copy-Item -Force $log (Join-Path $resultRoot "ics-result.txt")
  foreach ($file in @("ics-vpn.out", "ics-vpn.err")) {
    $src = Join-Path $root $file
    if (Test-Path $src) {
      Copy-Item -Force $src (Join-Path $resultRoot $file)
    }
  }
  if ($name) {
    $name | Set-Content -Path (Join-Path $resultRoot "$name.txt") -Encoding ascii
  }
}

function Try-EnableIcs($publicName, $privateName) {
  try {
    $share = New-Object -ComObject HNetCfg.HNetShare
    $publicConn = $null
    $privateConn = $null
    foreach ($conn in $share.EnumEveryConnection()) {
      $props = $share.NetConnectionProps($conn)
      Add-Log "ICS candidate name=$($props.Name) device=$($props.DeviceName)"
      if ($props.Name -eq $publicName) {
        $publicConn = $conn
      }
      if ($props.Name -eq $privateName) {
        $privateConn = $conn
      }
    }
    if (!$publicConn -or !$privateConn) {
      Add-Log "ICS COM did not find both adapters"
      return $false
    }
    $pubCfg = $share.INetSharingConfigurationForINetConnection($publicConn)
    $privCfg = $share.INetSharingConfigurationForINetConnection($privateConn)
    if ($pubCfg.SharingEnabled) { $pubCfg.DisableSharing() }
    if ($privCfg.SharingEnabled) { $privCfg.DisableSharing() }
    Start-Sleep -Seconds 2
    $pubCfg.EnableSharing(0)
    $privCfg.EnableSharing(1)
    Add-Log "ICS COM enabled public=$publicName private=$privateName"
    return $true
  } catch {
    Add-Log "ICS COM failed: $($_.Exception.Message)"
    return $false
  }
}

Add-Log "sloptunnel ICS lab starting"
Add-Log "computer=$env:COMPUTERNAME user=$env:USERNAME"
Install-Payload
if (!(Test-Path (Join-Path $root "sloptunnel.exe")) -or
    !(Test-Path (Join-Path $root "token.txt"))) {
  Add-Log "required payload missing; aborting"
  Copy-Results "ERROR"
  shutdown.exe /s /t 5 /f
  exit 1
}
Add-Log "adapter listing before config"
Get-NetAdapter -IncludeHidden | Out-String | Out-File -Append -FilePath $log -Encoding ascii

$wan = Get-NetAdapter | Where-Object { $_.MacAddress -eq $wanMac } | Select-Object -First 1
$lan = Get-NetAdapter | Where-Object { $_.MacAddress -eq $lanMac } | Select-Object -First 1
if (!$wan -or !$lan) {
  Add-Log "failed to find expected adapters wan=$wanMac lan=$lanMac"
  Copy-Results "ERROR"
  shutdown.exe /s /t 5 /f
  exit 1
}

Rename-NetAdapter -Name $wan.Name -NewName "slop-wan" -ErrorAction SilentlyContinue
Rename-NetAdapter -Name $lan.Name -NewName "slop-lan" -ErrorAction SilentlyContinue
$wan = Get-NetAdapter -Name "slop-wan"
$lan = Get-NetAdapter -Name "slop-lan"

Set-NetIPInterface -InterfaceIndex $wan.ifIndex -Dhcp Disabled -ErrorAction SilentlyContinue
Get-NetIPAddress -InterfaceIndex $wan.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
Get-NetRoute -InterfaceIndex $wan.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
  Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceIndex $wan.ifIndex -IPAddress "10.210.0.50" -PrefixLength 24 -DefaultGateway "10.210.0.1" -ErrorAction SilentlyContinue | Out-Null
Set-DnsClientServerAddress -InterfaceIndex $wan.ifIndex -ServerAddresses "10.210.0.1" -ErrorAction SilentlyContinue
Get-NetIPAddress -InterfaceIndex $lan.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceIndex $lan.ifIndex -IPAddress "192.168.137.1" -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null
Set-DnsClientServerAddress -InterfaceIndex $lan.ifIndex -ServerAddresses "1.1.1.1" -ErrorAction SilentlyContinue
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name IPEnableRouter -Value 1
Set-NetIPInterface -InterfaceIndex $wan.ifIndex -Forwarding Enabled -ErrorAction SilentlyContinue
Set-NetIPInterface -InterfaceIndex $lan.ifIndex -Forwarding Enabled -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False -ErrorAction SilentlyContinue

$icsEnabled = $false
Set-Service SharedAccess -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service SharedAccess -ErrorAction SilentlyContinue
$icsEnabled = Try-EnableIcs "slop-wan" "slop-lan"
if (!$icsEnabled) {
  Add-Log "falling back to WinNAT for private LAN"
  Get-NetNat -Name "slopICS" -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false
  New-NetNat -Name "slopICS" -InternalIPInterfaceAddressPrefix "192.168.137.0/24" | Out-Null
}

Add-Log "network after sharing config"
ipconfig /all | Out-File -Append -FilePath $log -Encoding ascii
route print -4 | Out-File -Append -FilePath $log -Encoding ascii
Get-NetIPInterface -AddressFamily IPv4 | Sort-Object InterfaceAlias | Out-String | Out-File -Append -FilePath $log -Encoding ascii
Get-NetNat | Out-String | Out-File -Append -FilePath $log -Encoding ascii
Copy-Results "ICS_READY"
Start-Sleep -Seconds 25

$serverIp = "18.219.84.252"
$resolverIp = "10.210.0.1"
$args = @(
  "--client",
  "--transport", "tcp+dns",
  "--ports", "5223",
  "--server-ip", $serverIp,
  "--dns-tunnel-domain", "sploinkstersploinkster.online",
  "--dns-resolver", $resolverIp,
  "--token-file", (Join-Path $root "token.txt"),
  "--tun-name", "slopics0",
  "--no-ipv6",
  "--headless"
)
Add-Log "starting sloptunnel.exe $($args -join ' ')"
$proc = Start-Process -FilePath (Join-Path $root "sloptunnel.exe") `
  -ArgumentList $args -WorkingDirectory $root -PassThru `
  -RedirectStandardOutput $stdout -RedirectStandardError $stderr

$deadline = (Get-Date).AddSeconds(180)
$pathsReady = $false
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 2
  if (Test-Path $stdout) {
    $tail = Get-Content $stdout -Tail 30
    if ($tail -match "paths=2/2") {
      $pathsReady = $true
      break
    }
  }
  if ($proc.HasExited) {
    break
  }
}
Add-Log "paths_ready=$pathsReady exited=$($proc.HasExited) exit_code=$($proc.ExitCode)"
Add-Log "route print after tunnel startup"
route print -4 | Out-File -Append -FilePath $log -Encoding ascii
Add-Log "host bypass routes after tunnel startup"
Get-NetRoute -DestinationPrefix "$serverIp/32" -ErrorAction SilentlyContinue |
  Format-Table -AutoSize | Out-String | Out-File -Append -FilePath $log -Encoding ascii
Find-NetRoute -RemoteIPAddress $serverIp -ErrorAction SilentlyContinue |
  Format-Table -AutoSize | Out-String | Out-File -Append -FilePath $log -Encoding ascii
Get-NetRoute -DestinationPrefix "$resolverIp/32" -ErrorAction SilentlyContinue |
  Format-Table -AutoSize | Out-String | Out-File -Append -FilePath $log -Encoding ascii
Add-Log "net IP config after tunnel startup"
Get-NetIPConfiguration | Out-String | Out-File -Append -FilePath $log -Encoding ascii
if (Test-Path $stdout) {
  Add-Log "sloptunnel stdout tail at ready"
  Get-Content $stdout -Tail 80 | Out-File -Append -FilePath $log -Encoding ascii
}
if (Test-Path $stderr) {
  Add-Log "sloptunnel stderr tail at ready"
  Get-Content $stderr -Tail 80 | Out-File -Append -FilePath $log -Encoding ascii
}
Copy-Results "TUNNEL_READY"

Start-Sleep -Seconds 120
if (Test-Path $stdout) {
  Add-Log "sloptunnel stdout final tail"
  Get-Content $stdout -Tail 120 | Out-File -Append -FilePath $log -Encoding ascii
}
if (Test-Path $stderr) {
  Add-Log "sloptunnel stderr final tail"
  Get-Content $stderr -Tail 120 | Out-File -Append -FilePath $log -Encoding ascii
}
if (!$proc.HasExited) {
  Stop-Process -Id $proc.Id -Force
}
Copy-Results "DONE"
shutdown.exe /s /t 5 /f
