#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB_DIR="${SLOPTUNNEL_WINDOWS_LAB_DIR:-$ROOT_DIR/lab/windows}"
ISO="${SLOPTUNNEL_WINDOWS_ISO:-$LAB_DIR/SERVER_EVAL_x64FRE_en-us.iso}"
ANSWER_DIR="$LAB_DIR/answer"
ANSWER_ISO="$LAB_DIR/sloptunnel-answer.iso"
MNT="$LAB_DIR/iso-mnt"
TOKEN_FILE="${SLOPTUNNEL_TOKEN_FILE:-/tmp/sloptunnel_token}"
ADMIN_PASSWORD="${SLOPTUNNEL_WINDOWS_ADMIN_PASSWORD:-Sloptunnel!234}"
IMAGE_NAME="${SLOPTUNNEL_WINDOWS_IMAGE_NAME:-}"

if [[ ! -r "$ISO" ]]; then
  echo "missing Windows Server ISO: $ISO" >&2
  exit 1
fi

if [[ ! -r "$ROOT_DIR/build/sloptunnel.exe" ]]; then
  echo "missing Windows executable; run the MinGW build first" >&2
  exit 1
fi

if [[ ! -r "$TOKEN_FILE" ]]; then
  echo "missing token file: $TOKEN_FILE" >&2
  exit 1
fi

command -v wiminfo >/dev/null || {
  echo "missing wiminfo; install wimtools" >&2
  exit 1
}
command -v xorriso >/dev/null || {
  echo "missing xorriso" >&2
  exit 1
}

rm -rf "$ANSWER_DIR"
mkdir -p "$ANSWER_DIR/\$OEM\$/\$\$/Setup/Scripts" "$ANSWER_DIR/\$OEM\$/\$1/sloptunnel-lab"
mkdir -p "$ANSWER_DIR/payload"
mkdir -p "$LAB_DIR"

mkdir -p "$MNT"
if ! mountpoint -q "$MNT"; then
  mount -o loop,ro "$ISO" "$MNT"
fi
trap 'mountpoint -q "$MNT" && umount "$MNT" || true' EXIT

if [[ -z "$IMAGE_NAME" ]]; then
  IMAGE_NAME="$(wiminfo "$MNT/sources/install.wim" | awk -F': ' '
    /Name[[:space:]]*:/ && /SERVERDATACENTERCORE/ {print $2; exit}
    /Name[[:space:]]*:/ && /Datacenter Evaluation/ && /Core/ {print $2; exit}
  ')"
  IMAGE_NAME="$(printf '%s' "$IMAGE_NAME" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
fi
if [[ -z "$IMAGE_NAME" ]]; then
  echo "could not detect a Server Core image in install.wim" >&2
  wiminfo "$MNT/sources/install.wim" | sed -n '/Name[[:space:]]*:/p' >&2
  exit 1
fi

cp "$ROOT_DIR/build/sloptunnel.exe" "$ANSWER_DIR/\$OEM\$/\$1/sloptunnel-lab/sloptunnel.exe"
cp "$TOKEN_FILE" "$ANSWER_DIR/\$OEM\$/\$1/sloptunnel-lab/token.txt"
cp "$ROOT_DIR/build/sloptunnel.exe" "$ANSWER_DIR/payload/sloptunnel.exe"
cp "$TOKEN_FILE" "$ANSWER_DIR/payload/token.txt"
if [[ -r "$LAB_DIR/deps/wintun.dll" ]]; then
  cp "$LAB_DIR/deps/wintun.dll" "$ANSWER_DIR/\$OEM\$/\$1/sloptunnel-lab/wintun.dll"
  cp "$LAB_DIR/deps/wintun.dll" "$ANSWER_DIR/payload/wintun.dll"
fi
printf 'sloptunnel answer media\n' > "$ANSWER_DIR/SLOPTUNNEL_ANSWER.txt"

cat > "$ANSWER_DIR/\$OEM\$/\$\$/Setup/Scripts/SetupComplete.cmd" <<'CMD'
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Setup\Scripts\run-sloptunnel-test.ps1
CMD

cat > "$ANSWER_DIR/run-sloptunnel-test.ps1" <<'PS1'
$ErrorActionPreference = "Continue"
$root = "C:\sloptunnel-lab"
$localLog = Join-Path $root "windows-result.txt"
$stdout = Join-Path $root "vpn.out"
$stderr = Join-Path $root "vpn.err"
New-Item -ItemType Directory -Force -Path $root | Out-Null
if (Test-Path (Join-Path $PSScriptRoot "payload")) {
  Copy-Item -Force -Recurse (Join-Path $PSScriptRoot "payload\*") $root
}

function Add-Log($text) {
  $line = "$(Get-Date -Format o) $text"
  Add-Content -Path $localLog -Value $line
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

Add-Log "sloptunnel Windows Server Core lab starting"
Add-Log "computer=$env:COMPUTERNAME user=$env:USERNAME"
Add-Log "payload listing:"
Get-ChildItem -Force $root | ForEach-Object {
  Add-Log ("  {0} {1} bytes" -f $_.Name, $_.Length)
}
Add-Log "ipconfig:"
ipconfig /all | Out-File -Append -FilePath $localLog -Encoding ascii

Add-Log "preflight direct HTTP should fail behind the firewall"
$direct = & curl.exe -4 -m 5 http://1.1.1.1/cdn-cgi/trace 2>&1
Add-Log "direct_http_exit=$LASTEXITCODE"
Add-Content -Path $localLog -Value $direct

$smokeArgs = @("--help")
Add-Log "smoke sloptunnel.exe $($smokeArgs -join ' ')"
$smoke = & (Join-Path $root "sloptunnel.exe") $smokeArgs 2>&1
Add-Log "smoke_exit=$LASTEXITCODE"
Add-Content -Path $localLog -Value $smoke

Add-Log "manual DNS TXT query through firewall resolver"
$manualDns = & nslookup.exe -type=TXT probe.sploinkstersploinkster.online 10.210.0.1 2>&1
Add-Log "manual_dns_exit=$LASTEXITCODE"
Add-Content -Path $localLog -Value $manualDns

Add-Log "manual TCP 5223 connectivity check"
$manualTcp = Test-NetConnection -ComputerName 18.219.84.252 -Port 5223 -InformationLevel Detailed 2>&1 | Out-String
Add-Content -Path $localLog -Value $manualTcp

function Run-Probe($label, [string[]]$probeArgs, [int]$seconds) {
  $probeStdout = Join-Path $root "$label.out"
  $probeStderr = Join-Path $root "$label.err"
  Remove-Item -Force -ErrorAction SilentlyContinue $probeStdout, $probeStderr
  Add-Log "$label probe sloptunnel.exe $($probeArgs -join ' ')"
  $probeProc = Start-Process -FilePath (Join-Path $root "sloptunnel.exe") `
    -ArgumentList $probeArgs -WorkingDirectory $root -PassThru `
    -RedirectStandardOutput $probeStdout -RedirectStandardError $probeStderr
  $finished = $probeProc.WaitForExit($seconds * 1000)
  if (!$finished) {
    Stop-Process -Id $probeProc.Id -Force
    [void]$probeProc.WaitForExit(5000)
  }
  $probeProc.Refresh()
  Add-Log "$label exit=$($probeProc.ExitCode) exited=$($probeProc.HasExited)"
  if (Test-Path $probeStdout) {
    Add-Log "$label stdout tail"
    Get-Content $probeStdout -Tail 40 | Out-File -Append -FilePath $localLog -Encoding ascii
  }
  if (Test-Path $probeStderr) {
    Add-Log "$label stderr tail"
    Get-Content $probeStderr -Tail 40 | Out-File -Append -FilePath $localLog -Encoding ascii
  }
}

$commonArgs = @(
  "--client",
  "--no-vpn",
  "--ports", "5223",
  "--server-ip", "18.219.84.252",
  "--dns-tunnel-domain", "sploinkstersploinkster.online",
  "--dns-resolver", "10.210.0.1",
  "--token-file", (Join-Path $root "token.txt"),
  "--headless"
)
Run-Probe "help" @("--help") 3
Run-Probe "dns" (@($commonArgs) + @("--transport", "dns")) 10
Run-Probe "tcp" (@($commonArgs) + @("--transport", "tcp")) 10
Run-Probe "stack" (@($commonArgs) + @("--transport", "tcp+dns")) 12

$args = @(
  "--client",
  "--transport", "tcp+dns",
  "--ports", "5223",
  "--server-ip", "18.219.84.252",
  "--dns-tunnel-domain", "sploinkstersploinkster.online",
  "--dns-resolver", "10.210.0.1",
  "--token-file", (Join-Path $root "token.txt"),
  "--tun-name", "slopwin0",
  "--no-ipv6",
  "--headless"
)
Add-Log "full-vpn sloptunnel.exe $($args -join ' ')"
$proc = Start-Process -FilePath (Join-Path $root "sloptunnel.exe") `
  -ArgumentList $args -WorkingDirectory $root -PassThru `
  -RedirectStandardOutput $stdout -RedirectStandardError $stderr

$deadline = (Get-Date).AddSeconds(180)
$pathsReady = $false
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 2
  if (Test-Path $stdout) {
    $tail = Get-Content $stdout -Tail 20
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
if (Test-Path $stdout) {
  Add-Log "sloptunnel stdout tail"
  Get-Content $stdout -Tail 40 | Out-File -Append -FilePath $localLog -Encoding ascii
}
if (Test-Path $stderr) {
  Add-Log "sloptunnel stderr tail"
  Get-Content $stderr -Tail 40 | Out-File -Append -FilePath $localLog -Encoding ascii
}

Add-Log "route print after tunnel startup"
route print -4 | Out-File -Append -FilePath $localLog -Encoding ascii
Add-Log "net IP configuration after tunnel startup"
Get-NetIPConfiguration | Out-String | Out-File -Append -FilePath $localLog -Encoding ascii
if ($pathsReady) {
  Start-Sleep -Seconds 8
}

Add-Log "testing HTTP after tunnel startup"
$after = & curl.exe -4 -m 60 http://1.1.1.1/cdn-cgi/trace 2>&1
Add-Log "tunnel_http_exit=$LASTEXITCODE"
Add-Content -Path $localLog -Value $after

if (!$proc.HasExited) {
  Stop-Process -Id $proc.Id -Force
}

$resultRoot = Get-ResultRoot
if ($resultRoot) {
  Copy-Item -Force $localLog (Join-Path $resultRoot "windows-result.txt")
  foreach ($name in @("help.out", "help.err", "dns.out", "dns.err", "tcp.out", "tcp.err", "stack.out", "stack.err", "vpn.out", "vpn.err")) {
    $src = Join-Path $root $name
    if (Test-Path $src) {
      Copy-Item -Force $src (Join-Path $resultRoot $name)
    }
  }
  "complete" | Set-Content -Path (Join-Path $resultRoot "DONE.txt") -Encoding ascii
}

shutdown.exe /s /t 5 /f
PS1
cp "$ANSWER_DIR/run-sloptunnel-test.ps1" "$ANSWER_DIR/\$OEM\$/\$\$/Setup/Scripts/run-sloptunnel-test.ps1"

cat > "$ANSWER_DIR/Autounattend.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DiskConfiguration>
        <Disk wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add">
              <Order>1</Order>
              <Type>Primary</Type>
              <Size>100</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>2</Order>
              <Type>Primary</Type>
              <Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order>
              <PartitionID>1</PartitionID>
              <Format>NTFS</Format>
              <Label>System</Label>
              <Active>true</Active>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>2</Order>
              <PartitionID>2</PartitionID>
              <Format>NTFS</Format>
              <Label>Windows</Label>
              <Letter>C</Letter>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
        <WillShowUI>OnError</WillShowUI>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom>
            <MetaData wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
              <Key>/IMAGE/NAME</Key>
              <Value>$IMAGE_NAME</Value>
            </MetaData>
          </InstallFrom>
          <InstallTo>
            <DiskID>0</DiskID>
            <PartitionID>2</PartitionID>
          </InstallTo>
          <WillShowUI>OnError</WillShowUI>
        </OSImage>
      </ImageInstall>
      <UserData>
        <AcceptEula>true</AcceptEula>
        <FullName>sloptunnel</FullName>
        <Organization>sloptunnel</Organization>
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>SLOPTUNWIN</ComputerName>
      <TimeZone>UTC</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <NetworkLocation>Work</NetworkLocation>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <AdministratorPassword>
          <Value>$ADMIN_PASSWORD</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <AutoLogon>
        <Password>
          <Value>$ADMIN_PASSWORD</Value>
          <PlainText>true</PlainText>
        </Password>
        <Username>Administrator</Username>
        <Enabled>true</Enabled>
        <LogonCount>1</LogonCount>
      </AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>1</Order>
          <Description>Run sloptunnel Windows lab</Description>
          <CommandLine>powershell.exe -NoProfile -ExecutionPolicy Bypass -Command &quot;\$d=(Get-PSDrive -PSProvider FileSystem | Where-Object { Test-Path (Join-Path \$_.Root 'SLOPTUNNEL_ANSWER.txt') } | Select-Object -First 1).Root; if(\$d){ &amp; (Join-Path \$d 'run-sloptunnel-test.ps1') }&quot;</CommandLine>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
XML

xorriso -as mkisofs -quiet -J -r -o "$ANSWER_ISO" "$ANSWER_DIR"
echo "created $ANSWER_ISO using image '$IMAGE_NAME'"
