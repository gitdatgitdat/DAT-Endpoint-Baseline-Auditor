<#
.SYNOPSIS
  Endpoint Baseline Auditor (Windows)

.DESCRIPTION
  Checks common security baselines:
    - BitLocker on OS volume
    - Secure Boot + TPM ready
    - Microsoft Defender: real-time on, signatures fresh
    - Windows Firewall: all profiles enabled
    - RDP disabled
    - SMBv1 disabled
    - (Optional) Local Administrators only in allowlist
    - (Optional) LAPS present

  Outputs JSON/CSV + compliance reasons.
#>

[CmdletBinding()]
param(
  [string[]]$ComputerName,
  [pscredential]$Credential,
  [string]$HostsCsv,
  [string]$Json,
  [string]$Csv,
  [string]$LogPath,
  [int]$MaxSigAgeDays = 7,
  [string[]]$AllowedAdmins,
  [switch]$RequireLAPS
)

# ---------- logging ----------
$script:LogFile = $null
function Initialize-Logging { param([string]$Path)
  if (-not $Path) { return }
  try {
    if (Test-Path $Path -PathType Leaf) { $file=$Path }
    else { if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
           $file = Join-Path $Path ("Baseline_" + (Get-Date -Format "yyyy-MM-ddTHH-mm-ssZ") + ".log") }
    $script:LogFile = $file
    "[$([datetime]::UtcNow.ToString('o'))] INFO Logging to $file" | Out-File $file -Encoding utf8
  } catch { Write-Warning $_.Exception.Message }
}
function Write-Log { param([ValidateSet('INFO','WARN','ERROR')][string]$Level='INFO',[string]$Message)
  $line = "[{0}] {1} {2}" -f ([datetime]::UtcNow.ToString('o')),$Level,$Message
  if ($script:LogFile) { $line | Out-File $script:LogFile -Append -Encoding utf8 }
  Write-Verbose $line
}

# ---------- helpers ----------
function Get-TargetsFromCsv { param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    $alt = Join-Path $PSScriptRoot $Path
    if (-not (Test-Path -LiteralPath $alt)) { throw "Hosts list not found: $Path" }
    $Path = $alt
  }
  if ([IO.Path]::GetExtension($Path).ToLower() -eq '.txt') {
    return (Get-Content -LiteralPath $Path |? { $_ -and $_ -notmatch '^\s*#' } |% Trim |? {$_}) | Sort-Object -Unique
  }
  $rows = Import-Csv -LiteralPath $Path
  $props = ($rows | Get-Member -MemberType NoteProperty | Select-Object -Expand Name)
  $col   = @('ComputerName','Hostname','Host','Name','FQDN') |? { $_ -in $props } | Select-Object -First 1
  if (-not $col) { $col = $props | Select-Object -First 1 }
  $rows | ForEach-Object { $_.$col } |? { $_ } |% Trim | Sort-Object -Unique
}

function Test-BitLockerOS {
  try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $on = $bl.ProtectionStatus -eq 'On'
    return @{ Pass=$on; Detail="Status=$($bl.ProtectionStatus)" }
  } catch { return @{ Pass=$false; Detail="BitLocker cmdlet not available or error" } }
}

function Test-SecureBootTPM {
  $sb=$null;$tpm=$null
  try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sb=$false }
  try { $tpm = Get-Tpm -ErrorAction Stop } catch { $tpm=$null }
  $tpmReady = $tpm -and $tpm.TpmPresent -and $tpm.TpmReady
  return @{ Pass=($sb -and $tpmReady); Detail="SecureBoot=$sb; TPMReady=$tpmReady" }
}

function Test-Defender {
  try {
    $s = Get-MpComputerStatus -ErrorAction Stop
    $okRT = $s.RealTimeProtectionEnabled -and $s.AntivirusEnabled
    $age  = [int]$s.AntivirusSignatureAge
    $okAge = ($age -le $MaxSigAgeDays)
    return @{ Pass=($okRT -and $okAge); Detail="RT=$okRT; SigAge=$age d (<= $MaxSigAgeDays)" }
  } catch { return @{ Pass=$false; Detail="Defender not available or disabled" } }
}

function Test-FirewallAllProfiles {
  try {
    $p = Get-NetFirewallProfile -ErrorAction Stop
    $allOn = @($p |? { -not $_.Enabled }) -eq $null
    return @{ Pass=$allOn; Detail=("Domain={0}, Private={1}, Public={2}" -f $p[0].Enabled,$p[1].Enabled,$p[2].Enabled) }
  } catch { return @{ Pass=$false; Detail="Firewall cmdlets not available" } }
}

function Test-RDPDisabled {
  try {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
    return @{ Pass=($v -eq 1); Detail="fDenyTSConnections=$v (1=disabled)" }
  } catch { return @{ Pass=$false; Detail="RDP registry read failed" } }
}

function Test-SMB1Disabled {
  try {
    $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    return @{ Pass=($f.State -eq 'Disabled'); Detail="SMB1=$($f.State)" }
  } catch {
    # fallback registry (server/service param)
    try {
      $reg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction Stop).SMB1
      $ok = ($reg -eq 0 -or $reg -eq $null)
      return @{ Pass=$ok; Detail="SMB1Reg=$reg (0/null=disabled)" }
    } catch { return @{ Pass=$false; Detail="SMB1 check failed" } }
  }
}

function Test-AdminsAllowlist {
  if (-not $AllowedAdmins) { return @{ Pass=$true; Detail="No allowlist supplied" } }
  try {
    $members = (Get-LocalGroupMember -Group 'Administrators' | Select-Object -Expand Name)
    $extra = @($members | Where-Object { $_ -notin $AllowedAdmins })
    $ok = ($extra.Count -eq 0)
    return @{ Pass=$ok; Detail= if ($ok) { "OK" } else { "Extra:" + ($extra -join ', ') } }
  } catch { return @{ Pass=$false; Detail="LocalGroupMember failed (need admin?)" } }
}

function Test-LAPS {
  if (-not $RequireLAPS) { return @{ Pass=$true; Detail="LAPS not required" } }
  $ok = $false
  try {
    $ok = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS' -ErrorAction SilentlyContinue
    if (-not $ok) { $ok = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -ErrorAction SilentlyContinue }
  } catch { }
  return @{ Pass=$ok; Detail= if ($ok) { "Detected" } else { "Not found" } }
}

function Get-EndpointBaselineLocal {
  $checks = [ordered]@{
    BitLocker     = Test-BitLockerOS
    SecureBootTPM = Test-SecureBootTPM
    Defender      = Test-Defender
    Firewall      = Test-FirewallAllProfiles
    RDPDisabled   = Test-RDPDisabled
    SMB1Disabled  = Test-SMB1Disabled
    AdminsAllow   = Test-AdminsAllowlist
    LAPS          = Test-LAPS
  }

  $reasons = @()
  foreach ($k in $checks.Keys) {
    $res = & $checks[$k]
    if (-not $res.Pass) { $reasons += "$k:$($res.Detail)" }
    Set-Variable -Name ("c_" + $k) -Value $res -Scope Local
  }

  [pscustomobject]@{
    ComputerName   = $env:COMPUTERNAME
    Compliance     = if ($reasons.Count) { "NonCompliant" } else { "Compliant" }
    Reasons        = ($reasons -join '; ')
    BitLocker      = $c_BitLocker.Detail
    SecureBootTPM  = $c_SecureBootTPM.Detail
    Defender       = $c_Defender.Detail
    Firewall       = $c_Firewall.Detail
    RDP            = $c_RDPDisabled.Detail
    SMB1           = $c_SMB1Disabled.Detail
    Admins         = $c_AdminsAllow.Detail
    LAPS           = $c_LAPS.Detail
    CollectedAt    = [datetime]::UtcNow
  }
}

function Invoke-RemoteBaseline {
  param([string[]]$Targets,[pscredential]$Cred)
  Write-Log INFO "Remote baseline on $($Targets.Count) host(s)"

  $sb = {
    param($MaxSigAgeDays,$AllowedAdmins,$RequireLAPS)
    ${function:Test-BitLockerOS} | Out-Null
    ${function:Test-SecureBootTPM} | Out-Null
    ${function:Test-Defender} | Out-Null
    ${function:Test-FirewallAllProfiles} | Out-Null
    ${function:Test-RDPDisabled} | Out-Null
    ${function:Test-SMB1Disabled} | Out-Null
    ${function:Test-AdminsAllowlist} | Out-Null
    ${function:Test-LAPS} | Out-Null
    ${function:Get-EndpointBaselineLocal} | Out-Null
    Set-Variable MaxSigAgeDays -Value $MaxSigAgeDays -Scope Script
    Set-Variable AllowedAdmins -Value $AllowedAdmins -Scope Script
    if ($RequireLAPS) { Set-Variable RequireLAPS -Value $true -Scope Script }
    Get-EndpointBaselineLocal
  }

  $results = @()
  foreach ($t in $Targets) {
    # local fast path
    $short = ($t -split '\.')[0]
    if ($short -ieq $env:COMPUTERNAME) {
      $loc = Get-EndpointBaselineLocal; $loc.ComputerName = $t
      $results += $loc
      Write-Log INFO "Local shortcut $t"
      continue
    }
    try {
      $res = if ($Cred) {
        Invoke-Command -ComputerName $t -Credential $Cred -ScriptBlock $sb `
          -ArgumentList $MaxSigAgeDays,$AllowedAdmins,$RequireLAPS -ErrorAction Stop
      } else {
        Invoke-Command -ComputerName $t -ScriptBlock $sb `
          -ArgumentList $MaxSigAgeDays,$AllowedAdmins,$RequireLAPS -ErrorAction Stop
      }
      $results += $res
      Write-Log INFO "OK $t -> $($res.Compliance)"
    } catch {
      $msg = $_.Exception.Message
      Write-Log ERROR "RemoteError $t: $msg"
      $results += [pscustomobject]@{
        ComputerName=$t; Compliance='Unknown'; Reasons="RemoteError: $msg"; CollectedAt=[datetime]::UtcNow
      }
    }
  }
  $results
}

# ---------- main ----------
$__isDotSourced = $MyInvocation.InvocationName -eq '.'
if (-not $__isDotSourced) {
  Initialize-Logging -Path $LogPath

  # build targets
  $targets = @()
  if ($HostsCsv) { $targets += Get-TargetsFromCsv -Path $HostsCsv }
  if ($ComputerName) { $targets += $ComputerName }
  $targets = $targets | Sort-Object -Unique

  $all = if ($targets) {
    Invoke-RemoteBaseline -Targets $targets -Cred $Credential
  } else {
    @(Get-EndpointBaselineLocal)
  }

  # console preview
  $all | Select-Object ComputerName,Compliance,Reasons,BitLocker,SecureBootTPM,Defender,Firewall,RDP,SMB1 |
    Sort-Object ComputerName | Format-Table -AutoSize

  # outputs
  if ($Json) { $all | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 $Json; Write-Log INFO "JSON -> $Json" }
  if ($Csv)  { $all | Export-Csv -NoTypeInformation -Encoding UTF8 $Csv; Write-Log INFO "CSV  -> $Csv" }

  # exit codes: 0 ok, 1 noncompliant, 2 errors
  if ($all | Where-Object { $_.Compliance -eq 'Unknown' }) { exit 2 }
  elseif ($all | Where-Object { $_.Compliance -eq 'NonCompliant' }) { exit 1 }
  else { exit 0 }
}
