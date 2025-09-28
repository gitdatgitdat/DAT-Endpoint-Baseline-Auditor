[CmdletBinding()]
param(
  [Parameter(Mandatory)][string[]]$InputPath,
  [string]$OutHtml = ".\reports\EndpointBaseline.html",
  [switch]$Open
)

function Read-Recs {
  $files = foreach ($p in $InputPath) { Get-ChildItem -Path $p -File -ErrorAction Stop }
  $all = @()
  foreach ($f in $files) {
    if ($f.Extension -match 'json') { $all += @(Get-Content -Raw $f.FullName | ConvertFrom-Json) }
    elseif ($f.Extension -match 'csv') { $all += @(Import-Csv $f.FullName) }
  }
  $all | Group-Object ComputerName | ForEach-Object {
    $_.Group | Sort-Object CollectedAt -Descending | Select-Object -First 1
  }
}
function H([string]$s){ if($null -eq $s){''}else{$s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'} }

$data = Read-Recs
$rows = foreach ($r in ($data | Sort-Object ComputerName)) {
  $cls = switch ($r.Compliance) { 'Compliant'{'ok'} 'NonCompliant'{'bad'} default{'unk'} }
@"
<tr class="$cls">
  <td class="name">$(H $r.ComputerName)</td>
  <td class="status"><span class="dot"></span>$(H $r.Compliance)</td>
  <td>$(H $r.BitLocker)</td>
  <td>$(H $r.SecureBootTPM)</td>
  <td>$(H $r.Defender)</td>
  <td>$(H $r.Firewall)</td>
  <td>$(H $r.RDP)</td>
  <td>$(H $r.SMB1)</td>
  <td class="reasons">$(H $r.Reasons)</td>
</tr>
"@
}

$html = @"
<!doctype html><meta charset="utf-8"><title>Endpoint Baseline</title>
<style>
:root{--ok:#22c55e;--bad:#ef4444;--unk:#9ca3af;--muted:#6b7280}
body{font-family:ui-sans-serif,Segoe UI,Roboto,Arial;margin:24px}
h1{margin:0 0 6px;font-size:24px} .sub{color:var(--muted);margin-bottom:12px}
table{width:100%;border-collapse:collapse} th,td{padding:10px 8px;border-bottom:1px solid #e5e7eb}
tr:nth-child(even){background:#f9fafb}.name{font-weight:600}.status{font-weight:600}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle}
tr.ok .dot{background:var(--ok)} tr.bad .dot{background:var(--bad)} tr.unk .dot{background:var(--unk)}
.reasons{max-width:520px;overflow-wrap:anywhere}
</style>
<h1>Endpoint Baseline</h1>
<div class="sub">Generated $(Get-Date)</div>
<table id="t"><thead>
<tr><th>Computer</th><th>Status</th><th>BitLocker</th><th>SecureBoot/TPM</th><th>Defender</th><th>Firewall</th><th>RDP</th><th>SMB1</th><th>Reasons</th></tr>
</thead><tbody>
$($rows -join "")
</tbody></table>
"@
$dir = Split-Path -Parent $OutHtml
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory $dir -Force | Out-Null }
$html | Out-File -Encoding utf8 $OutHtml
Write-Host "[OK] Wrote HTML -> $OutHtml"
if ($Open){ Start-Process $OutHtml | Out-Null }
