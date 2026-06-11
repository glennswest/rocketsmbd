# Concurrent multi-stream read+write benchmark from a Windows client.
# Usage: powershell -File win-multistream.ps1 [server] [reads] [writes] [gibPerStream]
param(
  [string]$Server = "192.168.8.161",
  [int]$Reads = 4,
  [int]$Writes = 4,
  [int]$Gib = 1
)
# Store creds so background jobs can reach the UNC path in their own sessions.
cmdkey /add:$Server /user:glenn /pass:testpw123 | Out-Null
$share = "\\$Server\data"

$readJob = {
  param($path, $gib)
  $fs = [System.IO.File]::OpenRead($path)
  $buf = New-Object byte[] (4MB); $tot = 0
  while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) { $tot += $n }
  $fs.Close(); [int64]$tot
}
$writeJob = {
  param($path, $gib)
  $fs = [System.IO.File]::Create($path)
  $buf = New-Object byte[] (4MB); $tot = 0; $target = $gib * 1GB
  while ($tot -lt $target) { $fs.Write($buf, 0, $buf.Length); $tot += $buf.Length }
  $fs.Flush(); $fs.Close(); [int64]$tot
}

$jobs = @()
$sw = [System.Diagnostics.Stopwatch]::StartNew()
for ($i = 0; $i -lt $Reads; $i++)  { $jobs += Start-Job -ScriptBlock $readJob  -ArgumentList "$share\big$i.bin", $Gib }
for ($i = 0; $i -lt $Writes; $i++) { $jobs += Start-Job -ScriptBlock $writeJob -ArgumentList "$share\winw$i.bin", $Gib }
$jobs | Wait-Job | Out-Null
$sw.Stop()

$bytes = 0
foreach ($j in $jobs) {
  $r = Receive-Job $j 2>$null | Where-Object { $_ -is [int64] -or $_ -is [int] } | Select-Object -Last 1
  if ($r) { $bytes += [int64]$r } else { Write-Host ("job {0} state={1} (no count)" -f $j.Id, $j.State) }
}
$jobs | Remove-Job
$s = $sw.Elapsed.TotalSeconds; $gibTot = $bytes / 1GB
"{0} read + {1} write streams concurrently: {2:N2} GiB in {3:N2}s = {4:N2} GB/s ({5:N1} Gbps)" -f `
  $Reads, $Writes, $gibTot, $s, ($gibTot/$s), ($gibTot*8/$s)

# cleanup
for ($i = 0; $i -lt $Writes; $i++) { Remove-Item "$share\winw$i.bin" -Force -ErrorAction SilentlyContinue }
cmdkey /delete:$Server | Out-Null
