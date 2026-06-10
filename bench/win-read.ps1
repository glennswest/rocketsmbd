cmd /c "net use \\192.168.8.161\data /user:glenn testpw123" | Out-Null
try { $fs=[System.IO.File]::OpenRead("\\192.168.8.161\data\big0.bin"); $sw=[Diagnostics.Stopwatch]::StartNew(); $buf=New-Object byte[] (4MB); $tot=0
  while(($n=$fs.Read($buf,0,$buf.Length)) -gt 0){$tot+=$n}; $fs.Close(); $sw.Stop()
  $gb=$tot/1GB; $s=$sw.Elapsed.TotalSeconds
  ".NET OpenRead+stream OK: {0:N2} GiB in {1:N2}s = {2:N2} GB/s ({3:N1} Gbps)" -f $gb,$s,($gb/$s),($gb*8/$s)
} catch { ".NET FAILED: " + $_.Exception.Message }
