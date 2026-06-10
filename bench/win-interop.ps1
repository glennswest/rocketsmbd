$ErrorActionPreference = "Continue"
cmd /c "net use \\192.168.8.161\data /user:glenn testpw123" 2>&1 | Out-String
"--- dir ---"
Get-ChildItem \\192.168.8.161\data | Select-Object Name,Length | Format-Table -AutoSize | Out-String
"--- read hello.txt ---"
Get-Content \\192.168.8.161\data\hello.txt -ErrorAction SilentlyContinue
"--- write test ---"
"written from Windows Server 2025" | Set-Content \\192.168.8.161\data\fromwin.txt -ErrorAction SilentlyContinue
if (Test-Path \\192.168.8.161\data\fromwin.txt) { "write OK: " + (Get-Content \\192.168.8.161\data\fromwin.txt) }
"--- SMB connection ---"
Get-SmbConnection -ServerName 192.168.8.161 -ErrorAction SilentlyContinue | Select-Object Dialect,Signed,NumOpens | Format-Table -AutoSize | Out-String
"--- multichannel ---"
Get-SmbMultichannelConnection -ErrorAction SilentlyContinue | Select-Object Server,ClientIpAddress,ServerIpAddress | Format-Table -AutoSize | Out-String
