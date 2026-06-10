#!/usr/bin/env bash
# Measure the raw TCP ceiling between two hosts before blaming the server.
# Usage: net-iperf.sh <server-ip>   (run iperf3 -s on the server first)
set -u
S=${1:?server ip}
echo "== 1 stream =="
iperf3 -c "$S" -t 4 2>/dev/null | grep -E "sender|receiver"
echo "== 8 parallel streams =="
iperf3 -c "$S" -t 4 -P 8 2>/dev/null | grep -E "SUM.*sender|SUM.*receiver"
