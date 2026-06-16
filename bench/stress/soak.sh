#!/bin/bash
# Soak test: run the N-concurrent-mount stress round ROUNDS times against a
# running rocketsmbd to surface slow leaks and slot/lease exhaustion that a
# single round can't. Run on the server host.
#
#   soak.sh [ROUNDS] [N] [SRV] [SHARE_PATH]
#     ROUNDS  number of stress rounds (default 1000)
#     N       client containers per round (default 100)
#     SRV     server address (default 127.0.0.1)
#     SHARE_PATH  server-side path of the "data" share (default /srv/stress)
#
# Per round it records pass/fail and the server's RSS, then prints a leak
# verdict at the end (baseline vs final RSS). Aborts immediately if the server
# dies. Tolerates a lagging container via BARRIER_PCT (default 98 here).
#
# Every round is appended to a CSV (STATS_CSV, default /tmp/soak-stats.csv) for
# post-run analysis with analyze-soak.sh:
#   round,epoch_s,pass,fail,rss_kb,peak_conns,duration_s
set -u
ROUNDS=${1:-1000}
N=${2:-100}
SRV=${3:-127.0.0.1}
SHARE_PATH=${4:-/srv/stress}
HERE=$(cd "$(dirname "$0")" && pwd)
export BARRIER_PCT=${BARRIER_PCT:-98}
CSV=${STATS_CSV:-/tmp/soak-stats.csv}

srvpid=$(pgrep -x rocketsmbd | head -1)
if [ -z "$srvpid" ]; then echo "no rocketsmbd running"; exit 1; fi
rss0=$(awk '/VmRSS/{print $2}' /proc/"$srvpid"/status)
echo "soak start: pid=$srvpid rounds=$ROUNDS N=$N baseline_rss=${rss0}kB csv=$CSV"
echo "round,epoch_s,pass,fail,rss_kb,peak_conns,duration_s" > "$CSV"

# Build the image once up front (run-stress.sh would rebuild each round; the
# cache makes it cheap, but skip the noise by warming it here).
podman build -q -t rsmbd-stress -f "$HERE/Containerfile" "$HERE" >/dev/null

totpass=0; totfail=0; minrss=$rss0; maxrss=$rss0
for r in $(seq 1 "$ROUNDS"); do
    if ! kill -0 "$srvpid" 2>/dev/null; then
        echo "ROUND $r: SERVER DIED — aborting soak"; exit 2
    fi
    # one round; suppress the per-round chatter, keep the RESULT line
    t0=$(date +%s)
    out=$(bash "$HERE/run-stress.sh" "$N" "$SRV" "$SHARE_PATH" 2>&1)
    dur=$(( $(date +%s) - t0 ))
    res=$(echo "$out" | grep '^RESULT:')
    p=$(echo "$res" | sed -E 's/.*RESULT: ([0-9]+) passed.*/\1/')
    f=$(echo "$res" | sed -E 's/.*passed, ([0-9]+) failed.*/\1/')
    p=${p:-0}; f=${f:-$N}
    peak=$(echo "$out" | sed -nE 's/.*peak: established :445 conns=([0-9]+).*/\1/p' | head -1)
    peak=${peak:-0}
    totpass=$((totpass + p)); totfail=$((totfail + f))
    rss=$(awk '/VmRSS/{print $2}' /proc/"$srvpid"/status 2>/dev/null)
    rss=${rss:-0}
    [ "$rss" -lt "$minrss" ] && minrss=$rss
    [ "$rss" -gt "$maxrss" ] && maxrss=$rss
    echo "$r,$(date +%s),$p,$f,$rss,$peak,$dur" >> "$CSV"
    if [ "$f" != "0" ]; then
        echo "round $r/$ROUNDS: $p ok $f FAIL  rss=${rss}kB"
        echo "$out" | grep '  FAIL'
    elif [ $((r % 10)) -eq 0 ] || [ "$r" = "1" ]; then
        echo "round $r/$ROUNDS: ${p} ok  rss=${rss}kB  (cum: ${totpass} ok / ${totfail} fail)"
    fi
done

rssF=$(awk '/VmRSS/{print $2}' /proc/"$srvpid"/status)
echo "=========================================================="
echo "soak done: $ROUNDS rounds x $N clients = $((ROUNDS * N)) mount cycles"
echo "  passed=$totpass  failed=$totfail"
echo "  server rss: baseline=${rss0}kB final=${rssF}kB min=${minrss}kB max(idle samples)=${maxrss}kB"
echo "  alive=$(kill -0 "$srvpid" 2>/dev/null && echo YES || echo NO)"
drift=$((rssF - rss0))
echo "  rss drift baseline->final: ${drift}kB (leak if this grows ~linearly with rounds)"
echo "  per-round stats: $CSV  (analyze with bench/stress/analyze-soak.sh)"
echo "=== SOAK-DONE ==="
"$HERE/analyze-soak.sh" "$CSV" 2>/dev/null || true
