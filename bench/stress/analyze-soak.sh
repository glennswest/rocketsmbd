#!/bin/bash
# Analyze a soak.sh stats CSV (round,epoch_s,pass,fail,rss_kb,peak_conns,duration_s).
# Reports I/O pass/fail, RSS leak trend (least-squares slope + first/last-quartile
# means → plateau vs linear-leak verdict), peak-connection coverage, and timing.
# Portable awk; runs on macOS or Linux.
#
#   analyze-soak.sh [stats.csv]   (default /tmp/soak-stats.csv)
set -u
CSV=${1:-/tmp/soak-stats.csv}
if [ ! -f "$CSV" ]; then echo "no stats file: $CSV"; exit 1; fi

awk -F, '
NR==1 { next }                              # header
{
    n++
    rnd[n]=$1+0; ps=$3+0; fl=$4+0; rss=$5+0; pk=$6+0; dur=$7+0
    tot_pass+=ps; tot_fail+=fl
    if (fl>0) { nfail_rounds++; failrounds=failrounds (failrounds==""?"":",") rnd[n] }
    # RSS series for regression
    x[n]=rnd[n]; y[n]=rss
    if (n==1 || rss<rmin){rmin=rss; rminr=rnd[n]}
    if (n==1 || rss>rmax){rmax=rss; rmaxr=rnd[n]}
    rss_first = (n==1?rss:rss_first)         # keep first
    rss_last = rss
    # peak conns
    if (n==1 || pk<pkmin) pkmin=pk
    pksum+=pk
    # duration
    dsum+=dur; if(n==1||dur<dmin)dmin=dur; if(n==1||dur>dmax)dmax=dur
}
END {
    if (n==0){print "empty CSV"; exit 1}
    # least-squares slope of rss vs round
    for(i=1;i<=n;i++){sx+=x[i];sy+=y[i]}
    mx=sx/n; my=sy/n
    for(i=1;i<=n;i++){dxx=x[i]-mx; sxx+=dxx*dxx; sxy+=dxx*(y[i]-my)}
    slope=(sxx>0)?sxy/sxx:0
    # first vs last quartile mean (plateau test)
    q=int(n/4); if(q<1)q=1
    for(i=1;i<=q;i++) fq+=y[i]; fq/=q
    for(i=n-q+1;i<=n;i++) lq+=y[i]; lq/=q
    span=x[n]-x[1]; if(span<1)span=1
    proj1000 = slope*1000                    # projected drift over 1000 rounds

    printf "=== soak analysis: %s ===\n", FILENAME
    printf "rounds recorded : %d (round %d..%d)\n", n, x[1], x[n]
    printf "I/O             : %d passed, %d failed across %d rounds\n", tot_pass, tot_fail, n
    if (nfail_rounds>0) printf "  FAILED ROUNDS : %d  [%s]\n", nfail_rounds, failrounds
    else                printf "  clean         : every round 100%% verified\n"
    printf "peak conns/round: min=%d  mean=%.1f  (target was N)\n", pkmin, pksum/n
    printf "round duration  : min=%ds mean=%.1fs max=%ds  (total ~%.1f h)\n", dmin, dsum/n, dmax, dsum/3600
    printf "server RSS (kB) : first=%d last=%d min=%d(@r%d) max=%d(@r%d)\n", rss_first, rss_last, rmin, rminr, rmax, rmaxr
    printf "  drift first->last : %+d kB over %d rounds\n", rss_last-rss_first, span
    printf "  least-sq slope    : %+.3f kB/round  -> %+.0f kB projected over 1000 rounds\n", slope, proj1000
    printf "  quartile means    : first-25%%=%.0f kB  last-25%%=%.0f kB  (delta %+.0f)\n", fq, lq, lq-fq
    # verdict
    if (proj1000 < 1024 && (lq-fq) < 512)
        printf "  VERDICT: no meaningful leak — RSS plateaus (allocator high-water).\n"
    else if (proj1000 < 8192)
        printf "  VERDICT: small steady growth (%+.0f kB/1000 rounds) — investigate but not severe.\n", proj1000
    else
        printf "  VERDICT: LINEAR LEAK suspected (%+.0f kB/1000 rounds).\n", proj1000
}' "$CSV"
