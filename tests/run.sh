#!/usr/bin/env bash
#
# End-to-end tests: ftam client <-> ftamd test responder over XOT on
# localhost.  If tshark is installed, every client capture is also run
# through Wireshark's XOT/X.25/COTP/SES/PRES/ACSE/FTAM dissectors and
# must decode without malformed packets or BER errors.
#
set -u
cd "$(dirname "$0")/.."

PORT=${PORT:-19987}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ftamtest.XXXXXX")
SRV=$WORK/srv
mkdir -p "$SRV"
PASS=0
FAIL=0
SRVPID=

cleanup() {
    [ -n "$SRVPID" ] && kill "$SRVPID" 2>/dev/null
    wait 2>/dev/null
    if [ $FAIL -eq 0 ]; then rm -rf "$WORK"; else echo "artifacts kept in $WORK"; fi
}
trap cleanup EXIT

start_server() {
    [ -n "$SRVPID" ] && kill "$SRVPID" 2>/dev/null && wait "$SRVPID" 2>/dev/null
    ./ftamd -p "$PORT" -d "$SRV" "$@" -v >"$WORK/ftamd.log" 2>&1 &
    SRVPID=$!
    for _ in $(seq 50); do
        nc -z 127.0.0.1 "$PORT" 2>/dev/null && return
        sleep 0.05
    done
}

N=0
# run NAME EXPECTED_EXIT ftam-args...
run() {
    local name=$1 want=$2
    shift 2
    N=$((N + 1))
    local pcap=$WORK/t$N.pcap
    ./ftam -H "127.0.0.1:$PORT" -A 20000001 -a 20000002 --timeout 10 \
        --pcap "$pcap" "$@" >"$WORK/t$N.out" 2>"$WORK/t$N.err"
    local got=$?
    if [ "$got" -ne "$want" ]; then
        echo "FAIL  $name (exit $got, expected $want)"
        sed 's/^/      /' "$WORK/t$N.err"
        FAIL=$((FAIL + 1))
        return 1
    fi
    # SKIP_TSHARK: loss-injection tests record the "lost" packet in the
    # capture, which Wireshark's X.25 reassembly then counts twice
    if [ -z "${SKIP_TSHARK:-}" ] && command -v tshark >/dev/null; then
        local bad
        bad=$(tshark -r "$pcap" -d "tcp.port==$PORT,xot" -V 2>&1 |
              grep -E "Malformed|BER Error|Wrong field|Unknown (PDU|SPDU|TPDU)|Exception occurred|Dissector bug" |
              grep -v "Dissector for OID not implemented" | head -3)
        if [ -n "$bad" ]; then
            echo "FAIL  $name (tshark decode problems)"
            echo "$bad" | sed 's/^/      /'
            FAIL=$((FAIL + 1))
            return 1
        fi
    fi
    echo "ok    $name"
    PASS=$((PASS + 1))
}

check() {
    local name=$1
    shift
    if "$@"; then
        echo "ok    $name"
        PASS=$((PASS + 1))
    else
        echo "FAIL  $name"
        FAIL=$((FAIL + 1))
    fi
}

last_err() { cat "$WORK/t$N.err"; }

# ---- fixtures ---------------------------------------------------------------
head -c 300000 /dev/urandom >"$WORK/big.bin"
printf 'line one\nline two\n\nline four with\ttab\n' >"$WORK/lines.txt"
cp "$WORK/big.bin" "$SRV/remote.bin"
cp "$WORK/lines.txt" "$SRV/remote.txt"

start_server

run "ping (associate + release)" 0 ping
run "get binary (FTAM-3, 300 KB)" 0 get remote.bin "$WORK/got.bin"
check "  content matches" cmp -s "$WORK/big.bin" "$WORK/got.bin"
run "get text (FTAM-1)" 0 --text get remote.txt "$WORK/got.txt"
check "  content matches" cmp -s "$WORK/lines.txt" "$WORK/got.txt"
run "get to stdout" 0 get remote.txt -
check "  stdout matches" cmp -s "$WORK/lines.txt" "$WORK/t$N.out"

run "put binary (300 KB)" 0 put "$WORK/big.bin" up.bin
check "  content matches" cmp -s "$WORK/big.bin" "$SRV/up.bin"
run "put text (FTAM-1)" 0 --text put "$WORK/lines.txt" up.txt
check "  content matches" cmp -s "$WORK/lines.txt" "$SRV/up.txt"
run "put onto existing file is refused" 1 put "$WORK/lines.txt" up.bin
check "  diagnostic 3005" grep -q "error 3005" "$WORK/t$N.err"
check "  file untouched" cmp -s "$WORK/big.bin" "$SRV/up.bin"
run "put --force replaces" 0 --force put "$WORK/lines.txt" up.bin
check "  content replaced" cmp -s "$WORK/lines.txt" "$SRV/up.bin"
run "put --append extends" 0 --append put "$WORK/lines.txt" up.bin
check "  content appended" cmp -s <(cat "$WORK/lines.txt" "$WORK/lines.txt") "$SRV/up.bin"

run "attr" 0 attr remote.bin
check "  filesize reported" grep -q "filesize *300000" "$WORK/t$N.out"
check "  contents type reported" grep -q "FTAM-3" "$WORK/t$N.out"
run "rename" 0 rename up.txt renamed.txt
check "  renamed on disk" test -f "$SRV/renamed.txt" -a ! -f "$SRV/up.txt"
run "delete" 0 delete renamed.txt
check "  deleted on disk" test ! -f "$SRV/renamed.txt"
run "get missing file fails cleanly" 1 get nosuchfile "$WORK/none"
check "  diagnostic 3000" grep -q "error 3000" "$WORK/t$N.err"
check "  no partial local file" test ! -f "$WORK/none"
run "delete missing file fails" 1 delete nosuchfile

run "mod 128, packet 1024, window 7" 0 --mod128 --packet-size 1024 --window 7 \
    get remote.bin "$WORK/got2.bin"
check "  content matches" cmp -s "$WORK/big.bin" "$WORK/got2.bin"
run "packet 128, window 1, TPDU 128" 0 --packet-size 128 --window 1 --tpdu-size 128 \
    put "$WORK/big.bin" small.bin
check "  content matches" cmp -s "$WORK/big.bin" "$SRV/small.bin"
run "without grouping functional unit" 0 --no-grouping get remote.txt "$WORK/g3.txt"
check "  content matches" cmp -s "$WORK/lines.txt" "$WORK/g3.txt"
run "selectors + AP title" 0 --tsel 0x0001 --calling-tsel FTAM --ssel 0x0001 \
    --psel 0x0001 --ap-title 1.3.9999.1 --ae-qualifier 7 ping

# ---- session segmenting ----------------------------------------------------
start_server -s 256
run "segmenting: get (responder limit 256)" 0 -v --tsdu-size 512 get remote.bin "$WORK/seg.bin"
check "  content matches" cmp -s "$WORK/big.bin" "$WORK/seg.bin"
check "  segmenting negotiated" grep -q "segmenting: TSDU max 256 (send), 512 (receive)" "$WORK/t$N.err"
run "segmenting: put" 0 --tsdu-size 300 put "$WORK/big.bin" segup.bin
check "  content matches" cmp -s "$WORK/big.bin" "$SRV/segup.bin"
run "segmenting not proposed: responder does not segment" 0 -v ping
check "  no segmenting" bash -c "! grep -q segmenting '$WORK/t$N.err'"

# ---- octet-aligned presentation data values -------------------------------
start_server -O
run "octet-aligned (constructed) PDVs received: binary" 0 get remote.bin "$WORK/oct.bin"
check "  content matches" cmp -s "$WORK/big.bin" "$WORK/oct.bin"
run "octet-aligned PDVs received: text" 0 --text get remote.txt "$WORK/oct.txt"
check "  content matches" cmp -s "$WORK/lines.txt" "$WORK/oct.txt"
start_server
run "octet-aligned PDVs sent: binary, constructed" 0 --octet-aligned --chunk 3000 \
    put "$WORK/big.bin" octup.bin
check "  content matches" cmp -s "$WORK/big.bin" "$SRV/octup.bin"
run "octet-aligned PDVs sent: text, primitive" 0 --octet-aligned --text \
    put "$WORK/lines.txt" octup.txt
check "  content matches" cmp -s "$WORK/lines.txt" "$SRV/octup.txt"

# ---- X.25: D-bit, interrupts, REJ --------------------------------------------
run "D-bit: put with delivery confirmation" 0 -v --dbit put "$WORK/big.bin" dbit.bin
check "  content matches" cmp -s "$WORK/big.bin" "$SRV/dbit.bin"
check "  D-bit agreed" grep -q "D-bit procedure agreed" "$WORK/t$N.err"
run "D-bit: get" 0 --dbit get remote.bin "$WORK/dbit.bin"
check "  content matches" cmp -s "$WORK/big.bin" "$WORK/dbit.bin"

start_server -I cafe01
run "interrupts with user data, both directions" 0 -v --interrupt 0102ff ping
check "  client received ca fe 01" grep -q "INTERRUPT received (3 octets: ca fe 01" "$WORK/t$N.err"
check "  responder received 01 02 ff" grep -q "INTERRUPT received (3 octets: 01 02 ff" "$WORK/ftamd.log"

# the client needs retransmission procedures too: depending on where in
# the window the loss falls, recovery is by REJ or by T25 expiry
for drop in 40 41; do
    start_server -D $drop
    SKIP_TSHARK=1 run "responder loses data packet $drop, client retransmits" 0 \
        -v --rej --t25 500 put "$WORK/big.bin" rej$drop.bin
    check "  content matches" cmp -s "$WORK/big.bin" "$SRV/rej$drop.bin"
    check "  recovered by REJ or T25" bash -c \
        "grep -q 'send REJ' '$WORK/ftamd.log' || grep -q 'T25 expired' '$WORK/t$N.err'"
done
start_server -R -T 500
SKIP_TSHARK=1 FTAM_TEST_DROP=20 run "REJ: client loses a packet, responder retransmits" 0 \
    -v --rej --window 7 get remote.bin "$WORK/rej2.bin"
check "  content matches" cmp -s "$WORK/big.bin" "$WORK/rej2.bin"
check "  client sent REJ" grep -q "send REJ" "$WORK/t$N.err"
SKIP_TSHARK=1 FTAM_TEST_DROP=9 run "T25: last packet of window lost, recovered by timer" 0 \
    --rej get remote.bin "$WORK/rej3.bin"
check "  content matches" cmp -s "$WORK/big.bin" "$WORK/rej3.bin"
check "  responder T25 retransmission" grep -q "T25 expired" "$WORK/ftamd.log"
start_server
SKIP_TSHARK=1 FTAM_TEST_DROP=20 run "without REJ a lost packet resets the call" 1 \
    get remote.bin "$WORK/rej4.bin"
check "  reported as out of sequence" grep -q "out of sequence" "$WORK/t$N.err"

# ---- X.25: Q-bit, RNR ---------------------------------------------------------
start_server -Q 01020304
run "Q-bit data both ways (client's spans 2 packets)" 0 -v \
    --qdata "$(printf 'ab%.0s' $(seq 200))" ping
check "  client received 01 02 03 04" grep -q "qualified data received (4 octets: 01 02 03 04" "$WORK/t$N.err"
check "  responder received 200 octets" grep -q "qualified data received (200 octets" "$WORK/ftamd.log"
start_server -N 800
run "RNR from responder holds the client back" 0 -vv ping
check "  client saw RNR and waited" grep -q "window closed.*RNR" "$WORK/t$N.err"
start_server
run "RNR from a client with a 1-octet receive buffer" 0 -vv --rx-buffer 1 \
    get remote.bin "$WORK/rnr1.bin"
check "  content matches" cmp -s "$WORK/big.bin" "$WORK/rnr1.bin"
check "  client sent RNR" grep -q "send RNR" "$WORK/t$N.err"
start_server -B 1
run "RNR from a responder with a 1-octet receive buffer" 0 -vv put "$WORK/big.bin" rnr2.bin
check "  content matches" cmp -s "$WORK/big.bin" "$SRV/rnr2.bin"
check "  client saw RNR" grep -q "recv RNR" "$WORK/t$N.err"

# ---- session: connect data overflow, extended concatenation -----------------
# Wireshark decodes the first 10240 octets in CN as a whole presentation
# PDU (it does not reassemble CDO), so these captures skip tshark
start_server
SKIP_TSHARK=1 FTAM_TEST_PAD=25000 run "connect data overflow (CN + OA + 2 CDO)" 0 -v \
    get remote.bin "$WORK/ovf.bin"
check "  content matches" cmp -s "$WORK/big.bin" "$WORK/ovf.bin"
check "  sent CDO" grep -q "CDO: .* in 2 SPDU" "$WORK/t$N.err"
check "  responder reassembled" grep -q "connect data complete" "$WORK/ftamd.log"
start_server -s 512
SKIP_TSHARK=1 FTAM_TEST_PAD=12000 run "connect data overflow with segmenting" 0 -v \
    --tsdu-size 1024 ping
check "  CDOs sized to TSDU max" grep -q "CDO: .* in 4 SPDU" "$WORK/t$N.err"
start_server -X
run "extended concatenation received (GT + MIP + DT)" 0 -v --ext-concat \
    get remote.bin "$WORK/ext.bin"
check "  content matches" cmp -s "$WORK/big.bin" "$WORK/ext.bin"
check "  MIP skipped" grep -q "ignoring concatenated category 2 SPDU 49" "$WORK/t$N.err"
run "no extended concatenation unless announced" 0 -v get remote.bin "$WORK/ext2.bin"
check "  plain GT + DT" bash -c "! grep -q 'ignoring concatenated' '$WORK/t$N.err'"

# ---- presentation / ACSE encodings -------------------------------------------
start_server -A
run "arbitrary (BIT STRING) PDVs received" 0 get remote.bin "$WORK/arb.bin"
check "  content matches" cmp -s "$WORK/big.bin" "$WORK/arb.bin"
start_server
run "arbitrary PDVs sent, constructed" 0 --pdv-encoding arbitrary --pdv-segment 700 \
    put "$WORK/big.bin" arb.bin
check "  content matches" cmp -s "$WORK/big.bin" "$SRV/arb.bin"
start_server -E octet -S 40
run "ACSE user-information: segmented octet-aligned both ways" 0 -v \
    --acse-encoding octet --pdv-segment 30 ping
check "  F-TERMINATE-response decoded" grep -q "charging: test 0 units" "$WORK/t$N.err"
start_server -E arbitrary -S 40
run "ACSE user-information: segmented arbitrary both ways" 0 -v \
    --acse-encoding arbitrary --pdv-segment 30 ping
check "  F-TERMINATE-response decoded" grep -q "charging: test 0 units" "$WORK/t$N.err"

# ---- directory listing -----------------------------------------------------
mkdir -p "$SRV/lsdir/sub"
printf 'abc' >"$SRV/lsdir/a.bin"
printf 'hello\n' >"$SRV/lsdir/b.txt"
printf 'x' >"$SRV/lsdir/sub/inner.bin"
printf 'a.bin\nb.txt\nsub/\n' >"$WORK/ls.expected"

start_server
run "ls with F-LIST (auto, FTAM version 2)" 0 -v ls lsdir
check "  names" cmp -s "$WORK/ls.expected" "$WORK/t$N.out"
check "  used F-LIST" grep -q "with F-LIST" "$WORK/t$N.err"
run "dir: type, size, date" 0 dir lsdir
check "  file sizes" bash -c "grep -q '^-  *3  .*a.bin\$' '$WORK/t$N.out' && grep -q '^-  *6  .*b.txt\$' '$WORK/t$N.out'"
check "  directory marked" grep -q "^d .* sub/\$" "$WORK/t$N.out"
run "ls of a subdirectory" 0 ls lsdir/sub
check "  names" bash -c "[ \"\$(cat '$WORK/t$N.out')\" = inner.bin ]"
run "ls of a missing directory fails" 1 ls nosuchdir
check "  diagnostic 3000" grep -q "error 3000" "$WORK/t$N.err"
run "ls with NBS-9 forced" 0 -v --list-method nbs9 ls lsdir
check "  names" cmp -s "$WORK/ls.expected" "$WORK/t$N.out"
check "  used NBS-9, version 1 only" bash -c \
    "grep -q 'with NBS-9' '$WORK/t$N.err' && grep -q 'protocol version: version-1\$' '$WORK/t$N.err'"
run "other commands still negotiate version 1 only" 0 -v ping
check "  version 1" grep -q "protocol version: version-1\$" "$WORK/t$N.err"

start_server -L
run "ls falls back to NBS-9 without version 2" 0 -v ls lsdir
check "  names" cmp -s "$WORK/ls.expected" "$WORK/t$N.out"
check "  used NBS-9" grep -q "with NBS-9" "$WORK/t$N.err"
run "dir with NBS-9" 0 dir lsdir
check "  directory marked" grep -q "^d .* sub/\$" "$WORK/t$N.out"
run "F-LIST forced without version 2 fails clearly" 1 --list-method flist ls lsdir
check "  explains why" grep -q "F-LIST needs FTAM version 2" "$WORK/t$N.err"
start_server -L -O
run "NBS-9 entries in octet-aligned PDVs" 0 ls lsdir
check "  names" cmp -s "$WORK/ls.expected" "$WORK/t$N.out"

start_server -w secret
run "password accepted" 0 -u alice -p secret ping
run "wrong password rejects association" 1 -u alice -p wrong ping
check "  diagnostic 2020" grep -q "error 2020" "$WORK/t$N.err"

echo
echo "$PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
