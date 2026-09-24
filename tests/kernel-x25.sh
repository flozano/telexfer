#!/usr/bin/env bash
#
# FTAM over the Linux kernel's X.25 (--transport x25), end to end, on one
# machine: a veth pair carries LAPB over Ethernet (lapbether), the kernel
# runs the X.25 packet layer on both ends, the client calls out through
# one LAPB interface and ftamd -t x25 answers behind the other.
#
# Needs Linux, root (modules, interfaces, routes) and the x25, lapb and
# lapbether modules (lapbether is in linux-modules-extra on Ubuntu).
# Exits 77 when kernel X.25 is not available.
#
#   sudo tests/kernel-x25.sh
#
set -u
cd "$(dirname "$0")/.."

SERVER=11110001            # X.121 address ftamd listens on
CLIENT=22220001
WORK=$(mktemp -d "${TMPDIR:-/tmp}/kx25test.XXXXXX")
SRV=$WORK/srv
PASS=0
FAIL=0
SRVPID=
CAPPID=

cleanup() {
    [ -n "$SRVPID" ] && kill "$SRVPID" 2>/dev/null
    [ -n "$CAPPID" ] && kill "$CAPPID" 2>/dev/null
    wait 2>/dev/null
    ip link del txv0 2>/dev/null
    if [ $FAIL -eq 0 ]; then rm -rf "$WORK"; else echo "artifacts kept in $WORK"; fi
}
trap cleanup EXIT

[ "$(uname -s)" = Linux ] || { echo "kernel X.25 needs Linux"; exit 77; }
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 2; }
for m in x25 lapb lapbether; do
    modprobe "$m" 2>/dev/null || { echo "kernel module $m not available"; exit 77; }
done

# veth ends come up one at a time: lapbether creates one lapbN per
# Ethernet device that comes up, so the new one belongs to that end
lapbs() { ls /sys/class/net | grep '^lapb' | sort; }
up_and_find() {
    local before after
    before=$(lapbs)
    ip link set "$1" up
    for _ in $(seq 50); do
        after=$(lapbs)
        [ "$after" != "$before" ] && break
        sleep 0.1
    done
    comm -13 <(echo "$before") <(echo "$after") | head -1
}
ip link del txv0 2>/dev/null
ip link add txv0 type veth peer name txv1 || exit 1
L0=$(up_and_find txv0)
L1=$(up_and_find txv1)
if [ -z "$L0" ] || [ -z "$L1" ]; then
    echo "lapbether created no LAPB interfaces for the veth pair"
    exit 1
fi
ip link set "$L0" up
ip link set "$L1" up
echo "LAPB over Ethernet: $L0 (txv0) <-> $L1 (txv1)"
# calls to the server's address leave through the client's side
./x25route "$SERVER" 8 "$L0" || exit 1

if command -v tshark >/dev/null; then
    tshark -q -i txv0 -w "$WORK/txv0.pcapng" >/dev/null 2>&1 &
    CAPPID=$!
    sleep 1
fi

mkdir -p "$SRV"
head -c 200000 /dev/urandom >"$WORK/big.bin"
printf 'line one\nline two\n\nline four with\ttab\n' >"$WORK/lines.txt"
cp "$WORK/big.bin" "$SRV/remote.bin"
./ftamd -t x25 -x "$SERVER" -d "$SRV" -v >"$WORK/ftamd.log" 2>&1 &
SRVPID=$!
sleep 0.5

N=0
run() {
    local name=$1 want=$2
    shift 2
    N=$((N + 1))
    ./ftam --transport x25 -A "$SERVER" -a "$CLIENT" --timeout 20 "$@" \
        >"$WORK/t$N.out" 2>"$WORK/t$N.err"
    local got=$?
    if [ "$got" -ne "$want" ]; then
        echo "FAIL  $name (exit $got, expected $want)"
        sed 's/^/      /' "$WORK/t$N.err"
        FAIL=$((FAIL + 1))
        return 1
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

run "associate and release over kernel X.25" 0 -v ping
check "  call went through the kernel" grep -q "CALL CONNECTED" "$WORK/t$N.err"
run "get binary (200 KB)" 0 get remote.bin "$WORK/got.bin"
check "  content matches" cmp -s "$WORK/big.bin" "$WORK/got.bin"
run "put binary (200 KB)" 0 put "$WORK/big.bin" up.bin
check "  content matches" cmp -s "$WORK/big.bin" "$SRV/up.bin"
run "put text" 0 --text put "$WORK/lines.txt" lines.txt
run "get text" 0 --text get lines.txt "$WORK/lines.back"
check "  content matches" cmp -s "$WORK/lines.txt" "$WORK/lines.back"
run "packet size 1024, window 7" 0 -v --packet-size 1024 --window 7 get remote.bin "$WORK/g2.bin"
check "  content matches" cmp -s "$WORK/big.bin" "$WORK/g2.bin"
run "packet size 128, window 1, TPDU 128" 0 --packet-size 128 --window 1 --tpdu-size 128 \
    put "$WORK/big.bin" small.bin
check "  content matches" cmp -s "$WORK/big.bin" "$SRV/small.bin"
run "call user data" 0 --cud 03010100 ping
run "attr / ls / dir" 0 attr remote.bin
check "  filesize" grep -q "filesize *200000" "$WORK/t$N.out"
run "missing file" 1 get nosuchfile "$WORK/none"
check "  diagnostic 3000" grep -q "error 3000" "$WORK/t$N.err"
run "call to an unknown address is cleared" 1 -A 99990001 --timeout 10 ping

mkdir -p "$SRV/AMA" "$WORK/coll"
for i in 1 2 3; do printf "rec$i" >"$SRV/AMA/F$i"; touch -t 20260101000$i "$SRV/AMA/F$i"; done
run "collect" 0 collect --name AMA/F%d --seq-range 1-9 --dest "$WORK/coll" --start 1
check "  1 and 2 collected" bash -c "[ \$(grep -c '^collected ' '$WORK/t$N.out') = 2 ]"

if [ -n "$CAPPID" ]; then
    sleep 1
    kill "$CAPPID" 2>/dev/null
    wait "$CAPPID" 2>/dev/null
    CAPPID=
    check "capture on txv0 has LAPB and X.25 frames" bash -c \
        "tshark -r '$WORK/txv0.pcapng' 2>/dev/null | grep -Eq 'X\\.25|LAPB'"
fi

echo
echo "kernel X.25: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
