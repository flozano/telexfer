#!/usr/bin/env bash
#
# Interoperability test: the ftam client against ISODE's FTAM responder
# (tsapd -> ftamd over RFC 1006), an implementation written independently
# of this one.  Needs Docker; builds interop/isode unless ISODE_IMAGE names
# an existing image.
#
#   tests/isode-interop.sh
#
# Environment: ISODE_PORT (10102), ISODE_IMAGE (telexfer-isode)
#
set -u
cd "$(dirname "$0")/.."

PORT=${ISODE_PORT:-10102}
IMAGE=${ISODE_IMAGE:-telexfer-isode}
NAME=telexfer-isode-$$
WORK=$(mktemp -d "${TMPDIR:-/tmp}/isodetest.XXXXXX")
PASS=0
FAIL=0

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1
    if [ $FAIL -eq 0 ]; then rm -rf "$WORK"; else echo "artifacts kept in $WORK"; fi
}
trap cleanup EXIT

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "building $IMAGE (ISODE from source)..."
    docker build -q -t "$IMAGE" interop/isode >/dev/null || exit 1
fi
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:10102" "$IMAGE" >/dev/null || exit 1
for _ in $(seq 100); do
    docker exec "$NAME" sh -c 'ss -ltn 2>/dev/null | grep -q ":10102 "' && break
    sleep 0.1
done

# files on the ISODE side, owned by the FTAM user
on_isode() { docker exec "$NAME" sh -c "$1 && chown -R ftam /srv/ftam"; }

N=0
run() {
    local name=$1 want=$2
    shift 2
    N=$((N + 1))
    ./ftam --transport rfc1006 -H "127.0.0.1:$PORT" --tsel 0x0103 -u ftam -p secret \
        --timeout 20 --pcap "$WORK/t$N.pcap" "$@" >"$WORK/t$N.out" 2>"$WORK/t$N.err"
    local got=$?
    if [ "$got" -ne "$want" ]; then
        echo "FAIL  $name (exit $got, expected $want)"
        sed 's/^/      /' "$WORK/t$N.err"
        FAIL=$((FAIL + 1))
        return 1
    fi
    if command -v tshark >/dev/null; then
        local bad
        bad=$(tshark -r "$WORK/t$N.pcap" -d "tcp.port==$PORT,tpkt" -V 2>/dev/null |
              grep -E "Malformed|BER Error|Wrong field|Exception occurred|Dissector bug" | head -3)
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

head -c 200000 /dev/urandom >"$WORK/big.bin"
printf 'line one\nline two\n\nline four with\ttab\n' >"$WORK/lines.txt"

run "associate and release" 0 -v ping
check "  ISODE chose FTAM version 1, transfer-and-management" \
    bash -c "grep -q 'protocol version: version-1\$' '$WORK/t$N.err' && grep -q 'service class: transfer-and-management' '$WORK/t$N.err'"

run "put binary (200 KB, FTAM-3)" 0 put "$WORK/big.bin" big.bin
check "  stored byte-identical on ISODE" \
    bash -c "docker exec $NAME cat /srv/ftam/big.bin | cmp -s - '$WORK/big.bin'"
run "get binary" 0 get big.bin "$WORK/big.back"
check "  byte-identical" cmp -s "$WORK/big.bin" "$WORK/big.back"

run "put text (FTAM-1)" 0 --text put "$WORK/lines.txt" lines.txt
check "  ISODE stores it with local line ends" \
    bash -c "docker exec $NAME cat /srv/ftam/lines.txt | cmp -s - '$WORK/lines.txt'"
run "get text" 0 --text get lines.txt "$WORK/lines.back"
check "  byte-identical, empty line kept" cmp -s "$WORK/lines.txt" "$WORK/lines.back"

run "attributes" 0 attr big.bin
check "  size 200000" grep -q "filesize *200000" "$WORK/t$N.out"
check "  dates repaired (ISODE sends 2026 as 0126)" \
    bash -c "grep -E 'modified +20[0-9]{2}' '$WORK/t$N.out' >/dev/null"

run "missing file" 1 get nosuchfile "$WORK/none"
check "  diagnostic 3000" grep -q "error 3000" "$WORK/t$N.err"

on_isode "mkdir -p /srv/ftam/ls/sub && printf abc >/srv/ftam/ls/a.bin && printf 'hello\n' >/srv/ftam/ls/b.txt"
run "ls (NBS-9, as ISODE has no F-LIST)" 0 -v ls ls
check "  used NBS-9" grep -q "with NBS-9" "$WORK/t$N.err"
check "  entries" bash -c "grep -qx a.bin '$WORK/t$N.out' && grep -qx b.txt '$WORK/t$N.out' && grep -qx sub/ '$WORK/t$N.out'"
run "dir" 0 dir ls
check "  size and type" bash -c "grep -Eq '^- +3 .* a\\.bin\$' '$WORK/t$N.out' && grep -Eq '^d .* sub/\$' '$WORK/t$N.out'"

on_isode "mkdir -p /srv/ftam/rn && printf x >/srv/ftam/rn/f"
run "rename" 0 rename rn/f rn/g
check "  renamed on ISODE" docker exec "$NAME" test -e /srv/ftam/rn/g -a ! -e /srv/ftam/rn/f
run "delete" 0 delete rn/g
check "  gone from ISODE" docker exec "$NAME" test ! -e /srv/ftam/rn/g

# collect: rotation, wrap, gap, as a switch would present its files
mk() { on_isode "mkdir -p /srv/ftam/AMA && printf '%s' '$2' >/srv/ftam/AMA/F$1 && touch -t $3 /srv/ftam/AMA/F$1"; }
D=$WORK/coll
mkdir -p "$D"
C=(collect --name AMA/F%d --seq-range 1-5 --dest "$D")
mk 1 one 202601010001; mk 2 two 202601010002; mk 3 three 202601010003
run "collect: first poll" 0 "${C[@]}" --start 1
check "  1 and 2, 3 still being written" \
    bash -c "[ \$(grep -c '^collected ' '$WORK/t$N.out') = 2 ] && ! grep -q 'seq=3 ' '$WORK/t$N.out'"
mk 4 four 202601010004; mk 5 five 202601010005
run "collect: 5 waits for the wrap" 0 "${C[@]}"
check "  3 and 4" bash -c "grep -q 'seq=3 ' '$WORK/t$N.out' && grep -q 'seq=4 ' '$WORK/t$N.out' && ! grep -q 'seq=5 ' '$WORK/t$N.out'"
mk 1 one-b 202601010006; mk 2 two-b 202601010007
run "collect: wrap" 0 "${C[@]}"
check "  5 and the new 1, both generations of 1 on disk" \
    bash -c "grep -q 'seq=5 ' '$WORK/t$N.out' && [ \$(ls '$D' | grep -c '^F1\\.') = 2 ]"
mk 4 four-b 202601010008; mk 5 five-b 202601010009
run "collect: gap" 3 "${C[@]}"
check "  gap at 3 reported" grep -q "^gap seq=3 " "$WORK/t$N.out"

on_isode "mkdir -p /srv/ftam/DEL && for i in 1 2 3; do printf x\$i >/srv/ftam/DEL/F\$i; touch -t 20260102000\$i /srv/ftam/DEL/F\$i; done"
mkdir -p "$WORK/coll-del"
run "collect --ack delete" 0 collect --name DEL/F%d --seq-range 1-9 --dest "$WORK/coll-del" \
    --start 1 --ack delete
check "  1 and 2 removed from ISODE, 3 left" \
    docker exec "$NAME" test ! -e /srv/ftam/DEL/F1 -a ! -e /srv/ftam/DEL/F2 -a -e /srv/ftam/DEL/F3

echo
echo "ISODE interop: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
