#!/usr/bin/env bash
# Run ISODE's tsapd on RFC 1006 (TCP) with ftamd behind transport
# selector #259 (octets 0x0103), serving the home directory of a local
# user that FTAM initiators log in as.
#
# Environment: FTAM_USER (ftam), FTAM_PASSWORD (secret), PORT (10102),
# FTAMD_DEBUG (empty; "1" runs ftamd -d)
set -euo pipefail

FTAM_USER=${FTAM_USER:-ftam}
FTAM_PASSWORD=${FTAM_PASSWORD:-secret}
PORT=${PORT:-10102}
HOME_DIR=/srv/ftam
ETC=/usr/local/etc/isode

pick() { for f in "$@"; do [ -x "$f" ] && { echo "$f"; return; }; done; }
TSAPD=$(pick /usr/local/sbin/tsapd /isode/support/xtsapd)
FTAMD=$(pick /usr/local/sbin/iso.ftam /usr/local/sbin/ftamd /isode/ftam2/xftamd)
[ -n "$TSAPD" ] && [ -n "$FTAMD" ] || { echo "tsapd/ftamd not found" >&2; exit 1; }

# the FTAM user: ftamd checks the password with crypt(), against
# /etc/shadow or, without shadow support, /etc/passwd
if ! id "$FTAM_USER" >/dev/null 2>&1; then
    useradd -d "$HOME_DIR" -m -s /bin/sh "$FTAM_USER"
fi
echo "$FTAM_USER:$FTAM_PASSWORD" | chpasswd
HASH=$(openssl passwd -6 -salt telexfer "$FTAM_PASSWORD")
awk -F: -v u="$FTAM_USER" -v h="$HASH" 'BEGIN { OFS=":" } $1 == u { $2 = h } { print }' \
    /etc/passwd >/etc/passwd.new && cat /etc/passwd.new >/etc/passwd && rm /etc/passwd.new
chown -R "$FTAM_USER" "$HOME_DIR"

mkdir -p "$ETC" /var/log/isode
cp /isode/support/isomacros /isode/support/isobjects "$ETC/" 2>/dev/null || true
cp /isode/ftam/isodocuments "$ETC/" 2>/dev/null || true
cat >"$ETC/isoservices" <<EOF
"tsap/filestore"		#259		$FTAMD${FTAMD_DEBUG:+ -d}
EOF
cat >"$ETC/isoentities" <<EOF
default		filestore	1.17.4.0.16	#259/localHost=$PORT
EOF
cat >"$ETC/isotailor" <<EOF
etcpath:	$ETC/
logpath:	/var/log/isode/
tsaplevel:	all
tsapfile:	tsapd.log
ssaplevel:	exceptions
ssapfile:	ssap.log
psaplevel:	exceptions
psapfile:	psap.log
acsaplevel:	exceptions
acsapfile:	acsap.log
EOF

echo "isode: $TSAPD on TCP $PORT, ftamd $FTAMD, user $FTAM_USER, files in $HOME_DIR"
exec "$TSAPD" -f -t -r -p "$PORT"
