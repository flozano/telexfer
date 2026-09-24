# TELEXFER — FTAM file transfer over X.25 (XOT or Linux kernel) and RFC 1006

```
#####  #####  #      #####  #   #  #####  #####  ####
  #    #      #      #       # #   #      #      #   #
  #    ####   #      ####     #    ####   ####   ####
  #    #      #      #       # #   #      #      #  #
  #    #####  #####  #####  #   #  #      #####  #   #

     ISO 8571 FTAM * OSI stack * XOT and RFC 1006
```

The binaries are `ftam` (client) and `ftamd` (test responder).

A dependency-free C11 implementation of an ISO 8571 FTAM initiator. It talks
to an OSI responder in one of two ways:

- over X.25 carried over TCP (XOT, RFC 1613), for partners on an X.25
  network behind a router
- over the Linux kernel's own X.25 (`AF_X25`), for X.25 lines attached to
  the machine itself: a synchronous serial card, or LAPB over Ethernet
- directly over TCP (RFC 1006, port 102), the usual way on IP networks

It covers the whole stack; nothing comes from ISODE or any other OSI
library.

| Layer        | Standard                     | File              |
|--------------|------------------------------|-------------------|
| FTAM         | ISO 8571-4                   | `src/ftam.c`, `src/ftam_pdu.c` |
| ACSE         | ISO 8650 / X.227             | `src/pres.c`      |
| Presentation | ISO 8823 / X.226 (normal mode) | `src/pres.c`    |
| Session      | ISO 8327 / X.225 (kernel, duplex, v1/v2) | `src/session.c` |
| Transport    | ISO 8073 / X.224 class 0     | `src/tp0.c`       |
| Network      | X.25 PLP (ISO 8208), mod 8/128, over XOT (RFC 1613, TCP port 1998) | `src/x25.c` |
| ...or        | the Linux kernel's X.25 (`AF_X25` sockets) | `src/x25linux.c` |
| ...or        | RFC 1006: TPKT over TCP, port 102 | `src/rfc1006.c` |
| TCP          | connect/listen, deadline I/O | `src/tcp.c`       |
| ASN.1        | BER (X.690)                  | `src/ber.c`       |

## Build

```sh
make            # builds ./ftam (client) and ./ftamd (test responder)
make test       # end-to-end test suite (uses tshark if installed)
tests/isode-interop.sh   # against ISODE's FTAM responder (needs Docker)
sudo tests/kernel-x25.sh # over the Linux kernel's X.25 (Linux, root)
```

## Usage

```sh
# fetch a binary file (FTAM-3)
ftam -H xot-router.example:1998 -A 26245000012 -a 26245000099 \
     --tsel 0x0001 --ssel 0x0001 --psel 0x0001 \
     -u USER -p PASSWORD  get REMOTE.DAT local.dat

# send a text file (FTAM-1), replacing it if it already exists
ftam -H 10.1.1.1 -A 1234567 --text --force put report.txt REPORT

# the same over TCP/IP, without X.25 (RFC 1006, port 102)
ftam --transport rfc1006 -H ftam.example --tsel 0x0001 --ssel 0x0001 \
     --psel 0x0001 -u USER -p PASSWORD get REMOTE.DAT local.dat

ftam ... attr REMOTE.DAT          # file attributes
ftam ... rename OLD NEW
ftam ... delete REMOTE.DAT
ftam ... ping                     # associate + release only
ftam ... ls [DIR]                 # directory listing (names)
ftam ... dir [DIR]                # ... with type, size, modification time
```

Run `ftam --help` for every option. The ones you will usually need to match
the responder's configuration are:

- **Transport:** `--transport xot` (the default), `rfc1006` or `x25`. The
  default port follows the transport: 1998 or 102. Options that don't apply
  to the chosen transport are refused rather than silently ignored.
  - **`x25` (Linux only):** the kernel's X.25. There's no `--host`; the
    kernel routes the call by its called address (`-A`) through the X.25
    route table. `-a`, `--cud`, `--packet-size` and `--window` go to the
    kernel as call parameters. TELEXFER's own X.25 options (`--mod128`,
    `--rej`, `--dbit`, …) don't apply, because the kernel runs X.25. Neither
    does `--pcap`: capture on the X.25 interface instead.
- **X.25:** `-A` called and `-a` calling X.121 addresses, `--packet-size`,
  `--window`, `--mod128`. The call user data defaults to `03010100` (the
  ISO/TR 9577 identifier for ISO 8073 transport). Override it with
  `--cud HEX`, or pass `--cud ""` to send none.
- **OSI selectors:** `--tsel`, `--ssel`, `--psel` and their `--calling-*`
  forms. A plain value is sent as ASCII text; prefix it with `0x` or `hex:`
  for binary.
- **ACSE:** `--ap-title OID` and `--ae-qualifier N`, if the responder checks
  AE titles.
- **Password:** `-p`, or set `$FTAM_PASSWORD` to keep it out of `ps` output.

Optional procedures, off by default because the peer has to support them:

| Option | Layer | Effect |
|---|---|---|
| `--rej` | X.25 | Packet retransmission. A missing packet is answered with REJ instead of a reset. Unacknowledged packets are resent when REJ arrives or the window rotation timer T25 expires (`--t25 MS`, at most 3 times without progress). |
| `--dbit` | X.25 | Asks for the D-bit procedure. If the called DTE agrees, each TSDU ends with a D=1 packet and is not complete until the far end confirms delivery. |
| `--interrupt HEX` | X.25 | Sends an INTERRUPT carrying 1 to 32 octets once the call is up. Interrupts the peer sends are always confirmed and logged (`-v`) with their data. |
| `--qdata HEX` | X.25 | Sends a qualified (Q-bit) packet sequence once the call is up. Qualified data from the peer is control information (X.29 style): it is logged (`-v`) and never passed to the transport. |
| `--rx-buffer N` | X.25 | Sends RNR when more than N octets of received data are waiting for the upper layers, and RR once they drop to half (default 65536). |
| `--tsdu-size N` | Session | Proposes segmenting. Large SSDUs are split into DT SPDUs with Enclosure Items, and incoming segments are reassembled. |
| `--ext-concat` | Session | Announces (protocol options) that we accept extended concatenated SPDUs. |
| `--pdv-encoding E` | Presentation | How `put` carries data values: `single` (single-ASN1-type, default), `octet` (octet-aligned) or `arbitrary` (BIT STRING). The latter two are sent constructed above `--pdv-segment` octets (default 1000). `--octet-aligned` is short for `octet`. All encodings, segmented or not, are always accepted on receive. |
| `--acse-encoding E` | ACSE | The same choice for the FTAM PDU inside the user-information EXTERNAL of AARQ, RLRQ and ABRT. |

Connect user data longer than 10240 octets is sent automatically with the
session data overflow procedure (CN + OA + CDO).

### Debugging against a real responder

- `-v` logs events per layer; `-vv` adds packet-level detail; `-vvv` adds hex
  dumps.
- `--pcap FILE` writes the TCP byte stream as a pcap file. Wireshark then
  decodes every layer up to FTAM, from XOT or from TPKT. On a port other
  than 1998 or 102, add `-d tcp.port==PORT,xot` or `-d tcp.port==PORT,tpkt`.

## Collecting billing files (`collect`)

`collect` polls a responder for files named with a constant prefix plus a
rotating sequence number, e.g. `AMA0001` … `AMA9999`, then `AMA0001` again.
Switches such as a 5ESS present their AMA/CDR files this way. Run it from
cron or a systemd timer:

```sh
ftam --transport rfc1006 -H switch.example --tsel … --ssel … --psel … \
     -u USER collect --name AMA%04d --seq-range 1-9999 \
     --dest /var/spool/cdr/switch1 [--start 1] [--ack none|delete|rename]
```

Each run collects every finished file since the last one, in sequence order.
It prints one line per file for reconciliation:

```
collected seq=17 name=AMA0017 size=204800 time=20260924T031000Z sha256=… local=…/AMA0017.20260924T031000Z
gap seq=18 name=AMA0018
```

**How it decides.** The switch usually keeps its files and overwrites them
in rotation (`--ack none`, the default), so a name alone says nothing:

- **Generation.** A file at the next sequence number is new only if it is
  not older than the last one collected, using its creation time (or its
  modification time). Otherwise it is last cycle's file. A per-sequence
  SHA-256 of what was collected is the second check.
- **Finished.** A file counts as done once a newer file exists further
  along the sequence (up to `--lookahead` places), because then the switch
  has moved on. Under rotation the following name always exists, so
  "newer" matters.
- **No times.** If the switch reports neither creation nor modification
  time, neither rule can work. `collect` then refuses, unless you assert
  with `--closed any` that the switch only shows finished files. The
  SHA-256 check alone then catches last cycle's files.
- **Gaps.** A missing (or stale) sequence number with a newer file after it
  is reported as a `gap` line and exit code 3. Collection carries on, so
  one lost file doesn't hold up everything behind it.

**Nothing is lost or taken twice.**
1. Each file is downloaded to a temp file, `fsync`ed, and its size checked
   against the switch's.
2. It is renamed into place. Local names carry the file's time, so a wrap
   never overwrites an earlier file.
3. The state file (default `DEST/.telexfer-state`) is rewritten atomically.
   That write is the commit point.
4. Only then is the file acknowledged on the switch (`--ack delete`, or
   `--ack rename`, default new name `%s.DONE`).

A crash at any point is safe on the next run. A file already on disk with
the same SHA-256 is not stored twice. A failed acknowledgement is reported
(`ack-failed` line, exit code 5) and never undone. A lock taken before
dialling keeps overlapping runs apart (exit code 4). The first run needs
`--start`.

**What is not verified yet** against a real 5ESS: whether it reports
creation/modification times through F-READ-ATTRIB, the exact file names,
and whether reading attributes needs a service class or functional unit it
doesn't grant. Without *limited file management*, `collect` falls back to an
existence check (select/deselect), which means no times, so `--closed any`.
The first session against the switch with `-vv --pcap` will answer all of
this.

## Protocol behaviour

- **Association.**
  - Presentation contexts proposed:
    - ACSE (`2.2.1.0.1`)
    - FTAM PCI (`1.0.8571.2.1`)
    - unstructured text (`1.0.8571.2.3`)
    - unstructured binary (`1.0.8571.2.4`)

    All use BER.
  - Application context: `1.0.8571.1.1`.
  - Service classes proposed: management, transfer, and
    transfer-and-management.
  - Functional units proposed: read, write, limited and enhanced file
    management, and grouping.
  - Attribute group proposed: storage.
- **Regimes.** If the responder grants grouping, select/open and close/deselect
  are sent as `F-BEGIN-GROUP … F-END-GROUP`, all in a single P-DATA with one
  PDV-list per PDU. ISODE aborts a group that is spread over several
  P-DATAs. Otherwise (`--no-grouping`, or not granted) the requests go one
  at a time. If a step fails, the client unwinds
  the regime, for example by deselecting when the select succeeded but the open
  failed.
- **Read.** `F-READ` with FADU identity *first* and access context
  *unstructured-all-data-units*.
- **Write.** Create, then open, then `F-WRITE` with FADU operation *replace*,
  or *extend* with `--append`. Overwrite (`--force`) uses create override
  *delete-and-create-with-new-attributes*.
- **Text (FTAM-1).** Text is sent as GeneralString with the line ends inside,
  declared with universal class GeneralString and string significance
  *not-significant*. That's the parameter ISODE generates for its own text
  files. On the wire lines end in CR LF, like FTP's ASCII mode: local LF is
  converted on put and converted back on get.
  - **Reading:** the string type decides. GraphicString, PrintableString and
    VisibleString can't hold control characters, so each such string is one
    line and gets a newline. The others (GeneralString, IA5String, …) are
    written as they are, after the CR LF conversion.
- **Release and abort.** `F-TERMINATE` travels over A-RELEASE (session FN/DN);
  errors lead to `F-U-ABORT` over A-ABORT. Class 0 has no transport
  disconnect of its own, so the network connection is then released: the
  X.25 call is cleared, or with RFC 1006 the TCP connection is closed.
- **RFC 1006.** TP0 is unchanged; only the network service below it
  differs. Each TPDU travels in a TPKT (version 3, 16-bit length), and there
  is no network connection setup. `--tpdu-size` goes up to 8192 here, while
  class 0 over X.25 stops at 2048. The default stays 2048 on both, because a
  strict class 0 responder may refuse larger sizes. The responder may lower
  whatever is proposed. The X.25 procedures (REJ, D-bit, Q-bit, interrupts,
  RNR) don't exist over TCP; TCP provides reliability and flow control.
- **Directory listing.** There are two methods, and `--list-method` picks
  one (default `auto`):
  - **F-LIST** (`flist`) is the filestore-management PDU of FTAM version 2.
    It needs the *limited filestore management* functional unit. The request
    matches every pathname in the directory, non-recursively (scope *child*).
  - **NBS-9** (`nbs9`) is the older convention that most version-1
    responders support. The directory is selected and opened as an NBS-9
    *file directory file* (`1.3.14.5.5.9`), and each data element read
    is one entry's attributes. The entries use
    abstract syntax `1.3.14.5.2.2`, proposed as its own presentation
    context. The details follow ISODE, the reference implementation:
    - the parameter is `[0] IMPLICIT Attribute-Names`
    - each entry is `[PRIVATE 2] Read-Attributes`
    - the read uses unstructured-all-data-units, since ISODE refuses any
      other access context; if a responder refuses that, the client retries
      with flat-all-data-units
    - entry names may be paths from the home directory, as with ISODE, and
      are shown relative to the directory listed

  Only `ls`/`dir` offer protocol version 2; every other command negotiates
  exactly as before. `auto` uses F-LIST when the responder grants version 2
  and the functional unit, and NBS-9 otherwise. Both ask for the pathname
  and the contents type; the modification time and size are added with the
  storage attribute group, and the object type with version 2. A directory
  is recognised by object type *file-directory* or by the NBS-9 contents
  type.
- **Diagnostics.** Responder diagnostics are shown with their ISO 8571 error
  number and text, e.g. `error 3004: non-existent file`.
- **X.25 sequencing.** Without `--rej`, an out-of-sequence packet resets the
  call. TP0 cannot recover lost data, so the transfer fails with a clear
  error. With `--rej`, only a packet ahead of V(R) inside the window counts as
  a gap and triggers REJ, once per REJ condition. Duplicates left over from a
  retransmission are dropped silently, so they don't start a REJ storm.
- **X.25 flow control.** RNR is sent when the receive buffer limit is
  crossed, or when the application calls `x25_set_busy()`. Only complete
  NSDUs count toward the limit: a half-reassembled packet sequence always
  gets to finish, otherwise the call would deadlock. P(R) values carried
  while not ready are sent as RNR, never RR.
- **Q-bit.** Every packet in a complete packet sequence must carry the same
  Q-bit; a change inside a sequence resets the call (diagnostic 83).
- **Session segmenting.** Each direction uses the lower of the two proposed
  limits, where 0 means unlimited. The responder's AC is final. Only DT SPDUs
  are segmented; each segment travels as GT + DT (basic concatenation) with
  an Enclosure Item.
- **Connect data overflow.** Above 10240 octets, the CN carries the first
  10240 in extended user data (PGI 194) plus Data Overflow (PI 60). After
  the responder's OA, the rest follows in CDO SPDUs, sized to the TSDU
  maximum if segmenting was agreed, with the end bit set in the last
  Enclosure Item.
- **Extended concatenation.** Received TSDUs may hold a category 0 SPDU,
  then any number of category 2 SPDUs, then a DT. With the functional units
  FTAM uses, the only possible extra SPDUs belong to synchronization and
  activity management, which are never negotiated, so they are logged and
  skipped. We never send extended concatenation ourselves; the test
  responder does (`-X`).

## Testing

`tests/ftamd.c` is a small FTAM responder that serves a directory over XOT
or RFC 1006 (`-t rfc1006`). `tests/run.sh` runs the client against it over
both transports.

- **Every test that doesn't depend on the network below TP0 runs twice**,
  once per transport.
- **XOT only:** the X.25 tests.
- **RFC 1006 only:** TPDU sizes 8192 and 128, and the refusal of X.25
  options.

The tests cover get and put in both text and
binary, a 300 KB transfer, overwrite and append, attributes, rename, delete,
error paths and a rejected password. It also exercises X.25 edge cases:
mod 128 with 1024-byte packets, window 1 with 128-byte TPDUs, and running
without grouping.

The optional procedures are covered too:

- session segmenting in both directions, with the responder limit (`-s`)
  lower than the client's proposal
- constructed and primitive octet-aligned PDVs, sent and received
- D-bit transfers
- interrupts with data in both directions
- packet loss, injected by the test hook (`ftamd -D N`, `FTAM_TEST_DROP=N`),
  recovered by REJ or by T25 expiry, plus a check that without `--rej` the
  loss is reported as a failure
- Q-bit data both ways, including a qualified NSDU spanning two packets
- RNR in both directions: a responder that holds the client back for 800 ms
  (`-N`), and 1-octet receive buffers on either side (a 300 KB transfer with
  RNR/RR around every message)
- connect data overflow (25 KB in CN + 2 CDO; 12 KB with segmenting, in 4
  CDO), using the test hook `FTAM_TEST_PAD=N` to pad the F-INITIALIZE
- extended concatenation (GT + MIP + DT, sent only after the client
  announced it)
- arbitrary PDVs sent and received
- segmented octet-aligned and arbitrary user-information in both directions
- `collect` over both transports:
  - first poll, nothing new, a file closed by the next one
  - a file held back because the name after it is last cycle's
  - the wrap and both generations kept on disk
  - a gap, the overlapping-run lock, `--ack delete` and `--ack rename`
  - a responder without times (`ftamd -G`): refusal, `--closed any`, and
    SHA-256 recognising last cycle's file
- directory listing via F-LIST (auto and forced) and NBS-9 (forced, as the
  fallback from a version-1-only responder `ftamd -L`, and with entries in
  octet-aligned PDVs), plus subdirectories, a missing directory, and F-LIST
  refused without version 2

A few runs skip the tshark check, each for a reason in the capture rather
than the code:

- **Loss injection.** The dropped packet is still in the capture, so
  Wireshark's X.25 reassembly counts it twice.
- **Connect data overflow.** Wireshark decodes the first 10240 octets in the
  CN as if they were the complete presentation PDU, because it does not
  reassemble CDOs. It does name OA, CDO, Data Overflow and the Enclosure
  Items correctly.

- **Arbitrary-encoded ACSE user-information.** Wireshark reads a
  constructed (segmented) BIT STRING there as if it were primitive, and never
  decodes arbitrary contents as FTAM. It can only confirm that nothing is
  malformed. Our own client and responder decode it, which the test checks.

When `tshark` is available, every capture is decoded by Wireshark's
dissectors (XOT and X.25, or TPKT; then COTP, SES, PRES, ACSE and FTAM). Any
malformed packet or BER error fails the test. For every run that is expected
to succeed, the decode must also contain FTAM. Otherwise a capture Wireshark
couldn't parse would pass silently; adding this found exactly one such case,
the one listed above. This is the check that does not depend on my own
reading of the standards. It caught three wrong encodings in the test
responder during development. All 303 checks also pass under ASan and UBSan,
and CI runs both on Ubuntu.

For directory listing, the F-LIST tags were not taken from memory. They
were found by feeding candidate encodings to Wireshark's FTAM dissector,
which has the full FTAM version 2 grammar. That established:

- FSM-PDUs are context-specific, with F-LIST at `[43]`/`[44]`
- the scope and filter are `[APPLICATION 28]`/`[APPLICATION 26]`
- the object list is `[APPLICATION 25]`
- `object-type` is `[18]` and must directly follow the pathname

Real captures decode completely, down to the any-match filter and each
entry's attributes.

## The Linux kernel's X.25

With `--transport x25`, the kernel runs the X.25 packet layer and the link
below it: LAPB on a synchronous serial line, or LAPB over Ethernet with
`lapbether`. TELEXFER runs TP0 and everything above on an `AF_X25` socket:

- Each message is one complete packet sequence, i.e. one TPDU. It is sent
  with `MSG_EOR`; the kernel refuses anything else.
- Packet and window size, and call user data, are set on the socket before
  the call.
- A call the kernel clears is reported with its cause and diagnostic.

**Setting it up.** The machine needs:
- the modules: `x25`, `lapb`, and `lapbether` for LAPB over Ethernet (on
  Ubuntu that one is in `linux-modules-extra`)
- an X.25 interface that is up
- a route for the called address. `x25route PREFIX DIGITS DEVICE` (built
  with `make x25route`) adds one; for example `x25route 1111 4 lapb0` sends
  calls to `1111…` through `lapb0`.

`ftamd -t x25 -x ADDRESS` answers calls to `ADDRESS`.

**Tested.** `tests/kernel-x25.sh`, in CI, runs on one Linux machine:
- **The link:** a veth pair carries LAPB over Ethernet, and the kernel runs
  X.25 at both ends. The client calls out through one LAPB interface;
  `ftamd` answers behind the other. The two ends are both LAPB DTEs, which
  the kernel's LAPB accepts.
- **What it covers:** binary and text transfers, packet size and window
  negotiation (1024/7, and 128/1 with 128-byte TPDUs), call user data,
  attributes, a missing file, a call to an unknown address being cleared,
  and `collect`.
- **Proof it used the link:** a capture records nothing on the CI runner,
  so the test compares the LAPB interfaces' frame counters before and
  after. About 4,000 frames go each way, so nothing is short-cut inside the
  kernel.

**Kernel details worth knowing:**
- `lapbether` creates a `lapbN` for every Ethernet interface that comes up,
  and only in the host's own network namespace; the same goes for `AF_X25`.
  So the test must run in the host namespace, and it finds its `lapbN` by
  bringing each veth end up separately.
- An incoming call is negotiated down to the *listening* socket's
  facilities, so `ftamd` listens offering 4096/7.

## Interoperability: ISODE

`tests/isode-interop.sh` runs the client against ISODE's FTAM responder
(`tsapd` → `ftamd`, over RFC 1006). ISODE is an implementation written
independently of this one, in the early 1990s, and was the reference for
much of the OSI world. It is built from source (the maintained
[Wildboar Software fork](https://github.com/Wildboar-Software/isode),
pinned) in `interop/isode/`, and the test runs in CI.

34 checks pass:
- association (ISODE picks FTAM version 1, transfer-and-management)
- binary and text round trips, byte-identical on both sides
- attributes, rename, delete, the missing-file diagnostic
- `ls`/`dir` through NBS-9
- `collect` through a rotation, a wrap, a gap and `--ack delete`

**Testing against ISODE changed TELEXFER in four places**, all described
above under protocol behaviour:
- grouped requests go in one P-DATA
- text travels with CR LF line ends, with line handling decided by the
  string type
- the NBS-9 parameter tag and entry wrapper
- the NBS-9 access context

**ISODE bugs found along the way:**
- **`tsapd` no longer compiles at the pinned commit.** Upstream commit
  `43aaabae` declares `ssapd` as a function pointer but defines a function.
  The Dockerfile patches the two declarations back.
- **Years from 2000 on are sent as `01YY`.** A `YEAR()` macro leaves
  `tm_year` (years since 1900) unconverted once it reaches 100, so 2026
  becomes `0126`. TELEXFER repairs a four-digit year of 100–999 by adding
  1900, which matters for `collect`'s ordering.
- **`ftamd -d` crashes on data values of 4096 octets or more,** in its debug
  hex dump. The interop setup runs without `-d` (`FTAMD_DEBUG=1` turns it
  on).
- **Some renames fail with ENOENT inside ISODE.** For example,
  `copyofack/AMA0002` → `copyofack/AMA0002.DONE` fails, while
  `LLLLLLLLL/AMA0002` → `LLLLLLLLL/AMA0002.DONE` works. It depends on the
  names and not on the files, and the request is identical in form. This
  isn't characterised further; the test uses names that work.

## Limitations

**NBS-9 entries are not checked by Wireshark.** Its dissector has no model
of NBS-9 entries: it hands them to the FTAM PDU decoder, which reports
"zero-byte FTAM PDU". The test suite does not count that message as a
failure. The NBS-9 encoding is instead confirmed by ISODE (see
[Interoperability](#interoperability-isode)). The client still accepts an
entry in any wrapping.

**Tested against one independent implementation (ISODE), over RFC 1006
only.** It has not been run against a vendor FTAM responder (a switch, a
bank) or a Cisco XOT router. The places most likely to need adjustment
against those are:

- the call user data (`--cud`), which ISODE, reached over TCP, doesn't use
- the FADU identity and operation used for writes (ISODE accepts them)

**Not implemented:**

- recovery and restart
- FADU locking
- structured files (FTAM-2 etc.)
- concurrency control
- session functional units beyond kernel and duplex (synchronization,
  activities, typed and capability data, expedited data); FTAM does not use
  them
- arbitrary PDVs whose length is not a whole number of octets. They can't
  hold BER values, so they are rejected with a clear error
