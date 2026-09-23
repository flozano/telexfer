/*
 * main.c - command line FTAM client over XOT.
 */
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "collect.h"
#include "ftam.h"

static void usage(FILE *f)
{
    fputs(
"usage: ftam [options] <command> [args]\n"
"\n"
"Commands:\n"
"  get <remote> [local]     read a remote file (local \"-\" = stdout)\n"
"  put <local> [remote]     write a local file to the responder\n"
"  delete <remote>          delete a remote file\n"
"  attr <remote>            show remote file attributes\n"
"  rename <old> <new>       rename a remote file\n"
"  ls [dir]                 list a remote directory (names)\n"
"  dir [dir]                list with type, size and modification time\n"
"  collect                  poll rotating-sequence files (billing/CDR style)\n"
"  ping                     establish and release an FTAM association\n"
"\n"
"Network:\n"
"  -H, --host HOST[:PORT]   the peer: an XOT router/gateway (default port\n"
"                           1998) or, with RFC 1006, the responder (port 102)\n"
"      --transport T        xot (default): TP0 over X.25 over TCP (RFC 1613)\n"
"                           rfc1006: TP0 directly over TCP (RFC 1006)\n"
"\n"
"X.25 (XOT only):\n"
"  -A, --called X121        called DTE address\n"
"  -a, --calling X121       calling DTE address\n"
"      --cud HEX            call user data (default 03010100; \"\" = none)\n"
"      --packet-size N      X.25 packet size (default 128)\n"
"      --window N           X.25 window size (default 2)\n"
"      --mod128             modulo 128 sequence numbering\n"
"      --lcn N              logical channel number (default 1)\n"
"      --rej                answer out-of-sequence packets with REJ instead\n"
"                           of a reset, and retransmit unacknowledged\n"
"                           packets when T25 expires\n"
"      --t25 MS             window rotation timer T25 (default: --timeout)\n"
"      --rx-buffer N        send RNR when more than N octets of received\n"
"                           data wait to be processed (default 65536)\n"
"      --qdata HEX          send a qualified (Q-bit) data packet sequence\n"
"                           once the call is connected; received ones are\n"
"                           logged (-v), never passed to the transport\n"
"      --dbit               request the D-bit procedure: every TSDU is sent\n"
"                           with delivery confirmation\n"
"      --interrupt HEX      send an X.25 interrupt carrying these 1..32\n"
"                           octets once the call is connected\n"
"\n"
"OSI addressing (selectors: text, or 0x... / hex:... for binary):\n"
"      --tsel SEL           called transport selector\n"
"      --calling-tsel SEL   calling transport selector\n"
"      --ssel SEL           called session selector\n"
"      --calling-ssel SEL   calling session selector\n"
"      --psel SEL           called presentation selector\n"
"      --calling-psel SEL   calling presentation selector\n"
"      --tpdu-size N        maximum TPDU size, 128..2048 (default 2048);\n"
"                           up to 8192 with --transport rfc1006\n"
"      --tsdu-size N        propose session segmenting with this TSDU\n"
"                           maximum size (64..65535; default: none)\n"
"      --ext-concat         announce that we accept extended concatenated\n"
"                           SPDUs (session protocol options)\n"
"      --pdv-encoding E     put: carry data values as single (single-ASN1-\n"
"                           type, default), octet (octet-aligned) or\n"
"                           arbitrary (BIT STRING) PDVs\n"
"      --octet-aligned      same as --pdv-encoding octet\n"
"      --acse-encoding E    same choice for the FTAM PDU inside the ACSE\n"
"                           user-information EXTERNAL (default single)\n"
"      --pdv-segment N      octets per segment when an octet-aligned or\n"
"                           arbitrary value is sent constructed (default 1000)\n"
"      --ap-title OID       called AP title (object identifier form)\n"
"      --ae-qualifier N     called AE qualifier\n"
"      --calling-ap-title OID\n"
"      --calling-ae-qualifier N\n"
"\n"
"FTAM:\n"
"  -u, --user NAME          initiator identity\n"
"  -p, --password PW        filestore password (or $FTAM_PASSWORD)\n"
"      --account ACCOUNT    account\n"
"  -b, --binary             FTAM-3 unstructured binary (default)\n"
"  -t, --text               FTAM-1 unstructured text\n"
"  -f, --force              put: replace an existing file\n"
"      --append             put: append to an existing file\n"
"      --chunk N            put: octets per data element (default 4096)\n"
"      --no-grouping        do not propose the grouping functional unit\n"
"      --list-method M      ls/dir: auto (default: F-LIST if the responder\n"
"                           grants FTAM version 2, else NBS-9), flist, nbs9\n"
"\n"
"Collect (files named with a constant plus a rotating sequence number):\n"
"      --name FMT           remote name, one %d for the sequence (AMA%04d)\n"
"      --seq-range MIN-MAX  sequence numbers; after MAX comes MIN again\n"
"      --state FILE         collection state (default DEST/.telexfer-state)\n"
"      --dest DIR           where collected files go (default .)\n"
"      --start N            first sequence number, when there is no state yet\n"
"      --ack A              after collecting: none (default), delete, rename\n"
"      --ack-rename FMT     new name for --ack rename, %s = old (%s.DONE)\n"
"      --closed C           next (default): a file is finished when a newer\n"
"                           one follows; any: every file shown is finished\n"
"      --lookahead N        sequence numbers checked past a gap (default 3)\n"
"      --max N              files per poll (default no limit)\n"
"  exit codes: 0 ok, 1 error, 3 gap detected, 4 another collect running,\n"
"  5 acknowledgement failed (files are collected and recorded)\n"
"\n"
"General:\n"
"      --timeout SEC        receive timeout (default 60)\n"
"      --pcap FILE          write the XOT session to a pcap file\n"
"  -v, --verbose            more output (repeat for protocol traces/hex)\n"
"  -h, --help\n", f);
}

enum {
    O_CUD = 256, O_PKT, O_WIN, O_MOD128, O_LCN, O_TSEL, O_CTSEL, O_SSEL,
    O_CSSEL, O_PSEL, O_CPSEL, O_TPDU, O_APT, O_AEQ, O_CAPT, O_CAEQ,
    O_ACCOUNT, O_APPEND, O_CHUNK, O_TIMEOUT, O_PCAP, O_NOGROUP,
    O_REJ, O_DBIT, O_INTERRUPT, O_TSDU, O_OCTET, O_T25,
    O_PDVENC, O_ACSEENC, O_PDVSEG, O_RXBUF, O_QDATA, O_EXTCONCAT,
    O_LISTMETHOD, O_TRANSPORT,
    O_CNAME, O_CRANGE, O_CSTATE, O_CDEST, O_CSTART, O_CACK, O_CACKREN,
    O_CCLOSED, O_CLOOK, O_CMAX,
};

static const struct option longopts[] = {
    { "host", required_argument, NULL, 'H' },
    { "transport", required_argument, NULL, O_TRANSPORT },
    { "name", required_argument, NULL, O_CNAME },
    { "seq-range", required_argument, NULL, O_CRANGE },
    { "state", required_argument, NULL, O_CSTATE },
    { "dest", required_argument, NULL, O_CDEST },
    { "start", required_argument, NULL, O_CSTART },
    { "ack", required_argument, NULL, O_CACK },
    { "ack-rename", required_argument, NULL, O_CACKREN },
    { "closed", required_argument, NULL, O_CCLOSED },
    { "lookahead", required_argument, NULL, O_CLOOK },
    { "max", required_argument, NULL, O_CMAX },
    { "called", required_argument, NULL, 'A' },
    { "calling", required_argument, NULL, 'a' },
    { "cud", required_argument, NULL, O_CUD },
    { "packet-size", required_argument, NULL, O_PKT },
    { "window", required_argument, NULL, O_WIN },
    { "mod128", no_argument, NULL, O_MOD128 },
    { "lcn", required_argument, NULL, O_LCN },
    { "rej", no_argument, NULL, O_REJ },
    { "t25", required_argument, NULL, O_T25 },
    { "rx-buffer", required_argument, NULL, O_RXBUF },
    { "qdata", required_argument, NULL, O_QDATA },
    { "dbit", no_argument, NULL, O_DBIT },
    { "interrupt", required_argument, NULL, O_INTERRUPT },
    { "tsdu-size", required_argument, NULL, O_TSDU },
    { "ext-concat", no_argument, NULL, O_EXTCONCAT },
    { "octet-aligned", no_argument, NULL, O_OCTET },
    { "pdv-encoding", required_argument, NULL, O_PDVENC },
    { "acse-encoding", required_argument, NULL, O_ACSEENC },
    { "pdv-segment", required_argument, NULL, O_PDVSEG },
    { "tsel", required_argument, NULL, O_TSEL },
    { "calling-tsel", required_argument, NULL, O_CTSEL },
    { "ssel", required_argument, NULL, O_SSEL },
    { "calling-ssel", required_argument, NULL, O_CSSEL },
    { "psel", required_argument, NULL, O_PSEL },
    { "calling-psel", required_argument, NULL, O_CPSEL },
    { "tpdu-size", required_argument, NULL, O_TPDU },
    { "ap-title", required_argument, NULL, O_APT },
    { "ae-qualifier", required_argument, NULL, O_AEQ },
    { "calling-ap-title", required_argument, NULL, O_CAPT },
    { "calling-ae-qualifier", required_argument, NULL, O_CAEQ },
    { "user", required_argument, NULL, 'u' },
    { "password", required_argument, NULL, 'p' },
    { "account", required_argument, NULL, O_ACCOUNT },
    { "binary", no_argument, NULL, 'b' },
    { "text", no_argument, NULL, 't' },
    { "force", no_argument, NULL, 'f' },
    { "append", no_argument, NULL, O_APPEND },
    { "chunk", required_argument, NULL, O_CHUNK },
    { "no-grouping", no_argument, NULL, O_NOGROUP },
    { "list-method", required_argument, NULL, O_LISTMETHOD },
    { "timeout", required_argument, NULL, O_TIMEOUT },
    { "pcap", required_argument, NULL, O_PCAP },
    { "verbose", no_argument, NULL, 'v' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 },
};

static long num_arg(const char *opt, const char *s, long lo, long hi)
{
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || *end || v < lo || v > hi) {
        fprintf(stderr, "ftam: invalid value for %s: %s (%ld..%ld)\n", opt, s, lo, hi);
        exit(2);
    }
    return v;
}

static void sel_arg(const char *opt, const char *s, uint8_t *out, size_t max, size_t *len)
{
    int n = parse_selector(s, out, max);
    if (n < 0) {
        fprintf(stderr, "ftam: invalid selector for %s (max %zu octets)\n", opt, max);
        exit(2);
    }
    *len = (size_t)n;
}

static int enc_arg(const char *opt, const char *s)
{
    if (strcmp(s, "single") == 0)
        return PDV_SINGLE;
    if (strcmp(s, "octet") == 0)
        return PDV_OCTET;
    if (strcmp(s, "arbitrary") == 0)
        return PDV_ARBITRARY;
    fprintf(stderr, "ftam: %s must be single, octet or arbitrary\n", opt);
    exit(2);
}

/* Options that only mean something for X.25, i.e. with XOT. */
static const char *x25_only_opt(int c)
{
    switch (c) {
    case 'A': return "--called";
    case 'a': return "--calling";
    case O_CUD: return "--cud";
    case O_PKT: return "--packet-size";
    case O_WIN: return "--window";
    case O_MOD128: return "--mod128";
    case O_LCN: return "--lcn";
    case O_REJ: return "--rej";
    case O_T25: return "--t25";
    case O_DBIT: return "--dbit";
    case O_INTERRUPT: return "--interrupt";
    case O_RXBUF: return "--rx-buffer";
    case O_QDATA: return "--qdata";
    default: return NULL;
    }
}

static int is_pow2(long v)
{
    return v > 0 && (v & (v - 1)) == 0;
}

int main(int argc, char **argv)
{
    ftam_opts o;
    int       doctype = 3, force = 0, append = 0, c;
    int       list_method = LIST_AUTO;
    int       port_given = 0;
    collect_opts co = { .seq_min = -1, .start = -1, .dest = ".",
                        .ack = ACK_NONE, .ack_rename = "%s.DONE",
                        .closed = CLOSED_NEXT, .lookahead = 3 };
    char      range_arg[64] = "";
    const char *x25_opt = NULL;
    char     *hostarg = NULL;

    ftam_opts_default(&o);
    o.password = getenv("FTAM_PASSWORD");
    /* test hook: discard the Nth received X.25 data packet (see tests/) */
    if (getenv("FTAM_TEST_DROP"))
        o.test_drop = atoi(getenv("FTAM_TEST_DROP"));
    if (o.test_drop)
        x25_opt = "FTAM_TEST_DROP";
    /* test hook: pad the F-INITIALIZE so connect data needs OA/CDO */
    if (getenv("FTAM_TEST_PAD"))
        o.impl_pad = (size_t)atoi(getenv("FTAM_TEST_PAD"));

    while ((c = getopt_long(argc, argv, "H:A:a:u:p:btfvh", longopts, NULL)) != -1) {
        if (x25_only_opt(c))
            x25_opt = x25_only_opt(c);
        switch (c) {
        case 'H': hostarg = optarg; break;
        case O_CNAME: co.name_fmt = optarg; break;
        case O_CRANGE: snprintf(range_arg, sizeof range_arg, "%s", optarg); break;
        case O_CSTATE: co.state_path = optarg; break;
        case O_CDEST: co.dest = optarg; break;
        case O_CSTART: co.start = num_arg("--start", optarg, 0, 999999999); break;
        case O_CACK:
            if (strcmp(optarg, "none") == 0) co.ack = ACK_NONE;
            else if (strcmp(optarg, "delete") == 0) co.ack = ACK_DELETE;
            else if (strcmp(optarg, "rename") == 0) co.ack = ACK_RENAME;
            else {
                fprintf(stderr, "ftam: --ack must be none, delete or rename\n");
                return 2;
            }
            break;
        case O_CACKREN: co.ack_rename = optarg; break;
        case O_CCLOSED:
            if (strcmp(optarg, "next") == 0) co.closed = CLOSED_NEXT;
            else if (strcmp(optarg, "any") == 0) co.closed = CLOSED_ANY;
            else {
                fprintf(stderr, "ftam: --closed must be next or any\n");
                return 2;
            }
            break;
        case O_CLOOK: co.lookahead = (int)num_arg("--lookahead", optarg, 1, 100); break;
        case O_CMAX: co.max_files = (int)num_arg("--max", optarg, 1, 1000000); break;
        case O_TRANSPORT:
            if (strcmp(optarg, "xot") == 0)
                o.transport = TRANSPORT_XOT;
            else if (strcmp(optarg, "rfc1006") == 0)
                o.transport = TRANSPORT_RFC1006;
            else {
                fprintf(stderr, "ftam: --transport must be xot or rfc1006\n");
                return 2;
            }
            break;
        case 'A': o.x25.called = optarg; break;
        case 'a': o.x25.calling = optarg; break;
        case O_CUD: {
            int n = parse_hex(optarg, o.x25.cud, 124);
            if (n < 0) {
                fprintf(stderr, "ftam: invalid --cud hex string\n");
                return 2;
            }
            o.x25.cud_len = (size_t)n;
            break;
        }
        case O_PKT:
            o.x25.pkt_size = (int)num_arg("--packet-size", optarg, 16, 4096);
            if (!is_pow2(o.x25.pkt_size)) {
                fprintf(stderr, "ftam: packet size must be a power of two\n");
                return 2;
            }
            break;
        case O_WIN: o.x25.window = (int)num_arg("--window", optarg, 1, 127); break;
        case O_MOD128: o.x25.mod128 = 1; break;
        case O_LCN: o.x25.lcn = (int)num_arg("--lcn", optarg, 1, 4095); break;
        case O_REJ: o.x25.use_rej = 1; break;
        case O_RXBUF: o.x25.rx_limit = (size_t)num_arg("--rx-buffer", optarg, 1, 1 << 30); break;
        case O_QDATA: {
            int n = parse_hex(optarg, o.qdata, sizeof o.qdata);
            if (n < 1) {
                fprintf(stderr, "ftam: --qdata needs 1..%zu octets of hex\n", sizeof o.qdata);
                return 2;
            }
            o.qdata_len = (size_t)n;
            break;
        }
        case O_T25: o.x25.t25_ms = (int)num_arg("--t25", optarg, 100, 3600000); break;
        case O_DBIT: o.x25.dbit = 1; break;
        case O_INTERRUPT: {
            int n = parse_hex(optarg, o.interrupt_data, X25_MAX_INT_DATA);
            if (n < 1) {
                fprintf(stderr, "ftam: --interrupt needs 1..%d octets of hex\n",
                        X25_MAX_INT_DATA);
                return 2;
            }
            o.interrupt_len = (size_t)n;
            break;
        }
        case O_TSDU:
            o.tsdu_size = (int)num_arg("--tsdu-size", optarg, SES_MIN_TSDU, 65535);
            break;
        case O_OCTET: o.pdv_mode = PDV_OCTET; break;
        case O_EXTCONCAT: o.ext_concat = 1; break;
        case O_PDVENC: o.pdv_mode = enc_arg("--pdv-encoding", optarg); break;
        case O_ACSEENC: o.acse_encoding = enc_arg("--acse-encoding", optarg); break;
        case O_PDVSEG: o.pdv_segment = (size_t)num_arg("--pdv-segment", optarg, 1, 65000); break;
        case O_TSEL: sel_arg("--tsel", optarg, o.tsel_called, 32, &o.tsel_called_len); break;
        case O_CTSEL: sel_arg("--calling-tsel", optarg, o.tsel_calling, 32, &o.tsel_calling_len); break;
        case O_SSEL: sel_arg("--ssel", optarg, o.ssel_called, 16, &o.ssel_called_len); break;
        case O_CSSEL: sel_arg("--calling-ssel", optarg, o.ssel_calling, 16, &o.ssel_calling_len); break;
        case O_PSEL: sel_arg("--psel", optarg, o.psel_called, 16, &o.psel_called_len); break;
        case O_CPSEL: sel_arg("--calling-psel", optarg, o.psel_calling, 16, &o.psel_calling_len); break;
        case O_TPDU:
            o.tpdu_size = (int)num_arg("--tpdu-size", optarg, 128, 8192);
            if (!is_pow2(o.tpdu_size)) {
                fprintf(stderr, "ftam: TPDU size must be a power of two\n");
                return 2;
            }
            break;
        case O_APT: o.acse.called_ap_title = optarg; break;
        case O_AEQ: o.acse.called_ae_qual = num_arg("--ae-qualifier", optarg, 0, 0x7fffffff); break;
        case O_CAPT: o.acse.calling_ap_title = optarg; break;
        case O_CAEQ: o.acse.calling_ae_qual = num_arg("--calling-ae-qualifier", optarg, 0, 0x7fffffff); break;
        case 'u': o.user = optarg; break;
        case 'p': o.password = optarg; break;
        case O_ACCOUNT: o.account = optarg; break;
        case 'b': doctype = 3; break;
        case 't': doctype = 1; break;
        case 'f': force = 1; break;
        case O_APPEND: append = 1; break;
        case O_CHUNK: o.chunk_size = (size_t)num_arg("--chunk", optarg, 64, 65000); break;
        case O_NOGROUP: o.functional_units &= ~FU_GROUPING; break;
        case O_LISTMETHOD:
            if (strcmp(optarg, "auto") == 0)
                list_method = LIST_AUTO;
            else if (strcmp(optarg, "flist") == 0)
                list_method = LIST_FLIST;
            else if (strcmp(optarg, "nbs9") == 0)
                list_method = LIST_NBS9;
            else {
                fprintf(stderr, "ftam: --list-method must be auto, flist or nbs9\n");
                return 2;
            }
            break;
        case O_TIMEOUT: o.timeout_ms = (int)num_arg("--timeout", optarg, 1, 3600) * 1000; break;
        case O_PCAP: o.pcap_path = optarg; break;
        case 'v': log_level++; break;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    argc -= optind;
    argv += optind;
    if (argc < 1) {
        usage(stderr);
        return 2;
    }
    if (!hostarg) {
        fprintf(stderr, "ftam: --host is required\n");
        return 2;
    }
    if (force && append) {
        fprintf(stderr, "ftam: --force and --append are mutually exclusive\n");
        return 2;
    }
    if (o.transport == TRANSPORT_RFC1006 && x25_opt) {
        fprintf(stderr, "ftam: %s is an X.25 option; it has no meaning with "
                        "--transport rfc1006\n", x25_opt);
        return 2;
    }
    if (o.transport == TRANSPORT_XOT && o.tpdu_size > 2048) {
        /* class 0 over X.25 is limited to 2048 (ISO 8073); RFC 1006
         * implementations commonly accept more */
        fprintf(stderr, "ftam: --tpdu-size above 2048 needs --transport rfc1006\n");
        return 2;
    }
    /* HOST[:PORT], IPv6 as [addr]:port */
    static char hostbuf[256];
    snprintf(hostbuf, sizeof hostbuf, "%s", hostarg);
    o.host = hostbuf;
    char *colon = strrchr(hostbuf, ':');
    if (hostbuf[0] == '[') {
        char *rb = strchr(hostbuf, ']');
        if (rb) {
            *rb = 0;
            o.host = hostbuf + 1;
            if (rb[1] == ':') {
                o.port = (int)num_arg("--host port", rb + 2, 1, 65535);
                port_given = 1;
            }
        }
    } else if (colon && strchr(hostbuf, ':') == colon) {
        *colon = 0;
        o.port = (int)num_arg("--host port", colon + 1, 1, 65535);
        port_given = 1;
    }
    if (!port_given)
        o.port = o.transport == TRANSPORT_RFC1006 ? RFC1006_PORT : XOT_PORT;

    const char *cmd = argv[0];
    int         nargs = argc - 1;
    struct { const char *name; int min, max; } cmds[] = {
        { "get", 1, 2 }, { "put", 1, 2 }, { "delete", 1, 1 },
        { "attr", 1, 1 }, { "rename", 2, 2 }, { "ping", 0, 0 },
        { "ls", 0, 1 }, { "dir", 0, 1 }, { "collect", 0, 0 },
    };
    int known = 0;
    for (size_t i = 0; i < sizeof cmds / sizeof cmds[0]; i++)
        if (strcmp(cmd, cmds[i].name) == 0) {
            known = 1;
            if (nargs < cmds[i].min || nargs > cmds[i].max) {
                fprintf(stderr, "ftam: wrong number of arguments for %s\n", cmd);
                return 2;
            }
        }
    if (!known) {
        fprintf(stderr, "ftam: unknown command '%s'\n", cmd);
        return 2;
    }

    /* open local files before touching the network */
    FILE       *local = NULL;
    const char *local_name = NULL;
    const char *remote = NULL;
    int         created_local = 0;
    if (strcmp(cmd, "get") == 0) {
        remote = argv[1];
        if (nargs == 2) {
            local_name = argv[2];
        } else {
            char *tmp = strdup(remote);
            local_name = strdup(basename(tmp));
            free(tmp);
        }
        if (strcmp(local_name, "-") == 0) {
            local = stdout;
        } else {
            local = fopen(local_name, "wb");
            created_local = 1;
        }
    } else if (strcmp(cmd, "put") == 0) {
        local_name = argv[1];
        if (nargs == 2) {
            remote = argv[2];
        } else {
            char *tmp = strdup(local_name);
            remote = strdup(basename(tmp));
            free(tmp);
        }
        local = strcmp(local_name, "-") == 0 ? stdin : fopen(local_name, "rb");
    }
    if ((strcmp(cmd, "get") == 0 || strcmp(cmd, "put") == 0) && !local) {
        fprintf(stderr, "ftam: %s: %s\n", local_name, strerror(errno));
        return 1;
    }

    int listing = strcmp(cmd, "ls") == 0 || strcmp(cmd, "dir") == 0;
    /* F-LIST is a version 2 feature; only offer version 2 when it can
     * be used, so other commands behave exactly as with a v1 responder */
    if (listing && list_method != LIST_NBS9)
        o.propose_v2 = 1;

    int collecting = strcmp(cmd, "collect") == 0;
    int lock_fd = -1;
    static char state_default[4096];
    if (collecting) {
        char *dash;
        if (!co.name_fmt || !range_arg[0]) {
            fprintf(stderr, "ftam: collect needs --name and --seq-range\n");
            return 2;
        }
        if (collect_check_format(co.name_fmt) < 0) {
            fprintf(stderr, "ftam: %s\n", get_error());
            return 2;
        }
        co.seq_min = strtol(range_arg, &dash, 10);
        if (*dash != '-' || (co.seq_max = strtol(dash + 1, &dash, 10), *dash) ||
            co.seq_min < 0 || co.seq_max < co.seq_min ||
            co.seq_max - co.seq_min >= 10000000) {
            fprintf(stderr, "ftam: --seq-range must be MIN-MAX (at most 10 million)\n");
            return 2;
        }
        if (co.start >= 0 && (co.start < co.seq_min || co.start > co.seq_max)) {
            fprintf(stderr, "ftam: --start is outside --seq-range\n");
            return 2;
        }
        if (co.ack == ACK_RENAME && !strstr(co.ack_rename, "%s")) {
            fprintf(stderr, "ftam: --ack-rename needs %%s for the original name\n");
            return 2;
        }
        struct stat sb;
        if (stat(co.dest, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
            fprintf(stderr, "ftam: --dest %s is not a directory\n", co.dest);
            return 2;
        }
        if (!co.state_path) {
            snprintf(state_default, sizeof state_default, "%s/.telexfer-state", co.dest);
            co.state_path = state_default;
        }
        /* lock before connecting: an overlapping poll costs no call */
        int busy;
        lock_fd = collect_lock(&co, &busy);
        if (lock_fd < 0) {
            fprintf(stderr, "ftam: %s\n", get_error());
            return busy ? COLLECT_BUSY : 1;
        }
    }

    signal(SIGPIPE, SIG_IGN);

    ftam_conn fc;
    if (ftam_connect(&fc, &o) < 0) {
        fprintf(stderr, "ftam: %s\n", get_error());
        ftam_close(&fc);
        if (created_local) {
            fclose(local);
            unlink(local_name);
        }
        return 1;
    }
    log_msg(LOG_INFO, "ftam", "association established");

    int       rc = 0;
    long long bytes = 0;
    if (strcmp(cmd, "get") == 0) {
        rc = ftam_get(&fc, remote, local, doctype, &bytes);
        if (local != stdout && fclose(local) != 0 && rc == 0) {
            set_error("%s: %s", local_name, strerror(errno));
            rc = -1;
        }
        if (rc < 0 && created_local)
            unlink(local_name);
        if (rc == 0)
            fprintf(stderr, "%s -> %s: %lld octets\n", remote, local_name, bytes);
    } else if (strcmp(cmd, "put") == 0) {
        int override = force ? OVR_DELETE_CREATE_NEW_ATTRS : OVR_CREATE_FAILURE;
        rc = ftam_put(&fc, local, remote, doctype, override, append, &bytes);
        if (local != stdin)
            fclose(local);
        if (rc == 0)
            fprintf(stderr, "%s -> %s: %lld octets\n", local_name, remote, bytes);
    } else if (strcmp(cmd, "delete") == 0) {
        rc = ftam_delete(&fc, argv[1]);
    } else if (strcmp(cmd, "attr") == 0) {
        rc = ftam_attributes(&fc, argv[1], stdout);
    } else if (strcmp(cmd, "rename") == 0) {
        rc = ftam_rename(&fc, argv[1], argv[2]);
    } else if (collecting) {
        int crc = ftam_collect(&fc, &co);
        if (crc != COLLECT_OK && crc != COLLECT_ERROR) {
            /* gap / ack failure: not an error of the association */
            ftam_release(&fc);
            ftam_close(&fc);
            fprintf(stderr, "ftam: collect finished with %s\n",
                    crc == COLLECT_GAP ? "a sequence gap" : "failed acknowledgements");
            return crc;
        }
        rc = crc == COLLECT_OK ? 0 : -1;
    } else if (listing) {
        rc = ftam_list(&fc, nargs ? argv[1] : NULL, list_method,
                       strcmp(cmd, "dir") == 0, stdout);
    }

    char errmsg[1024] = "";
    if (rc < 0)
        snprintf(errmsg, sizeof errmsg, "%s", get_error());

    if (fc.associated) {
        if (ftam_release(&fc) < 0) {
            fprintf(stderr, "ftam: release: %s\n", get_error());
            if (rc == 0)
                rc = -1;
        }
    }
    ftam_close(&fc);
    if (errmsg[0])
        fprintf(stderr, "ftam: %s\n", errmsg);
    return rc < 0 ? 1 : 0;
}
