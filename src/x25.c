/*
 * x25.c - X.25 packet layer over XOT (RFC 1613).
 *
 * XOT framing: every X.25 packet is preceded by a 4 octet header,
 * a 16 bit version (always 0) and a 16 bit length of the packet.
 */
#include "x25.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* packet type identifiers */
#define PT_CALL_REQ     0x0b    /* call request / incoming call */
#define PT_CALL_ACC     0x0f    /* call accepted / call connected */
#define PT_CLEAR_REQ    0x13    /* clear request / clear indication */
#define PT_CLEAR_CONF   0x17
#define PT_INTERRUPT    0x23
#define PT_INT_CONF     0x27
#define PT_RESET_REQ    0x1b
#define PT_RESET_CONF   0x1f
#define PT_RESTART_REQ  0xfb
#define PT_RESTART_CONF 0xff
#define PT_DIAG         0xf1
#define PT_RR           0x01
#define PT_RNR          0x05
#define PT_REJ          0x09

#define FAC_PKT_SIZE    0x42
#define FAC_WIN_SIZE    0x43

static const char *L = "x25";

/* ---- XOT packet I/O ---------------------------------------------------- */

static int send_pkt(x25_vc *vc, const uint8_t *pkt, size_t n)
{
    uint8_t hdr[4] = { 0, 0, (uint8_t)(n >> 8), (uint8_t)n };
    struct iovec iov[2] = { { hdr, 4 }, { (void *)pkt, n } };

    log_hex(LOG_DUMP, L, "send packet", pkt, n);
    if (vc->trace) {
        uint8_t tmp[4 + 4200];
        if (n <= 4200) {
            memcpy(tmp, hdr, 4);
            memcpy(tmp + 4, pkt, n);
            trace_write(vc->trace, 1, tmp, n + 4);
        }
    }
    return tcp_write_all(vc->fd, iov, 2);
}

/* 0 = packet read, -2 = timeout (nothing read), -1 = error */
static int read_pkt(x25_vc *vc, buf_t *pkt, int timeout_ms)
{
    long    deadline = tcp_now_ms() + timeout_ms;
    uint8_t hdr[4];
    int     rc;

    if ((rc = tcp_read_full(vc->fd, hdr, 4, deadline)) < 0)
        return rc;
    unsigned ver = (unsigned)(hdr[0] << 8 | hdr[1]);
    size_t   len = (size_t)(hdr[2] << 8 | hdr[3]);
    if (ver != 0) {
        set_error("XOT: unsupported version %u", ver);
        return -1;
    }
    if (len < 3) {
        set_error("XOT: runt packet (%zu bytes)", len);
        return -1;
    }
    buf_reset(pkt);
    buf_reserve(pkt, len);
    if (tcp_read_full(vc->fd, pkt->data, len, deadline) < 0)
        return -1;
    pkt->len = len;
    log_hex(LOG_DUMP, L, "recv packet", pkt->data, len);
    if (vc->trace) {
        uint8_t tmp[4 + 4200];
        if (len <= 4200) {
            memcpy(tmp, hdr, 4);
            memcpy(tmp + 4, pkt->data, len);
            trace_write(vc->trace, 0, tmp, len + 4);
        }
    }
    return 0;
}

static size_t pkt_hdr(x25_vc *vc, uint8_t *p, uint8_t type)
{
    p[0] = (uint8_t)((vc->mod == 128 ? 0x20 : 0x10) | ((vc->lcn >> 8) & 0x0f));
    p[1] = (uint8_t)vc->lcn;
    p[2] = type;
    return 3;
}

static int send_simple(x25_vc *vc, uint8_t type, int n_extra, uint8_t a, uint8_t b)
{
    uint8_t p[5];
    size_t  n = pkt_hdr(vc, p, type);
    if (n_extra > 0)
        p[n++] = a;
    if (n_extra > 1)
        p[n++] = b;
    return send_pkt(vc, p, n);
}

static int send_rr(x25_vc *vc)
{
    uint8_t p[4];
    size_t  n;
    if (vc->mod == 128) {
        n = pkt_hdr(vc, p, PT_RR);
        p[n++] = (uint8_t)(vc->vr << 1);
    } else {
        n = pkt_hdr(vc, p, (uint8_t)(vc->vr << 5 | PT_RR));
    }
    vc->vr_acked = vc->vr;
    log_msg(LOG_DEBUG, L, "send RR P(R)=%u", vc->vr);
    return send_pkt(vc, p, n);
}

static int send_rnr(x25_vc *vc)
{
    uint8_t p[4];
    size_t  n;
    if (vc->mod == 128) {
        n = pkt_hdr(vc, p, PT_RNR);
        p[n++] = (uint8_t)(vc->vr << 1);
    } else {
        n = pkt_hdr(vc, p, (uint8_t)(vc->vr << 5 | PT_RNR));
    }
    vc->vr_acked = vc->vr;
    log_msg(LOG_DEBUG, L, "send RNR P(R)=%u", vc->vr);
    return send_pkt(vc, p, n);
}

static int send_rej(x25_vc *vc)
{
    uint8_t p[4];
    size_t  n;
    if (vc->mod == 128) {
        n = pkt_hdr(vc, p, PT_REJ);
        p[n++] = (uint8_t)(vc->vr << 1);
    } else {
        n = pkt_hdr(vc, p, (uint8_t)(vc->vr << 5 | PT_REJ));
    }
    vc->vr_acked = vc->vr;
    log_msg(LOG_INFO, L, "send REJ P(R)=%u (requesting retransmission)", vc->vr);
    return send_pkt(vc, p, n);
}

/* ---- retransmission window ---------------------------------------------- */

static void txwin_store(x25_vc *vc, unsigned ps, const uint8_t *pkt, size_t n)
{
    free(vc->txwin[ps]);
    vc->txwin[ps] = xmalloc(n);
    memcpy(vc->txwin[ps], pkt, n);
    vc->txwin_len[ps] = n;
}

static void txwin_clear(x25_vc *vc)
{
    for (int i = 0; i < 128; i++) {
        free(vc->txwin[i]);
        vc->txwin[i] = NULL;
        vc->txwin_len[i] = 0;
    }
}

/* Drop copies of packets acknowledged by P(R) values old_pr..new_pr-1. */
static void txwin_ack(x25_vc *vc, unsigned old_pr, unsigned new_pr)
{
    for (unsigned s = old_pr; s != new_pr; s = (s + 1) % (unsigned)vc->mod) {
        free(vc->txwin[s]);
        vc->txwin[s] = NULL;
        vc->txwin_len[s] = 0;
    }
}

/* Retransmit every unacknowledged packet from P(R) on, with fresh P(R). */
static int retransmit(x25_vc *vc)
{
    for (unsigned s = vc->pr_peer; s != vc->vs; s = (s + 1) % (unsigned)vc->mod) {
        uint8_t *pkt = vc->txwin[s];
        if (!pkt) {
            set_error("X.25: REJ for packet %u which is no longer buffered", s);
            return -1;
        }
        if (vc->mod == 128)
            pkt[3] = (uint8_t)(vc->vr << 1 | (pkt[3] & 0x01));
        else
            pkt[2] = (uint8_t)(vc->vr << 5 | (pkt[2] & 0x1f));
        log_msg(LOG_INFO, L, "retransmit DATA P(S)=%u P(R)=%u", s, vc->vr);
        vc->vr_acked = vc->vr;
        if (send_pkt(vc, pkt, vc->txwin_len[s]) < 0)
            return -1;
    }
    return 0;
}

/* ---- addresses & facilities -------------------------------------------- */

static int bcd_put(uint8_t *out, int nib, const char *digits)
{
    for (const char *s = digits; *s; s++, nib++) {
        uint8_t d = (uint8_t)(*s - '0');
        if (nib & 1)
            out[nib / 2] |= d;
        else
            out[nib / 2] = (uint8_t)(d << 4);
    }
    return nib;
}

static void bcd_get(const uint8_t *in, int nib, int count, char *out)
{
    for (int i = 0; i < count; i++, nib++) {
        uint8_t b = in[nib / 2];
        out[i] = (char)('0' + ((nib & 1) ? (b & 0x0f) : (b >> 4)));
    }
    out[count] = 0;
}

static int log2i(int v)
{
    int n = 0;
    while ((1 << n) < v)
        n++;
    return n;
}

/*
 * Parse address block + facilities from a call set-up packet body
 * (p points after the packet type).  Returns offset after facilities.
 */
static size_t parse_setup(x25_vc *vc, const uint8_t *p, size_t n,
                          int *ps_called, int *ps_calling,
                          int *w_called, int *w_calling)
{
    size_t off = 0;
    if (n == 0)
        return 0;
    int calling_len = p[0] >> 4, called_len = p[0] & 0x0f;
    size_t alen = (size_t)(calling_len + called_len + 1) / 2;
    if (1 + alen > n)
        return n;
    bcd_get(p + 1, 0, called_len, vc->called);
    bcd_get(p + 1, called_len, calling_len, vc->calling);
    off = 1 + alen;
    if (off >= n)
        return off;
    size_t flen = p[off++];
    size_t fend = off + flen;
    if (fend > n)
        fend = n;
    while (off < fend) {
        uint8_t code = p[off++];
        size_t  plen;
        switch (code & 0xc0) {
        case 0x00: plen = 1; break;
        case 0x40: plen = 2; break;
        case 0x80: plen = 3; break;
        default:
            if (off >= fend)
                return fend;
            plen = p[off++];
            break;
        }
        if (off + plen > fend)
            break;
        if (code == FAC_PKT_SIZE) {
            /* valid codes 4..12 (16..4096 octets) */
            if (p[off] >= 4 && p[off] <= 12)
                *ps_called = 1 << p[off];
            if (p[off + 1] >= 4 && p[off + 1] <= 12)
                *ps_calling = 1 << p[off + 1];
        } else if (code == FAC_WIN_SIZE) {
            *w_called = p[off];
            *w_calling = p[off + 1];
        } else {
            log_msg(LOG_DEBUG, L, "ignoring facility 0x%02x", code);
        }
        off += plen;
    }
    return fend;
}

static int net_send(void *impl, const uint8_t *p, size_t n)
{
    return x25_send(impl, p, n);
}

static int net_recv(void *impl, buf_t *out)
{
    return x25_recv(impl, out);
}

static void net_disconnect(void *impl)
{
    x25_clear(impl, 0x00, 0);
}

static const net_ops x25_ops = { "X.25/XOT", net_send, net_recv, net_disconnect };

net_conn x25_net(x25_vc *vc)
{
    return (net_conn){ &x25_ops, vc };
}

const char *x25_cause_str(uint8_t cause)
{
    if (cause & 0x80)
        return "DTE originated";
    switch (cause) {
    case 0x00: return "DTE originated";
    case 0x01: return "number busy";
    case 0x03: return "invalid facility request";
    case 0x05: return "network congestion";
    case 0x09: return "out of order";
    case 0x0b: return "access barred";
    case 0x0d: return "not obtainable";
    case 0x11: return "remote procedure error";
    case 0x13: return "local procedure error";
    case 0x15: return "RPOA out of order";
    case 0x19: return "reverse charging acceptance not subscribed";
    case 0x21: return "incompatible destination";
    case 0x29: return "fast select acceptance not subscribed";
    case 0x39: return "ship absent";
    default:   return "unknown cause";
    }
}

/* ---- packet processing in data transfer state -------------------------- */

static void vc_reset_vars(x25_vc *vc)
{
    vc->vs = vc->vr = vc->pr_peer = vc->vr_acked = 0;
    vc->peer_busy = 0;
    vc->rej_sent = 0;
    vc->int_pending = 0;
    vc->in_mseq = 0;
    vc->busy = vc->app_busy = 0;
    vc->hold_until = 0;
    buf_reset(&vc->reasm);
    txwin_clear(vc);
}

static int update_pr(x25_vc *vc, unsigned pr)
{
    unsigned m = (unsigned)vc->mod;
    if (((pr - vc->pr_peer) % m) > ((vc->vs - vc->pr_peer) % m)) {
        set_error("X.25: invalid P(R)=%u (window %u..%u)", pr, vc->pr_peer, vc->vs);
        return -1;
    }
    txwin_ack(vc, vc->pr_peer, pr);
    vc->pr_peer = pr;
    return 0;
}

static size_t rx_limit(const x25_vc *vc)
{
    return vc->rx_limit ? vc->rx_limit : 65536;
}

/* Leave the RNR state once nothing holds us busy any more. */
static int update_busy(x25_vc *vc)
{
    if (!vc->busy || vc->app_busy || vc->hold_until ||
        vc->queued_bytes > rx_limit(vc) / 2)
        return 0;
    vc->busy = 0;
    log_msg(LOG_INFO, L, "receiver ready again (%zu octets queued)", vc->queued_bytes);
    return send_rr(vc);
}

static void enqueue(x25_vc *vc, const uint8_t *p, size_t n)
{
    vc->queued_bytes += n;
    nsdu_q *q = xmalloc(sizeof *q + n);
    q->next = NULL;
    q->len = n;
    memcpy(q->data, p, n);
    if (vc->qtail)
        vc->qtail->next = q;
    else
        vc->qhead = q;
    vc->qtail = q;
}

/* A complete qualified (Q-bit) NSDU: control data, not for the transport. */
static void deliver_qdata(x25_vc *vc, const uint8_t *p, size_t n)
{
    if (vc->on_qdata) {
        vc->on_qdata(vc->qdata_arg, p, n);
        return;
    }
    char hex[3 * 32 + 4] = "";
    size_t i;
    for (i = 0; i < n && i < 32; i++)
        snprintf(hex + 3 * i, 4, "%02x ", p[i]);
    if (n > 32)
        strcat(hex, "...");
    log_msg(LOG_INFO, L, "qualified data received (%zu octets: %s)", n, hex);
}

/* Handle one packet received in the data transfer phase. */
static int process_pkt(x25_vc *vc, const uint8_t *p, size_t n)
{
    int     lcn = ((p[0] & 0x0f) << 8) | p[1];
    uint8_t t = p[2];

    if (t == PT_DIAG) {
        log_msg(LOG_INFO, L, "DIAGNOSTIC packet, code %d", n > 3 ? p[3] : -1);
        return 0;
    }
    if (t == PT_RESTART_REQ) {
        vc->clear_cause = n > 3 ? p[3] : 0;
        vc->clear_diag = n > 4 ? p[4] : 0;
        send_simple(vc, PT_RESTART_CONF, 0, 0, 0);
        vc->state = X25_CLEARED;
        set_error("X.25 restart indication (cause 0x%02x, diag %u)",
                  vc->clear_cause, vc->clear_diag);
        return -1;
    }
    if (lcn != vc->lcn) {
        log_msg(LOG_INFO, L, "packet for unknown LCN %d ignored", lcn);
        return 0;
    }

    if (t == PT_CLEAR_REQ) {
        vc->clear_cause = n > 3 ? p[3] : 0;
        vc->clear_diag = n > 4 ? p[4] : 0;
        log_msg(LOG_INFO, L, "CLEAR INDICATION cause 0x%02x (%s) diag %u",
                vc->clear_cause, x25_cause_str(vc->clear_cause), vc->clear_diag);
        if (vc->state != X25_CLEARING)
            send_simple(vc, PT_CLEAR_CONF, 0, 0, 0);
        vc->state = X25_CLEARED;
        set_error("call cleared by network/peer: cause 0x%02x (%s), diagnostic %u",
                  vc->clear_cause, x25_cause_str(vc->clear_cause), vc->clear_diag);
        return -1;
    }
    if (t == PT_CLEAR_CONF) {
        vc->state = X25_CLEARED;
        return 0;
    }
    if (t == PT_RESET_REQ) {
        uint8_t c = n > 3 ? p[3] : 0, d = n > 4 ? p[4] : 0;
        log_msg(LOG_INFO, L, "RESET INDICATION cause 0x%02x diag %u", c, d);
        send_simple(vc, PT_RESET_CONF, 0, 0, 0);
        vc_reset_vars(vc);
        /* TP0 has no means to recover lost data */
        set_error("X.25 reset by network (cause 0x%02x, diag %u); data may be lost", c, d);
        return -1;
    }
    if (t == PT_RESET_CONF)
        return 0;
    if (t == PT_INTERRUPT) {
        const uint8_t *d = p + 3;
        size_t         dl = n - 3;
        if (vc->on_interrupt) {
            vc->on_interrupt(vc->int_arg, d, dl);
        } else {
            char hex[3 * X25_MAX_INT_DATA + 1] = "";
            for (size_t i = 0; i < dl && i < X25_MAX_INT_DATA; i++)
                snprintf(hex + 3 * i, 4, "%02x ", d[i]);
            log_msg(LOG_INFO, L, "INTERRUPT received (%zu octets: %s), confirming",
                    dl, dl ? hex : "none");
        }
        return send_simple(vc, PT_INT_CONF, 0, 0, 0);
    }
    if (t == PT_INT_CONF) {
        vc->int_pending = 0;
        log_msg(LOG_DEBUG, L, "INTERRUPT CONFIRMATION received");
        return 0;
    }

    if ((t & 0x01) == 0) {                      /* DATA */
        unsigned ps, pr;
        int      m;
        size_t   hl;
        if (vc->mod == 128) {
            if (n < 4)
                return 0;
            ps = t >> 1;
            pr = p[3] >> 1;
            m = p[3] & 1;
            hl = 4;
        } else {
            ps = (t >> 1) & 7;
            pr = t >> 5;
            m = (t >> 4) & 1;
            hl = 3;
        }
        int dbit = (p[0] & 0x40) != 0;
        if (ps != vc->vr) {
            if (vc->use_rej) {
                /* a P(S) just behind V(R) is a duplicate caused by a
                 * retransmission: drop it silently.  Anything else means
                 * a packet went missing: discard until it is retransmitted,
                 * with only one REJ per REJ condition. */
                unsigned ahead = (ps - vc->vr) % (unsigned)vc->mod;
                if (ahead >= (unsigned)vc->w_rx) {
                    log_msg(LOG_DEBUG, L, "duplicate P(S)=%u discarded", ps);
                    return 0;
                }
                log_msg(LOG_INFO, L, "out of sequence P(S)=%u, expected %u: discarded",
                        ps, vc->vr);
                if (!vc->rej_sent) {
                    vc->rej_sent = 1;
                    return send_rej(vc);
                }
                return 0;
            }
            set_error("X.25: out of sequence P(S)=%u, expected %u", ps, vc->vr);
            send_simple(vc, PT_RESET_REQ, 2, 0x00, 1 /* invalid P(S) */);
            return -1;
        }
        if (vc->test_drop && ++vc->rx_data_count == vc->test_drop) {
            log_msg(LOG_INFO, L, "test: dropping DATA P(S)=%u as if lost", ps);
            return 0;
        }
        vc->rej_sent = 0;
        if (update_pr(vc, pr) < 0)
            return -1;
        vc->vr = (vc->vr + 1) % (unsigned)vc->mod;
        if (n - hl > (size_t)vc->ps_rx)
            log_msg(LOG_INFO, L, "data packet exceeds negotiated size (%zu > %d)",
                    n - hl, vc->ps_rx);
        int qbit = (p[0] & 0x80) != 0;
        if (!vc->in_mseq) {
            vc->in_mseq = 1;
            vc->reasm_q = qbit;
        } else if (qbit != vc->reasm_q) {
            /* all packets of a complete packet sequence carry the same Q */
            set_error("X.25: Q-bit changes within a packet sequence");
            send_simple(vc, PT_RESET_REQ, 2, 0x00, 83 /* inconsistent Q-bit */);
            return -1;
        }
        buf_put(&vc->reasm, p + hl, n - hl);
        log_msg(LOG_DEBUG, L, "recv DATA P(S)=%u P(R)=%u M=%d D=%d Q=%d len=%zu",
                ps, pr, m, dbit, qbit, n - hl);
        int was_busy = vc->busy;
        if (!m) {
            vc->in_mseq = 0;
            if (vc->reasm_q) {
                deliver_qdata(vc, vc->reasm.data, vc->reasm.len);
            } else {
                enqueue(vc, vc->reasm.data, vc->reasm.len);
                /* only complete NSDUs count: a partial one must be able to
                 * finish or the call would deadlock */
                if (!vc->busy && vc->queued_bytes > rx_limit(vc)) {
                    vc->busy = 1;
                    log_msg(LOG_INFO, L, "receive buffer full (%zu octets): RNR",
                            vc->queued_bytes);
                }
            }
            buf_reset(&vc->reasm);
        }
        if (vc->busy && !was_busy)
            return send_rnr(vc);
        unsigned unacked = (vc->vr - vc->vr_acked) % (unsigned)vc->mod;
        /* D=1: the sender waits for end-to-end confirmation, give it now
         * that the data has been taken over by the transport layer */
        if (!m || dbit || unacked >= (unsigned)vc->w_rx)
            return vc->busy ? send_rnr(vc) : send_rr(vc);
        return 0;
    }

    /* RR / RNR / REJ */
    unsigned pr;
    uint8_t  kind;
    if (vc->mod == 128) {
        kind = t;
        pr = n > 3 ? p[3] >> 1 : 0;
    } else {
        kind = t & 0x1f;
        pr = t >> 5;
    }
    if (kind == PT_RR || kind == PT_RNR) {
        if (update_pr(vc, pr) < 0)
            return -1;
        vc->peer_busy = (kind == PT_RNR);
        log_msg(LOG_DEBUG, L, "recv %s P(R)=%u", kind == PT_RR ? "RR" : "RNR", pr);
        return 0;
    }
    if (kind == PT_REJ) {
        log_msg(LOG_INFO, L, "recv REJ P(R)=%u", pr);
        if (update_pr(vc, pr) < 0)
            return -1;
        vc->peer_busy = 0;
        return retransmit(vc);
    }
    log_msg(LOG_INFO, L, "unexpected packet type 0x%02x ignored", t);
    return 0;
}

/* ---- public API -------------------------------------------------------- */

static void vc_init(x25_vc *vc, int fd, trace_t *trace)
{
    memset(vc, 0, sizeof *vc);
    vc->fd = fd;
    vc->trace = trace;
    vc->timeout_ms = 60000;
    buf_init(&vc->reasm);
}

int x25_call(x25_vc *vc, int fd, const x25_params *prm, int timeout_ms,
             trace_t *trace)
{
    uint8_t  pkt[300];
    size_t   n;
    buf_t    rx;
    const char *called = prm->called ? prm->called : "";
    const char *calling = prm->calling ? prm->calling : "";

    vc_init(vc, fd, trace);
    vc->lcn = prm->lcn ? prm->lcn : 1;
    vc->mod = prm->mod128 ? 128 : 8;
    vc->ps_tx = vc->ps_rx = prm->pkt_size ? prm->pkt_size : 128;
    vc->w_tx = vc->w_rx = prm->window ? prm->window : 2;
    vc->timeout_ms = timeout_ms;
    vc->use_rej = prm->use_rej;
    vc->t25_ms = prm->t25_ms;
    vc->rx_limit = prm->rx_limit;

    if (strlen(called) > 15 || strlen(calling) > 15 ||
        strspn(called, "0123456789") != strlen(called) ||
        strspn(calling, "0123456789") != strlen(calling)) {
        set_error("X.121 addresses must be at most 15 decimal digits");
        return -1;
    }
    if (vc->w_tx < 1 || vc->w_tx > vc->mod - 1) {
        set_error("window size %d invalid for modulo %d", vc->w_tx, vc->mod);
        return -1;
    }

    n = pkt_hdr(vc, pkt, PT_CALL_REQ);
    if (prm->dbit)
        pkt[0] |= 0x40;                 /* D-bit procedure requested */
    int cl = (int)strlen(called), cg = (int)strlen(calling);
    pkt[n++] = (uint8_t)(cg << 4 | cl);
    memset(pkt + n, 0, (size_t)(cl + cg + 1) / 2);
    int nib = bcd_put(pkt + n, 0, called);
    bcd_put(pkt + n, nib, calling);
    n += (size_t)(cl + cg + 1) / 2;
    /* RFC 1613: always state packet and window size explicitly */
    pkt[n++] = 6;
    pkt[n++] = FAC_PKT_SIZE;
    pkt[n++] = (uint8_t)log2i(vc->ps_rx);
    pkt[n++] = (uint8_t)log2i(vc->ps_tx);
    pkt[n++] = FAC_WIN_SIZE;
    pkt[n++] = (uint8_t)vc->w_rx;
    pkt[n++] = (uint8_t)vc->w_tx;
    memcpy(pkt + n, prm->cud, prm->cud_len);
    n += prm->cud_len;

    log_msg(LOG_INFO, L, "CALL REQUEST lcn=%d called=%s calling=%s pkt=%d win=%d mod=%d",
            vc->lcn, called[0] ? called : "-", calling[0] ? calling : "-",
            vc->ps_tx, vc->w_tx, vc->mod);
    if (send_pkt(vc, pkt, n) < 0)
        return -1;
    vc->state = X25_CALLING;

    buf_init(&rx);
    for (;;) {
        if (read_pkt(vc, &rx, timeout_ms) < 0) {
            buf_free(&rx);
            return -1;
        }
        uint8_t *p = rx.data;
        uint8_t  t = p[2];
        if (t == PT_CALL_ACC) {
            int a = vc->ps_rx, b = vc->ps_tx, c = vc->w_rx, d = vc->w_tx;
            char save_called[16], save_calling[16];
            strcpy(save_called, called);
            strcpy(save_calling, calling);
            parse_setup(vc, p + 3, rx.len - 3, &a, &b, &c, &d);
            /* first octet: direction called -> calling (our receive).
             * Negotiation may only move towards the defaults, never
             * beyond what we proposed. */
            if (a < vc->ps_rx) vc->ps_rx = a;
            if (b < vc->ps_tx) vc->ps_tx = b;
            if (c >= 1 && c < vc->w_rx) vc->w_rx = c;
            if (d >= 1 && d < vc->w_tx) vc->w_tx = d;
            strcpy(vc->called, save_called);
            strcpy(vc->calling, save_calling);
            vc->state = X25_DATA;
            vc_reset_vars(vc);
            vc->dbit = prm->dbit && (p[0] & 0x40);
            log_msg(LOG_INFO, L, "CALL CONNECTED: packet size tx=%d rx=%d, window tx=%d rx=%d",
                    vc->ps_tx, vc->ps_rx, vc->w_tx, vc->w_rx);
            if (prm->dbit)
                log_msg(LOG_INFO, L, "D-bit procedure %s", vc->dbit ?
                        "agreed" : "not supported by called DTE, not used");
            buf_free(&rx);
            return 0;
        }
        if (t == PT_CLEAR_REQ) {
            vc->clear_cause = rx.len > 3 ? p[3] : 0;
            vc->clear_diag = rx.len > 4 ? p[4] : 0;
            send_simple(vc, PT_CLEAR_CONF, 0, 0, 0);
            vc->state = X25_CLEARED;
            set_error("call refused: cause 0x%02x (%s), diagnostic %u",
                      vc->clear_cause, x25_cause_str(vc->clear_cause), vc->clear_diag);
            buf_free(&rx);
            return -1;
        }
        log_msg(LOG_INFO, L, "ignoring packet type 0x%02x while calling", t);
    }
}

int x25_accept(x25_vc *vc, int fd, int max_pkt, int max_win, int timeout_ms,
               trace_t *trace)
{
    buf_t rx;
    vc_init(vc, fd, trace);
    vc->timeout_ms = timeout_ms;
    buf_init(&rx);

    tcp_tune(fd);

    for (;;) {
        if (read_pkt(vc, &rx, timeout_ms) < 0) {
            buf_free(&rx);
            return -1;
        }
        if (rx.data[2] == PT_CALL_REQ)
            break;
        log_msg(LOG_INFO, L, "ignoring packet type 0x%02x before call", rx.data[2]);
    }
    uint8_t *p = rx.data;
    vc->lcn = ((p[0] & 0x0f) << 8) | p[1];
    vc->mod = ((p[0] & 0x30) == 0x20) ? 128 : 8;
    int a = 128, b = 128, c = 2, d = 2;
    size_t off = 3 + parse_setup(vc, p + 3, rx.len - 3, &a, &b, &c, &d);
    if (off < rx.len) {
        vc->cud_len = rx.len - off;
        if (vc->cud_len > sizeof vc->cud)
            vc->cud_len = sizeof vc->cud;
        memcpy(vc->cud, p + off, vc->cud_len);
    }
    /* we are the called DTE: a = our tx direction, b = our rx */
    if (a > max_pkt) a = max_pkt;
    if (b > max_pkt) b = max_pkt;
    if (c > max_win) c = max_win;
    if (d > max_win) d = max_win;
    if (c < 1 || c > vc->mod - 1) c = 2;
    if (d < 1 || d > vc->mod - 1) d = 2;
    vc->ps_tx = a;
    vc->ps_rx = b;
    vc->w_tx = c;
    vc->w_rx = d;
    log_msg(LOG_INFO, L, "INCOMING CALL lcn=%d called=%s calling=%s pkt=%d/%d win=%d/%d",
            vc->lcn, vc->called, vc->calling, a, b, c, d);

    uint8_t pkt[16];
    size_t  n = pkt_hdr(vc, pkt, PT_CALL_ACC);
    vc->dbit = (p[0] & 0x40) != 0;
    if (vc->dbit) {
        pkt[0] |= 0x40;                 /* D-bit procedure agreed */
        log_msg(LOG_INFO, L, "D-bit procedure agreed");
    }
    pkt[n++] = 0;                       /* no addresses */
    pkt[n++] = 6;
    pkt[n++] = FAC_PKT_SIZE;
    pkt[n++] = (uint8_t)log2i(a);
    pkt[n++] = (uint8_t)log2i(b);
    pkt[n++] = FAC_WIN_SIZE;
    pkt[n++] = (uint8_t)c;
    pkt[n++] = (uint8_t)d;
    buf_free(&rx);
    if (send_pkt(vc, pkt, n) < 0)
        return -1;
    vc->state = X25_DATA;
    vc_reset_vars(vc);
    return 0;
}

/*
 * Wait for and process one packet while we have unacknowledged data
 * outstanding.  On expiry of the window rotation timer T25, with
 * retransmission procedures in effect, the outstanding packets are
 * retransmitted (at most R25 times without progress, ISO 8208 11.2).
 */
#define X25_R25 3

static int await_ack(x25_vc *vc, buf_t *rx, int *retries)
{
    unsigned before = vc->pr_peer;
    int rc = read_pkt(vc, rx, vc->t25_ms ? vc->t25_ms : vc->timeout_ms);
    if (rc == 0) {
        if (process_pkt(vc, rx->data, rx->len) < 0)
            return -1;
        if (vc->pr_peer != before)
            *retries = 0;
        return 0;
    }
    if (rc == -2 && vc->use_rej && vc->pr_peer != vc->vs) {
        if (++*retries > X25_R25) {
            set_error("X.25: no acknowledgement after %d retransmissions", X25_R25);
            return -1;
        }
        log_msg(LOG_INFO, L, "T25 expired: retransmitting from P(S)=%u (attempt %d)",
                vc->pr_peer, *retries);
        return retransmit(vc);
    }
    return -1;
}

static int send_nsdu(x25_vc *vc, const uint8_t *data, size_t len, int qbit)
{
    int retries = 0;

    buf_t  rx;
    size_t off = 0;

    if (vc->state != X25_DATA) {
        set_error("X.25 call not established");
        return -1;
    }
    buf_init(&rx);
    do {
        /* wait for an open window */
        while (((vc->vs - vc->pr_peer) % (unsigned)vc->mod) >= (unsigned)vc->w_tx ||
               vc->peer_busy) {
            log_msg(LOG_DEBUG, L, "window closed (V(S)=%u, P(R)=%u%s), waiting",
                    vc->vs, vc->pr_peer, vc->peer_busy ? ", RNR" : "");
            if (await_ack(vc, &rx, &retries) < 0) {
                buf_free(&rx);
                return -1;
            }
        }
        size_t  chunk = len - off;
        int     more = 0;
        if (chunk > (size_t)vc->ps_tx) {
            chunk = (size_t)vc->ps_tx;
            more = 1;
        }
        uint8_t pkt[4 + 4096];
        size_t  hl;
        if (vc->mod == 128) {
            hl = pkt_hdr(vc, pkt, (uint8_t)(vc->vs << 1));
            pkt[hl++] = (uint8_t)(vc->vr << 1 | more);
        } else {
            hl = pkt_hdr(vc, pkt, (uint8_t)(vc->vr << 5 | more << 4 | vc->vs << 1));
        }
        /* delivery confirmation for the complete NSDU */
        int dbit = vc->dbit && !more;
        if (dbit)
            pkt[0] |= 0x40;
        if (qbit)
            pkt[0] |= 0x80;
        memcpy(pkt + hl, data + off, chunk);
        log_msg(LOG_DEBUG, L, "send DATA P(S)=%u P(R)=%u M=%d D=%d Q=%d len=%zu",
                vc->vs, vc->vr, more, dbit, qbit, chunk);
        txwin_store(vc, vc->vs, pkt, hl + chunk);
        vc->vr_acked = vc->vr;
        vc->vs = (vc->vs + 1) % (unsigned)vc->mod;
        if (send_pkt(vc, pkt, hl + chunk) < 0) {
            buf_free(&rx);
            return -1;
        }
        off += chunk;
    } while (off < len);

    /* D-bit: the P(R) covering the last packet is the remote DTE's
     * confirmation of delivery */
    while (vc->dbit && vc->pr_peer != vc->vs) {
        log_msg(LOG_DEBUG, L, "awaiting delivery confirmation (V(S)=%u, P(R)=%u)",
                vc->vs, vc->pr_peer);
        if (await_ack(vc, &rx, &retries) < 0) {
            buf_free(&rx);
            return -1;
        }
    }
    buf_free(&rx);
    return 0;
}

int x25_send(x25_vc *vc, const uint8_t *data, size_t len)
{
    return send_nsdu(vc, data, len, 0);
}

int x25_send_qualified(x25_vc *vc, const uint8_t *data, size_t len)
{
    log_msg(LOG_INFO, L, "send qualified data (%zu octets)", len);
    return send_nsdu(vc, data, len, 1);
}

int x25_set_busy(x25_vc *vc, int busy)
{
    if (vc->state != X25_DATA) {
        set_error("X.25 call not established");
        return -1;
    }
    vc->app_busy = busy;
    if (busy && !vc->busy) {
        vc->busy = 1;
        log_msg(LOG_INFO, L, "receiver not ready (application)");
        return send_rnr(vc);
    }
    return busy ? 0 : update_busy(vc);
}

int x25_hold(x25_vc *vc, int ms)
{
    vc->hold_until = tcp_now_ms() + ms;
    log_msg(LOG_INFO, L, "receiver not ready for %d ms", ms);
    if (vc->busy)
        return 0;
    vc->busy = 1;
    return send_rnr(vc);
}

int x25_interrupt(x25_vc *vc, const uint8_t *data, size_t n)
{
    buf_t   rx;
    uint8_t pkt[3 + X25_MAX_INT_DATA];

    if (vc->state != X25_DATA) {
        set_error("X.25 call not established");
        return -1;
    }
    if (n < 1 || n > X25_MAX_INT_DATA) {
        set_error("interrupt user data must be 1..%d octets", X25_MAX_INT_DATA);
        return -1;
    }
    size_t hl = pkt_hdr(vc, pkt, PT_INTERRUPT);
    memcpy(pkt + hl, data, n);
    log_msg(LOG_INFO, L, "send INTERRUPT (%zu octets)", n);
    if (send_pkt(vc, pkt, hl + n) < 0)
        return -1;
    /* only one unconfirmed interrupt may be outstanding */
    vc->int_pending = 1;
    buf_init(&rx);
    while (vc->int_pending) {
        if (read_pkt(vc, &rx, vc->timeout_ms) < 0 ||
            process_pkt(vc, rx.data, rx.len) < 0) {
            buf_free(&rx);
            return -1;
        }
    }
    buf_free(&rx);
    return 0;
}

int x25_recv(x25_vc *vc, buf_t *out)
{
    buf_t rx;
    long  deadline = tcp_now_ms() + vc->timeout_ms;
    buf_init(&rx);
    while (!vc->qhead) {
        if (vc->state != X25_DATA) {
            set_error("X.25 call not established");
            buf_free(&rx);
            return -1;
        }
        long wait = deadline - tcp_now_ms();
        if (vc->hold_until) {
            long rem = vc->hold_until - tcp_now_ms();
            if (rem <= 0) {
                vc->hold_until = 0;
                if (update_busy(vc) < 0) {
                    buf_free(&rx);
                    return -1;
                }
                continue;
            }
            if (rem < wait)
                wait = rem;
        }
        int rc = wait > 0 ? read_pkt(vc, &rx, (int)wait) : -2;
        if (rc == -2 && vc->hold_until && tcp_now_ms() < deadline)
            continue;                           /* hold expired, not us */
        if (rc < 0 || process_pkt(vc, rx.data, rx.len) < 0) {
            buf_free(&rx);
            return -1;
        }
    }
    buf_free(&rx);
    nsdu_q *q = vc->qhead;
    vc->qhead = q->next;
    if (!vc->qhead)
        vc->qtail = NULL;
    buf_reset(out);
    buf_put(out, q->data, q->len);
    vc->queued_bytes -= q->len;
    free(q);
    if (update_busy(vc) < 0)
        return -1;
    return 0;
}

void x25_clear(x25_vc *vc, uint8_t cause, uint8_t diag)
{
    buf_t rx;
    if (vc->fd < 0 || vc->state == X25_CLEARED || vc->state == X25_IDLE)
        return;
    log_msg(LOG_INFO, L, "CLEAR REQUEST cause 0x%02x diag %u", cause, diag);
    if (send_simple(vc, PT_CLEAR_REQ, 2, cause, diag) < 0) {
        vc->state = X25_CLEARED;
        return;
    }
    vc->state = X25_CLEARING;
    buf_init(&rx);
    long deadline = tcp_now_ms() + 5000;
    while (vc->state == X25_CLEARING && tcp_now_ms() < deadline) {
        if (read_pkt(vc, &rx, (int)(deadline - tcp_now_ms())) < 0)
            break;
        uint8_t t = rx.data[2];
        if (t == PT_CLEAR_CONF || t == PT_CLEAR_REQ)
            vc->state = X25_CLEARED;
    }
    vc->state = X25_CLEARED;
    buf_free(&rx);
}

void x25_close(x25_vc *vc)
{
    while (vc->qhead) {
        nsdu_q *q = vc->qhead;
        vc->qhead = q->next;
        free(q);
    }
    vc->qtail = NULL;
    buf_free(&vc->reasm);
    txwin_clear(vc);
    if (vc->fd >= 0)
        close(vc->fd);
    vc->fd = -1;
    vc->state = X25_IDLE;
}
