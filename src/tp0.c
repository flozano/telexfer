/*
 * tp0.c - ISO 8073 / X.224 transport class 0 over any net_conn.
 */
#include "tp0.h"

#include <string.h>

#define TPDU_CR 0xe0
#define TPDU_CC 0xd0
#define TPDU_DR 0x80
#define TPDU_DT 0xf0
#define TPDU_ER 0x70

#define P_TPDU_SIZE 0xc0
#define P_CALLING   0xc1
#define P_CALLED    0xc2

static const char *L = "tp0";

static int size_code(int size)
{
    int c = 7;
    while (c < 13 && (1 << (c + 1)) <= size)
        c++;
    return c;
}

static const char *dr_reason(uint8_t r)
{
    switch (r) {
    case 0x00: return "reason not specified";
    case 0x01: return "congestion at TSAP";
    case 0x02: return "session entity not attached to TSAP";
    case 0x03: return "address unknown";
    case 0x80: return "normal disconnect";
    case 0x81: return "remote transport entity congestion";
    case 0x82: return "connection negotiation failed";
    case 0x83: return "duplicate source reference";
    case 0x84: return "mismatched references";
    case 0x85: return "protocol error";
    case 0x87: return "reference overflow";
    case 0x88: return "connection request refused on this network connection";
    case 0x8a: return "header or parameter length invalid";
    default:   return "unknown reason";
    }
}

/* Parse CR/CC variable part. */
static void parse_params(tp0_conn *tc, const uint8_t *p, size_t n,
                         int *size, uint8_t *tsel, size_t *tsel_len,
                         uint8_t want_tsel)
{
    size_t off = 0;
    while (off + 2 <= n) {
        uint8_t code = p[off], len = p[off + 1];
        if (off + 2 + len > n)
            break;
        const uint8_t *v = p + off + 2;
        if (code == P_TPDU_SIZE && len == 1 && v[0] >= 7 && v[0] <= 13)
            *size = 1 << v[0];
        else if (code == want_tsel && tsel && len <= 32) {
            memcpy(tsel, v, len);
            *tsel_len = len;
        }
        off += 2u + len;
    }
    (void)tc;
}

int tp0_connect(tp0_conn *tc, net_conn net,
                const uint8_t *calling, size_t calling_len,
                const uint8_t *called, size_t called_len, int tpdu_size)
{
    uint8_t cr[128];
    size_t  n = 0;
    buf_t   rx;

    memset(tc, 0, sizeof *tc);
    tc->net = net;
    tc->sref = 0x0001;
    if (tpdu_size <= 0)
        tpdu_size = 2048;
    if (calling_len > 32 || called_len > 32) {
        set_error("TSAP selectors are limited to 32 octets");
        return -1;
    }

    cr[n++] = 0;                        /* LI, filled below */
    cr[n++] = TPDU_CR;
    cr[n++] = 0; cr[n++] = 0;           /* DST-REF */
    cr[n++] = (uint8_t)(tc->sref >> 8);
    cr[n++] = (uint8_t)tc->sref;
    cr[n++] = 0x00;                     /* class 0, no options */
    if (calling_len) {
        cr[n++] = P_CALLING;
        cr[n++] = (uint8_t)calling_len;
        memcpy(cr + n, calling, calling_len);
        n += calling_len;
    }
    if (called_len) {
        cr[n++] = P_CALLED;
        cr[n++] = (uint8_t)called_len;
        memcpy(cr + n, called, called_len);
        n += called_len;
    }
    cr[n++] = P_TPDU_SIZE;
    cr[n++] = 1;
    cr[n++] = (uint8_t)size_code(tpdu_size);
    cr[0] = (uint8_t)(n - 1);

    log_msg(LOG_INFO, L, "CR class 0, TPDU size %d", 1 << size_code(tpdu_size));
    if (net.ops->send(net.impl, cr, n) < 0)
        return -1;

    buf_init(&rx);
    if (net.ops->recv(net.impl, &rx) < 0) {
        buf_free(&rx);
        return -1;
    }
    const uint8_t *p = rx.data;
    if (rx.len < 2 || p[0] + 1u > rx.len) {
        set_error("TP0: malformed TPDU in reply to CR");
        buf_free(&rx);
        return -1;
    }
    uint8_t code = p[1] & 0xf0;
    if (code == TPDU_CC && rx.len >= 7) {
        if ((p[6] & 0xf0) != 0) {
            set_error("TP0: responder selected class %d, only class 0 supported",
                      p[6] >> 4);
            buf_free(&rx);
            return -1;
        }
        tc->dref = (uint16_t)(p[4] << 8 | p[5]);
        tc->tpdu_size = 128;            /* class 0 default if absent */
        parse_params(tc, p + 7, (size_t)p[0] + 1 - 7, &tc->tpdu_size,
                     tc->peer_tsel, &tc->peer_tsel_len, P_CALLED);
        if (tc->tpdu_size > (1 << size_code(tpdu_size)))
            tc->tpdu_size = 1 << size_code(tpdu_size);
        log_msg(LOG_INFO, L, "CC received, TPDU size %d", tc->tpdu_size);
        buf_free(&rx);
        return 0;
    }
    if (code == TPDU_DR && rx.len >= 7) {
        set_error("transport connection refused: %s (0x%02x)",
                  dr_reason(p[6]), p[6]);
    } else if (code == TPDU_ER) {
        set_error("transport protocol error (ER TPDU, cause %d)", rx.len > 4 ? p[4] : -1);
    } else {
        set_error("TP0: unexpected TPDU 0x%02x in reply to CR", p[1]);
    }
    buf_free(&rx);
    return -1;
}

int tp0_accept(tp0_conn *tc, net_conn net, int max_tpdu)
{
    buf_t rx;
    memset(tc, 0, sizeof *tc);
    tc->net = net;
    tc->sref = 0x0002;
    buf_init(&rx);
    if (net.ops->recv(net.impl, &rx) < 0) {
        buf_free(&rx);
        return -1;
    }
    const uint8_t *p = rx.data;
    if (rx.len < 7 || (p[1] & 0xf0) != TPDU_CR || p[0] + 1u > rx.len) {
        set_error("TP0: expected CR TPDU");
        buf_free(&rx);
        return -1;
    }
    tc->dref = (uint16_t)(p[4] << 8 | p[5]);
    tc->tpdu_size = 128;
    parse_params(tc, p + 7, (size_t)p[0] + 1 - 7, &tc->tpdu_size,
                 tc->peer_tsel, &tc->peer_tsel_len, P_CALLING);
    if (tc->tpdu_size > max_tpdu)
        tc->tpdu_size = max_tpdu;
    buf_free(&rx);

    uint8_t cc[16];
    size_t  n = 0;
    cc[n++] = 0;
    cc[n++] = TPDU_CC;
    cc[n++] = (uint8_t)(tc->dref >> 8);
    cc[n++] = (uint8_t)tc->dref;
    cc[n++] = (uint8_t)(tc->sref >> 8);
    cc[n++] = (uint8_t)tc->sref;
    cc[n++] = 0x00;
    cc[n++] = P_TPDU_SIZE;
    cc[n++] = 1;
    cc[n++] = (uint8_t)size_code(tc->tpdu_size);
    cc[0] = (uint8_t)(n - 1);
    log_msg(LOG_INFO, L, "CR accepted, TPDU size %d", tc->tpdu_size);
    return net.ops->send(net.impl, cc, n);
}

int tp0_send(tp0_conn *tc, const uint8_t *p, size_t n)
{
    size_t  max = (size_t)tc->tpdu_size - 3;
    size_t  off = 0;
    uint8_t tpdu[3 + 8192];

    do {
        size_t chunk = n - off;
        int    eot = 1;
        if (chunk > max) {
            chunk = max;
            eot = 0;
        }
        tpdu[0] = 2;
        tpdu[1] = TPDU_DT;
        tpdu[2] = eot ? 0x80 : 0x00;
        memcpy(tpdu + 3, p + off, chunk);
        if (tc->net.ops->send(tc->net.impl, tpdu, chunk + 3) < 0)
            return -1;
        off += chunk;
    } while (off < n);
    log_msg(LOG_DEBUG, L, "sent TSDU of %zu octets", n);
    return 0;
}

int tp0_recv(tp0_conn *tc, buf_t *tsdu)
{
    buf_t rx;
    buf_init(&rx);
    buf_reset(tsdu);
    for (;;) {
        if (tc->net.ops->recv(tc->net.impl, &rx) < 0) {
            buf_free(&rx);
            return -1;
        }
        const uint8_t *p = rx.data;
        if (rx.len < 2 || p[0] + 1u > rx.len) {
            set_error("TP0: malformed TPDU");
            buf_free(&rx);
            return -1;
        }
        uint8_t code = p[1] & 0xf0;
        if (code == TPDU_DT && p[0] >= 2) {
            size_t hl = (size_t)p[0] + 1;
            buf_put(tsdu, p + hl, rx.len - hl);
            if (p[2] & 0x80) {
                buf_free(&rx);
                log_msg(LOG_DEBUG, L, "received TSDU of %zu octets", tsdu->len);
                return 0;
            }
            continue;
        }
        if (code == TPDU_DR) {
            set_error("transport disconnected by peer: %s",
                      rx.len >= 7 ? dr_reason(p[6]) : "no reason");
        } else if (code == TPDU_ER) {
            set_error("transport protocol error (ER TPDU)");
        } else {
            set_error("TP0: unexpected TPDU type 0x%02x", p[1]);
        }
        buf_free(&rx);
        return -1;
    }
}

void tp0_disconnect(tp0_conn *tc)
{
    if (tc->net.ops)
        tc->net.ops->disconnect(tc->net.impl);
}
