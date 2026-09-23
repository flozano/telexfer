/*
 * x25.h - X.25 packet layer (ISO 8208 DTE side) carried over TCP using
 * XOT, RFC 1613.  One TCP connection carries exactly one virtual call.
 *
 * The layer offers a connection-mode network service to TP0: whole
 * NSDUs are sent and received; segmentation into packets with the
 * M-bit, window-based flow control and packet acknowledgement are
 * handled internally.
 */
#ifndef FTAM_X25_H
#define FTAM_X25_H

#include <stddef.h>
#include <stdint.h>

#include "net.h"
#include "tcp.h"
#include "trace.h"
#include "util.h"

#define XOT_PORT 1998

typedef struct {
    const char *called;         /* X.121 address digits (may be "")   */
    const char *calling;        /* X.121 address digits (may be "")   */
    uint8_t     cud[128];       /* call user data                     */
    size_t      cud_len;
    int         pkt_size;       /* 16..4096, power of two             */
    int         window;         /* 1..7 (mod 8) or 1..127 (mod 128)   */
    int         mod128;
    int         lcn;            /* logical channel, 1..4095           */
    int         use_rej;        /* answer out-of-sequence data with REJ
                                   (packet retransmission) instead of a reset */
    int         dbit;           /* request the D-bit (delivery confirmation)
                                   procedure */
    int         t25_ms;         /* window rotation timer T25; with use_rej,
                                   unacknowledged packets are retransmitted
                                   on expiry (0 = the receive timeout) */
    size_t      rx_limit;       /* received data waiting for the upper
                                   layer beyond which RNR is sent
                                   (0 = 64 KiB) */
} x25_params;

#define X25_MAX_INT_DATA 32     /* interrupt user data, X.25 (1984+) */

typedef void (*x25_int_fn)(void *arg, const uint8_t *data, size_t len);
/* qualified (Q-bit) NSDUs are control data and bypass the transport */
typedef void (*x25_qdata_fn)(void *arg, const uint8_t *data, size_t len);

typedef struct nsdu_q {
    struct nsdu_q *next;
    size_t         len;
    uint8_t        data[];
} nsdu_q;

enum { X25_IDLE, X25_CALLING, X25_DATA, X25_CLEARING, X25_CLEARED };

typedef struct {
    int       fd;
    int       state;
    int       lcn;
    int       mod;              /* 8 or 128 */
    int       ps_tx, ps_rx;     /* max data field size per direction */
    int       w_tx, w_rx;       /* window per direction */
    unsigned  vs, vr;           /* send / receive state variables */
    unsigned  pr_peer;          /* lower window edge (last P(R) received) */
    unsigned  vr_acked;         /* last P(R) we sent */
    int       peer_busy;        /* RNR received */
    int       use_rej;          /* send REJ on out-of-sequence data and
                                   retransmit on T25 expiry */
    int       t25_ms;           /* 0 = timeout_ms */
    int       rej_sent;         /* REJ condition: waiting for retransmission */
    int       dbit;             /* D-bit procedure agreed for this call */
    int       int_pending;      /* our interrupt awaits confirmation */
    x25_int_fn on_interrupt;    /* received interrupt data (NULL: log only) */
    void     *int_arg;
    x25_qdata_fn on_qdata;      /* received Q-bit NSDUs (NULL: log only) */
    void     *qdata_arg;
    int       in_mseq;          /* an M-bit sequence is being reassembled */
    int       reasm_q;          /* ... and its Q-bit */
    size_t    rx_limit;         /* see x25_params */
    size_t    queued_bytes;     /* complete NSDUs not yet taken by x25_recv */
    int       busy;             /* we are in the RNR (receiver not ready) state */
    int       app_busy;         /* ... because the application asked for it */
    long      hold_until;       /* x25_hold: busy until this time (ms) */
    int       test_drop;        /* test hook: discard the Nth received data
                                   packet as if lost (0 = off) */
    int       rx_data_count;
    uint8_t  *txwin[128];       /* sent, unacknowledged data packets by P(S) */
    size_t    txwin_len[128];
    int       timeout_ms;
    uint8_t   clear_cause, clear_diag;
    buf_t     reasm;            /* NSDU under reassembly (M-bit) */
    nsdu_q   *qhead, *qtail;
    trace_t  *trace;
    /* incoming call details (server side) */
    char      called[16], calling[16];
    uint8_t   cud[128];
    size_t    cud_len;
} x25_vc;

/* Place a call (client) on an already connected XOT TCP socket. */
int  x25_call(x25_vc *vc, int fd, const x25_params *p, int timeout_ms,
              trace_t *trace);
/* Wait for an incoming call and accept it (test responder).  The D-bit
 * procedure is agreed if the caller requests it. */
int  x25_accept(x25_vc *vc, int fd, int max_pkt, int max_win,
                int timeout_ms, trace_t *trace);
/* Send one NSDU.  With the D-bit procedure in effect, returns only after
 * the remote DTE has confirmed delivery of the NSDU. */
int  x25_send(x25_vc *vc, const uint8_t *p, size_t n);
/* Send one NSDU with the Q-bit set (qualified data, e.g. X.29 control). */
int  x25_send_qualified(x25_vc *vc, const uint8_t *p, size_t n);
/* Send an INTERRUPT packet with 1..32 octets of user data and wait for
 * its confirmation. */
int  x25_interrupt(x25_vc *vc, const uint8_t *data, size_t n);
/* Flow control towards the peer: busy != 0 sends RNR and keeps the
 * receiver-not-ready state; 0 sends RR (unless the receive buffer is
 * still over its limit). */
int  x25_set_busy(x25_vc *vc, int busy);
/* Be busy for ms milliseconds; x25_recv sends RR when the time is up. */
int  x25_hold(x25_vc *vc, int ms);
/* Receive one NSDU (blocks up to vc->timeout_ms). */
int  x25_recv(x25_vc *vc, buf_t *out);
/* Clear the call (sends CLEAR REQUEST, waits for confirmation). */
void x25_clear(x25_vc *vc, uint8_t cause, uint8_t diag);
/* Release resources and close the socket. */
void x25_close(x25_vc *vc);

const char *x25_cause_str(uint8_t cause);

/* The call as TP0's network connection. */
net_conn x25_net(x25_vc *vc);

#endif
