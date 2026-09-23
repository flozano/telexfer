/*
 * session.h - ISO 8327-1 / X.225 session protocol, kernel + duplex
 * functional units (what FTAM needs), protocol version 2.
 */
#ifndef FTAM_SESSION_H
#define FTAM_SESSION_H

#include "tp0.h"

/* session requirements (PI 20) */
#define SUR_HALF_DUPLEX 0x0001
#define SUR_DUPLEX      0x0002

enum {
    SES_EV_DATA = 1,        /* DT: user data                        */
    SES_EV_FINISH,          /* FN: peer requests orderly release    */
    SES_EV_DISCONNECT,      /* DN: release accepted                 */
    SES_EV_NOT_FINISHED,    /* NF: release refused                  */
    SES_EV_ABORT,           /* AB: peer aborted                     */
};

typedef struct {
    tp0_conn *tc;
    int       version;      /* negotiated: 1 or 2 */
    uint16_t  sur;          /* negotiated session requirements */
    buf_t     tsdu;
    /* segmenting (TSDU maximum size, PI 21); 0 = unlimited */
    int       tsdu_max_tx;  /* our sending direction */
    int       tsdu_max_rx;  /* peer's sending direction */
    int       tsdu_limit;   /* responder: our own limit (0 = none) */
    int       cn_tsdu[2];   /* responder: values proposed in CN */
    int       cn_has_tsdu;
    buf_t     ssdu;         /* SSDU under reassembly */
    int       in_ssdu;
    int       peer_ext_concat;  /* peer can receive extended concatenation */
} ses_conn;

typedef struct {
    int tsdu_max;           /* > 0: propose segmenting with this TSDU size */
    int ext_concat;         /* announce that we receive extended concatenation */
} ses_params;

/* smallest TSDU maximum size accepted for segmenting */
#define SES_MIN_TSDU 64

/*
 * Connect.  Returns 0 if accepted (resp_ud = AC user data), 1 if
 * refused (resp_ud = RF user data, *reason = refuse reason), -1 error.
 * User data beyond 10240 octets is sent with the data overflow procedure
 * (CN + OA + CDO...).  prm may be NULL.
 */
int  ses_connect(ses_conn *s, tp0_conn *tc,
                 const uint8_t *calling, size_t calling_len,
                 const uint8_t *called, size_t called_len,
                 const uint8_t *ud, size_t udlen, const ses_params *prm,
                 buf_t *resp_ud, int *reason);
/* Responder: wait for CN, returning its user data (including any
 * connect data overflow, collected via OA/CDO).  tsdu_limit > 0 is the
 * largest TSDU we accept; segmenting is used if the initiator proposed
 * it.  The responder always announces extended concatenation. */
int  ses_wait_connect(ses_conn *s, tp0_conn *tc, buf_t *cn_ud, int tsdu_limit);
void ses_free(ses_conn *s);
int  ses_accept(ses_conn *s, const uint8_t *ud, size_t udlen);

int  ses_send_data(ses_conn *s, const uint8_t *p, size_t n);
/* DT preceded by other (already encoded) category 2 SPDUs in the same
 * TSDU: extended concatenation, only if the peer announced it. */
int  ses_send_data_concat(ses_conn *s, const uint8_t *cat2, size_t cat2len,
                          const uint8_t *p, size_t n);
int  ses_recv(ses_conn *s, int *ev, buf_t *ud);
int  ses_finish(ses_conn *s, const uint8_t *ud, size_t n);      /* FN */
int  ses_disconnect(ses_conn *s, const uint8_t *ud, size_t n);  /* DN */
int  ses_abort(ses_conn *s, const uint8_t *ud, size_t n);       /* AB */

#endif
