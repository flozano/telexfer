/*
 * tp0.h - ISO 8073 / X.224 transport protocol class 0, over X.25 (CONS)
 * or over TCP (RFC 1006).
 *
 * Class 0 has no multiplexing, no flow control and no explicit
 * disconnect phase: the transport connection lives and dies with the
 * network connection (X.25 call or TCP connection).  Each TPDU is
 * carried in exactly one NSDU.
 */
#ifndef FTAM_TP0_H
#define FTAM_TP0_H

#include "net.h"

typedef struct {
    net_conn net;
    int      tpdu_size;         /* negotiated maximum TPDU size */
    uint16_t sref, dref;
    uint8_t  peer_tsel[32];
    size_t   peer_tsel_len;
} tp0_conn;

/* tpdu_size: 128..8192 (above 2048 only makes sense over RFC 1006) */
int  tp0_connect(tp0_conn *tc, net_conn net,
                 const uint8_t *calling, size_t calling_len,
                 const uint8_t *called, size_t called_len, int tpdu_size);
int  tp0_accept(tp0_conn *tc, net_conn net, int max_tpdu);
int  tp0_send(tp0_conn *tc, const uint8_t *p, size_t n);
int  tp0_recv(tp0_conn *tc, buf_t *tsdu);
/* Class 0 release = clearing the network connection. */
void tp0_disconnect(tp0_conn *tc);

#endif
