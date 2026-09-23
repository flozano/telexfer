/*
 * tp0.h - ISO 8073 / X.224 transport protocol class 0 over X.25 (CONS).
 *
 * Class 0 has no multiplexing, no flow control and no explicit
 * disconnect phase: the transport connection lives and dies with the
 * X.25 virtual call.  Each TPDU is carried in exactly one NSDU.
 */
#ifndef FTAM_TP0_H
#define FTAM_TP0_H

#include "x25.h"

typedef struct {
    x25_vc  *vc;
    int      tpdu_size;         /* negotiated maximum TPDU size */
    uint16_t sref, dref;
    uint8_t  peer_tsel[32];
    size_t   peer_tsel_len;
} tp0_conn;

int  tp0_connect(tp0_conn *tc, x25_vc *vc,
                 const uint8_t *calling, size_t calling_len,
                 const uint8_t *called, size_t called_len, int tpdu_size);
int  tp0_accept(tp0_conn *tc, x25_vc *vc, int max_tpdu);
int  tp0_send(tp0_conn *tc, const uint8_t *p, size_t n);
int  tp0_recv(tp0_conn *tc, buf_t *tsdu);
/* Class 0 release = clearing the network connection. */
void tp0_disconnect(tp0_conn *tc);

#endif
