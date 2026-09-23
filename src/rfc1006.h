/*
 * rfc1006.h - ISO transport service on top of TCP (RFC 1006): every TPDU
 * travels in a TPKT, a 4 octet header (version 3, reserved 0, 16 bit
 * length including the header) followed by the TPDU.  Well-known port 102.
 */
#ifndef FTAM_RFC1006_H
#define FTAM_RFC1006_H

#include "net.h"
#include "trace.h"

#define RFC1006_PORT     102
#define TPKT_VERSION     3
#define TPKT_MAX_TPDU    (65535 - 4)

typedef struct {
    int      fd;
    int      timeout_ms;
    trace_t *trace;
} tpkt_conn;

void     tpkt_init(tpkt_conn *t, int fd, int timeout_ms, trace_t *trace);
int      tpkt_send(tpkt_conn *t, const uint8_t *p, size_t n);
int      tpkt_recv(tpkt_conn *t, buf_t *out);
/* Class 0 over RFC 1006 releases by closing the TCP connection. */
void     tpkt_close(tpkt_conn *t);
net_conn tpkt_net(tpkt_conn *t);

#endif
