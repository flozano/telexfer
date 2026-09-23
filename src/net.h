/*
 * net.h - the network service TP0 runs on.  One NSDU carries exactly
 * one TPDU; the two implementations are X.25 over XOT (x25.c) and
 * RFC 1006 (rfc1006.c, TPKT over TCP).
 */
#ifndef FTAM_NET_H
#define FTAM_NET_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

typedef struct {
    const char *name;
    int  (*send)(void *impl, const uint8_t *p, size_t n);
    int  (*recv)(void *impl, buf_t *out);
    /* release the network connection: X.25 clear, or TCP close */
    void (*disconnect)(void *impl);
} net_ops;

typedef struct {
    const net_ops *ops;
    void          *impl;
} net_conn;

#endif
