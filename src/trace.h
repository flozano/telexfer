/*
 * trace.h - write the XOT byte stream to a pcap file as synthetic
 * IPv4/TCP segments, so the whole OSI stack can be inspected with
 * Wireshark/tshark (XOT -> X.25 -> COTP -> SES -> PRES -> ACSE -> FTAM).
 */
#ifndef FTAM_TRACE_H
#define FTAM_TRACE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
    FILE    *f;
    uint16_t lport, rport;
    uint32_t seq[2];        /* [0] local->remote, [1] remote->local */
} trace_t;

int  trace_open(trace_t *t, const char *path, uint16_t lport, uint16_t rport);
/* outbound != 0: local -> remote */
void trace_write(trace_t *t, int outbound, const uint8_t *p, size_t n);
void trace_close(trace_t *t);

#endif
