/*
 * trace.c - pcap writer for the XOT byte stream (LINKTYPE_RAW, IPv4/TCP).
 * The local side is 10.0.0.1, the remote side 10.0.0.2.
 */
#include "trace.h"

#include <string.h>
#include <sys/time.h>

static void put32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void put16be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32be(uint8_t *p, uint32_t v)
{
    put16be(p, (uint16_t)(v >> 16));
    put16be(p + 2, (uint16_t)v);
}

static uint32_t csum_add(uint32_t sum, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i + 1 < n; i += 2)
        sum += (uint32_t)(p[i] << 8 | p[i + 1]);
    if (n & 1)
        sum += (uint32_t)(p[n - 1] << 8);
    return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

int trace_open(trace_t *t, const char *path, uint16_t lport, uint16_t rport)
{
    memset(t, 0, sizeof *t);
    t->f = fopen(path, "wb");
    if (!t->f)
        return -1;
    t->lport = lport;
    t->rport = rport;
    t->seq[0] = 1000;
    t->seq[1] = 5000;

    uint8_t gh[24];
    put32le(gh, 0xa1b2c3d4);
    gh[4] = 2; gh[5] = 0;           /* version 2.4 */
    gh[6] = 4; gh[7] = 0;
    put32le(gh + 8, 0);
    put32le(gh + 12, 0);
    put32le(gh + 16, 65535);
    put32le(gh + 20, 101);          /* LINKTYPE_RAW */
    fwrite(gh, 1, sizeof gh, t->f);
    return 0;
}

void trace_write(trace_t *t, int outbound, const uint8_t *p, size_t n)
{
    if (!t || !t->f)
        return;
    if (n > 65000)
        n = 65000;

    uint8_t  hdr[40];
    uint8_t  src[4] = { 10, 0, 0, (uint8_t)(outbound ? 1 : 2) };
    uint8_t  dst[4] = { 10, 0, 0, (uint8_t)(outbound ? 2 : 1) };
    int      d = outbound ? 0 : 1;
    uint16_t tot = (uint16_t)(40 + n);

    memset(hdr, 0, sizeof hdr);
    hdr[0] = 0x45;
    put16be(hdr + 2, tot);
    hdr[8] = 64;
    hdr[9] = 6;                     /* TCP */
    memcpy(hdr + 12, src, 4);
    memcpy(hdr + 16, dst, 4);
    put16be(hdr + 10, csum_fold(csum_add(0, hdr, 20)));

    uint8_t *th = hdr + 20;
    put16be(th, outbound ? t->lport : t->rport);
    put16be(th + 2, outbound ? t->rport : t->lport);
    put32be(th + 4, t->seq[d]);
    put32be(th + 8, t->seq[!d]);
    th[12] = 5 << 4;
    th[13] = 0x18;                  /* PSH|ACK */
    put16be(th + 14, 65535);

    uint8_t pseudo[12];
    memcpy(pseudo, src, 4);
    memcpy(pseudo + 4, dst, 4);
    pseudo[8] = 0;
    pseudo[9] = 6;
    put16be(pseudo + 10, (uint16_t)(20 + n));
    uint32_t sum = csum_add(0, pseudo, 12);
    sum = csum_add(sum, th, 20);
    /* payload may be odd length; checksum over it separately is fine
     * because the TCP header is 20 (even) bytes */
    sum = csum_add(sum, p, n);
    put16be(th + 16, csum_fold(sum));

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint8_t rh[16];
    put32le(rh, (uint32_t)tv.tv_sec);
    put32le(rh + 4, (uint32_t)tv.tv_usec);
    put32le(rh + 8, tot);
    put32le(rh + 12, tot);
    fwrite(rh, 1, sizeof rh, t->f);
    fwrite(hdr, 1, sizeof hdr, t->f);
    fwrite(p, 1, n, t->f);
    fflush(t->f);
    t->seq[d] += (uint32_t)n;
}

void trace_close(trace_t *t)
{
    if (t && t->f) {
        fclose(t->f);
        t->f = NULL;
    }
}
