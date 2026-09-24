/*
 * x25linux.h - the Linux kernel's X.25 (AF_X25 sockets) as TP0's network
 * service.  The kernel runs the packet layer and the link below it (LAPB
 * on a synchronous line, or LAPB over Ethernet with lapbether): call set
 * up, windows, M-bit segmentation and reassembly.  A SOCK_SEQPACKET
 * message is one complete NSDU, which is exactly one TPDU for class 0.
 *
 * Linux only; elsewhere every call fails with "not supported".
 */
#ifndef FTAM_X25LINUX_H
#define FTAM_X25LINUX_H

#include <stddef.h>
#include <stdint.h>

#include "net.h"

typedef struct {
    int     fd;
    int     timeout_ms;
    uint8_t clear_cause, clear_diag;
} kx25_conn;

typedef struct {
    const char *called;         /* X.121 address */
    const char *calling;        /* X.121 address, "" = the kernel's choice */
    const uint8_t *cud;         /* call user data */
    size_t      cud_len;
    int         pkt_size;       /* 0 = subscription default */
    int         window;         /* 0 = subscription default */
} kx25_params;

int      kx25_supported(void);
int      kx25_connect(kx25_conn *k, const kx25_params *p, int timeout_ms);
/* Responder: listen on a local X.121 address, then take one call. */
int      kx25_listen(const char *local);
int      kx25_accept(kx25_conn *k, int lfd, int timeout_ms);
void     kx25_close(kx25_conn *k);
net_conn kx25_net(kx25_conn *k);
/* Add a route: calls to addresses starting with the first 'digits'
 * digits of 'prefix' leave through network device 'dev' (e.g. lapb0). */
int      kx25_add_route(const char *prefix, int digits, const char *dev);

#endif
