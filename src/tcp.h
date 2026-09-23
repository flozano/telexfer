/*
 * tcp.h - TCP helpers shared by the XOT and RFC 1006 transports.
 */
#ifndef FTAM_TCP_H
#define FTAM_TCP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

#include "util.h"

/* Monotonic clock in milliseconds. */
long tcp_now_ms(void);
/* Connected socket (TCP_NODELAY set) or -1 with the error set. */
int  tcp_connect(const char *host, int port, int timeout_ms);
int  tcp_listen(const char *bind_addr, int port);
/* Set TCP_NODELAY (and SO_NOSIGPIPE where it exists) on a socket. */
void tcp_tune(int fd);
int  tcp_write_all(int fd, const struct iovec *iov, int cnt);
/* 0 = done, -2 = deadline passed, -1 = error or connection closed. */
int  tcp_read_full(int fd, uint8_t *p, size_t n, long deadline);

#endif
