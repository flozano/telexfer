/*
 * tcp.c - TCP helpers shared by the XOT and RFC 1006 transports:
 * connect/listen, and full writes/reads with a deadline.
 */
#include "tcp.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

long tcp_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

int tcp_connect(const char *host, int port, int timeout_ms)
{
    struct addrinfo  hints, *res, *ai;
    char             portstr[16];
    int              fd = -1, rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);
    if ((rc = getaddrinfo(host, portstr, &hints, &res)) != 0) {
        set_error("cannot resolve %s: %s", host, gai_strerror(rc));
        return -1;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        /* bounded connect: poll on a blocking socket is not enough, but
         * the kernel connect timeout is acceptable for a CLI; use alarm-
         * free approach with SO_SNDTIMEO */
        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        set_error("connect to %s:%d: %s", host, port, strerror(errno));
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        int one = 1;
        tcp_tune(fd);
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
        log_msg(LOG_INFO, "tcp", "connected to %s:%d", host, port);
    }
    return fd;
}

void tcp_tune(int fd)
{
    /* protocol units are small and paced by the peer: with Nagle, one
     * waits for the (delayed) ACK of the previous, ~40 ms on Linux */
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
}

int tcp_listen(const char *bind_addr, int port)
{
    struct addrinfo hints, *res;
    char            portstr[16];
    int             fd, one = 1, rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    snprintf(portstr, sizeof portstr, "%d", port);
    if ((rc = getaddrinfo(bind_addr, portstr, &hints, &res)) != 0) {
        set_error("getaddrinfo: %s", gai_strerror(rc));
        return -1;
    }
    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        set_error("socket: %s", strerror(errno));
        freeaddrinfo(res);
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0 || listen(fd, 8) < 0) {
        set_error("bind/listen port %d: %s", port, strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

int tcp_write_all(int fd, const struct iovec *iov, int cnt)
{
    struct iovec v[4];
    memcpy(v, iov, sizeof(*iov) * (size_t)cnt);
    while (cnt > 0) {
        ssize_t w = writev(fd, v, cnt);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            set_error("TCP write: %s", strerror(errno));
            return -1;
        }
        while (cnt > 0 && (size_t)w >= v[0].iov_len) {
            w -= (ssize_t)v[0].iov_len;
            memmove(v, v + 1, sizeof(*v) * (size_t)(cnt - 1));
            cnt--;
        }
        if (cnt > 0) {
            v[0].iov_base = (char *)v[0].iov_base + w;
            v[0].iov_len -= (size_t)w;
        }
    }
    return 0;
}

int tcp_read_full(int fd, uint8_t *p, size_t n, long deadline)
{
    while (n > 0) {
        long left = deadline - tcp_now_ms();
        if (left <= 0) {
            set_error("timeout waiting for data from peer");
            return -2;
        }
        struct pollfd pfd = { fd, POLLIN, 0 };
        int pr = poll(&pfd, 1, (int)left);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            set_error("poll: %s", strerror(errno));
            return -1;
        }
        if (pr == 0)
            continue;
        ssize_t r = read(fd, p, n);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            set_error("TCP read: %s", strerror(errno));
            return -1;
        }
        if (r == 0) {
            set_error("connection closed by peer");
            return -1;
        }
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

