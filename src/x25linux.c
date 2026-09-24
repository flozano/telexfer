/*
 * x25linux.c - TP0 over the Linux kernel's X.25 (AF_X25).
 */
#include "x25linux.h"

#include <string.h>

#include "x25.h"                        /* x25_cause_str */

static const char *L = "kx25";

#if defined(__linux__) && __has_include(<linux/x25.h>)

#include <errno.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/x25.h>

#ifndef AF_X25
#define AF_X25 9
#endif
#ifndef SIOCADDRT
#include <linux/sockios.h>
#endif

int kx25_supported(void)
{
    int fd = socket(AF_X25, SOCK_SEQPACKET, 0);
    if (fd < 0)
        return 0;
    close(fd);
    return 1;
}

static int set_addr(struct sockaddr_x25 *sa, const char *digits)
{
    memset(sa, 0, sizeof *sa);
    sa->sx25_family = AF_X25;
    if (strlen(digits) > 15 || strspn(digits, "0123456789") != strlen(digits)) {
        set_error("X.121 addresses must be at most 15 decimal digits");
        return -1;
    }
    strcpy(sa->sx25_addr.x25_addr, digits);
    return 0;
}

static int log2i(int v)
{
    int n = 0;
    while ((1 << n) < v)
        n++;
    return n;
}

static int wait_fd(int fd, short ev, int timeout_ms)
{
    struct pollfd pfd = { fd, ev, 0 };
    int rc;
    do {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);
    if (rc == 0) {
        set_error("X.25: timeout");
        return -1;
    }
    if (rc < 0) {
        set_error("X.25: poll: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static void read_cause(kx25_conn *k)
{
    struct x25_causediag cd;
    if (ioctl(k->fd, SIOCX25GCAUSEDIAG, &cd) == 0) {
        k->clear_cause = cd.cause;
        k->clear_diag = cd.diagnostic;
    }
}

static void failed(kx25_conn *k, const char *what)
{
    int err = errno;
    read_cause(k);
    if (k->clear_cause || k->clear_diag)
        set_error("X.25 %s: call cleared, cause 0x%02x (%s), diagnostic %u",
                  what, k->clear_cause, x25_cause_str(k->clear_cause), k->clear_diag);
    else
        set_error("X.25 %s: %s", what, strerror(err));
}

int kx25_connect(kx25_conn *k, const kx25_params *p, int timeout_ms)
{
    struct sockaddr_x25 local, remote;

    memset(k, 0, sizeof *k);
    k->timeout_ms = timeout_ms;
    k->fd = socket(AF_X25, SOCK_SEQPACKET, 0);
    if (k->fd < 0) {
        set_error("X.25 socket: %s (is the x25 kernel module loaded?)", strerror(errno));
        return -1;
    }
    if (set_addr(&local, p->calling ? p->calling : "") < 0 ||
        set_addr(&remote, p->called ? p->called : "") < 0)
        goto fail;
    if (bind(k->fd, (struct sockaddr *)&local, sizeof local) < 0) {
        set_error("X.25 bind %s: %s", local.sx25_addr.x25_addr, strerror(errno));
        goto fail;
    }

    /* packet and window size, as facilities of the call request */
    struct x25_facilities fac;
    if (ioctl(k->fd, SIOCX25GFACILITIES, &fac) == 0 && (p->pkt_size || p->window)) {
        if (p->pkt_size)
            fac.pacsize_in = fac.pacsize_out = (unsigned)log2i(p->pkt_size);
        if (p->window)
            fac.winsize_in = fac.winsize_out = (unsigned)p->window;
        if (ioctl(k->fd, SIOCX25SFACILITIES, &fac) < 0) {
            set_error("X.25 facilities (packet %d, window %d): %s",
                      p->pkt_size, p->window, strerror(errno));
            goto fail;
        }
    }
    if (p->cud_len) {
        struct x25_calluserdata cud;
        memset(&cud, 0, sizeof cud);
        cud.cudlength = (unsigned)p->cud_len;
        memcpy(cud.cuddata, p->cud, p->cud_len);
        if (ioctl(k->fd, SIOCX25SCALLUSERDATA, &cud) < 0) {
            set_error("X.25 call user data: %s", strerror(errno));
            goto fail;
        }
    }

    log_msg(LOG_INFO, L, "CALL REQUEST to %s (kernel X.25)", remote.sx25_addr.x25_addr);
    if (connect(k->fd, (struct sockaddr *)&remote, sizeof remote) < 0) {
        /* connect() blocks until the call is accepted or cleared */
        failed(k, "call");
        goto fail;
    }
    if (ioctl(k->fd, SIOCX25GFACILITIES, &fac) == 0)
        log_msg(LOG_INFO, L, "CALL CONNECTED: packet size %u/%u, window %u/%u",
                1u << fac.pacsize_out, 1u << fac.pacsize_in,
                fac.winsize_out, fac.winsize_in);
    return 0;
fail:
    close(k->fd);
    k->fd = -1;
    return -1;
}

int kx25_listen(const char *local)
{
    struct sockaddr_x25 sa;
    int fd = socket(AF_X25, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        set_error("X.25 socket: %s (is the x25 kernel module loaded?)", strerror(errno));
        return -1;
    }
    struct x25_subaddr sub = { .cudmatchlength = 0 };  /* take any CUD */
    if (set_addr(&sa, local) < 0)
        goto fail;
    if (ioctl(fd, SIOCX25SCUDMATCHLEN, &sub) < 0 ||
        bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(fd, 8) < 0) {
        set_error("X.25 listen on %s: %s", local, strerror(errno));
        goto fail;
    }
    return fd;
fail:
    close(fd);
    return -1;
}

int kx25_accept(kx25_conn *k, int lfd, int timeout_ms)
{
    struct sockaddr_x25 peer;
    socklen_t           len = sizeof peer;
    memset(k, 0, sizeof *k);
    k->timeout_ms = timeout_ms;
    k->fd = accept(lfd, (struct sockaddr *)&peer, &len);
    if (k->fd < 0) {
        set_error("X.25 accept: %s", strerror(errno));
        return -1;
    }
    log_msg(LOG_INFO, L, "INCOMING CALL from %s", peer.sx25_addr.x25_addr);
    return 0;
}

static int kx25_send(void *impl, const uint8_t *p, size_t n)
{
    kx25_conn *k = impl;
    if (k->fd < 0) {
        set_error("X.25: call not established");
        return -1;
    }
    /* one message = one NSDU; the kernel splits it into packets (M-bit)
     * and waits for the window */
    for (;;) {
        if (wait_fd(k->fd, POLLOUT, k->timeout_ms) < 0)
            return -1;
        ssize_t w = send(k->fd, p, n, 0);
        if (w == (ssize_t)n)
            return 0;
        if (w < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (w < 0) {
            failed(k, "send");
            return -1;
        }
        set_error("X.25: short send (%zd of %zu)", w, n);
        return -1;
    }
}

static int kx25_recv(void *impl, buf_t *out)
{
    kx25_conn *k = impl;
    if (k->fd < 0) {
        set_error("X.25: call not established");
        return -1;
    }
    if (wait_fd(k->fd, POLLIN, k->timeout_ms) < 0)
        return -1;
    buf_reset(out);
    buf_reserve(out, 65536);
    ssize_t r;
    do {
        r = recv(k->fd, out->data, 65536, MSG_TRUNC);
    } while (r < 0 && errno == EINTR);
    if (r == 0) {
        failed(k, "receive");
        if (!k->clear_cause && !k->clear_diag)
            set_error("X.25: call cleared by peer");
        return -1;
    }
    if (r < 0) {
        failed(k, "receive");
        return -1;
    }
    if (r > 65536) {
        set_error("X.25: NSDU of %zd octets truncated", r);
        return -1;
    }
    out->len = (size_t)r;
    log_hex(LOG_DUMP, L, "recv NSDU", out->data, out->len);
    return 0;
}

void kx25_close(kx25_conn *k)
{
    if (k->fd < 0)
        return;
    /* closing the socket clears the call; DTE originated, no reason */
    struct x25_causediag cd = { 0, 0 };
    ioctl(k->fd, SIOCX25SCAUSEDIAG, &cd);
    log_msg(LOG_INFO, L, "CLEAR REQUEST (kernel X.25)");
    close(k->fd);
    k->fd = -1;
}

int kx25_add_route(const char *prefix, int digits, const char *dev)
{
    struct x25_route_struct rt;
    int fd = socket(AF_X25, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        set_error("X.25 socket: %s", strerror(errno));
        return -1;
    }
    memset(&rt, 0, sizeof rt);
    snprintf(rt.address.x25_addr, sizeof rt.address.x25_addr, "%s", prefix);
    rt.sigdigits = (unsigned)digits;
    snprintf(rt.device, sizeof rt.device, "%s", dev);
    int rc = ioctl(fd, SIOCADDRT, &rt);
    if (rc < 0)
        set_error("X.25 route %s/%d via %s: %s", prefix, digits, dev, strerror(errno));
    close(fd);
    return rc < 0 ? -1 : 0;
}

#else  /* not Linux */

int kx25_supported(void)
{
    return 0;
}

static int unsupported(void)
{
    set_error("kernel X.25 (AF_X25) is only available on Linux");
    return -1;
}

int kx25_connect(kx25_conn *k, const kx25_params *p, int timeout_ms)
{
    (void)p;
    (void)timeout_ms;
    k->fd = -1;
    return unsupported();
}

int kx25_listen(const char *local)
{
    (void)local;
    return unsupported();
}

int kx25_accept(kx25_conn *k, int lfd, int timeout_ms)
{
    (void)lfd;
    (void)timeout_ms;
    k->fd = -1;
    return unsupported();
}

void kx25_close(kx25_conn *k)
{
    (void)k;
}

int kx25_add_route(const char *prefix, int digits, const char *dev)
{
    (void)prefix;
    (void)digits;
    (void)dev;
    return unsupported();
}

static int kx25_send(void *impl, const uint8_t *p, size_t n)
{
    (void)impl;
    (void)p;
    (void)n;
    return unsupported();
}

static int kx25_recv(void *impl, buf_t *out)
{
    (void)impl;
    (void)out;
    return unsupported();
}

#endif

static void kx25_disconnect(void *impl)
{
    kx25_close(impl);
}

static const net_ops kx25_ops = { "kernel X.25", kx25_send, kx25_recv, kx25_disconnect };

net_conn kx25_net(kx25_conn *k)
{
    (void)L;
    return (net_conn){ &kx25_ops, k };
}
