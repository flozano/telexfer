/*
 * rfc1006.c - TPKT framing of TPDUs over TCP (RFC 1006).
 */
#include "rfc1006.h"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tcp.h"

static const char *L = "tpkt";

void tpkt_init(tpkt_conn *t, int fd, int timeout_ms, trace_t *trace)
{
    t->fd = fd;
    t->timeout_ms = timeout_ms;
    t->trace = trace;
    tcp_tune(fd);
}

int tpkt_send(tpkt_conn *t, const uint8_t *p, size_t n)
{
    if (t->fd < 0) {
        set_error("RFC 1006: connection closed");
        return -1;
    }
    if (n > TPKT_MAX_TPDU) {
        set_error("RFC 1006: TPDU of %zu octets does not fit a TPKT", n);
        return -1;
    }
    size_t       total = n + 4;
    uint8_t      hdr[4] = { TPKT_VERSION, 0, (uint8_t)(total >> 8), (uint8_t)total };
    struct iovec iov[2] = { { hdr, 4 }, { (void *)p, n } };

    log_hex(LOG_DUMP, L, "send TPKT", p, n);
    if (t->trace) {
        buf_t b;
        buf_init(&b);
        buf_put(&b, hdr, 4);
        buf_put(&b, p, n);
        trace_write(t->trace, 1, b.data, b.len);
        buf_free(&b);
    }
    return tcp_write_all(t->fd, iov, 2);
}

int tpkt_recv(tpkt_conn *t, buf_t *out)
{
    uint8_t hdr[4];
    long    deadline = tcp_now_ms() + t->timeout_ms;

    if (t->fd < 0) {
        set_error("RFC 1006: connection closed");
        return -1;
    }
    if (tcp_read_full(t->fd, hdr, 4, deadline) < 0)
        return -1;
    size_t total = (size_t)(hdr[2] << 8 | hdr[3]);
    if (hdr[0] != TPKT_VERSION || total < 4 + 2) {
        set_error("RFC 1006: bad TPKT header %02x %02x, length %zu",
                  hdr[0], hdr[1], total);
        return -1;
    }
    buf_reset(out);
    buf_reserve(out, total - 4);
    if (tcp_read_full(t->fd, out->data, total - 4, deadline) < 0)
        return -1;
    out->len = total - 4;
    log_hex(LOG_DUMP, L, "recv TPKT", out->data, out->len);
    if (t->trace) {
        buf_t b;
        buf_init(&b);
        buf_put(&b, hdr, 4);
        buf_put(&b, out->data, out->len);
        trace_write(t->trace, 0, b.data, b.len);
        buf_free(&b);
    }
    return 0;
}

void tpkt_close(tpkt_conn *t)
{
    if (t->fd < 0)
        return;
    log_msg(LOG_INFO, L, "closing TCP connection");
    /* half-close first, so the last TPDU sent is not lost to an RST */
    shutdown(t->fd, SHUT_WR);
    close(t->fd);
    t->fd = -1;
}

static int net_send(void *impl, const uint8_t *p, size_t n)
{
    return tpkt_send(impl, p, n);
}

static int net_recv(void *impl, buf_t *out)
{
    return tpkt_recv(impl, out);
}

static void net_disconnect(void *impl)
{
    tpkt_close(impl);
}

static const net_ops tpkt_ops = { "RFC 1006", net_send, net_recv, net_disconnect };

net_conn tpkt_net(tpkt_conn *t)
{
    return (net_conn){ &tpkt_ops, t };
}
