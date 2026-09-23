/*
 * util.c - growable buffers, logging, error reporting, small parsers.
 */
#include "util.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int log_level = LOG_ERROR;

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) {
        fprintf(stderr, "out of memory\n");
        abort();
    }
    return p;
}

void *xrealloc(void *p, size_t n)
{
    p = realloc(p, n ? n : 1);
    if (!p) {
        fprintf(stderr, "out of memory\n");
        abort();
    }
    return p;
}

void buf_init(buf_t *b)
{
    b->data = NULL;
    b->len = b->cap = 0;
}

void buf_free(buf_t *b)
{
    free(b->data);
    buf_init(b);
}

void buf_reset(buf_t *b)
{
    b->len = 0;
}

void buf_reserve(buf_t *b, size_t extra)
{
    if (b->len + extra <= b->cap)
        return;
    size_t ncap = b->cap ? b->cap : 256;
    while (ncap < b->len + extra)
        ncap *= 2;
    b->data = xrealloc(b->data, ncap);
    b->cap = ncap;
}

void buf_put(buf_t *b, const void *p, size_t n)
{
    if (!n)
        return;
    buf_reserve(b, n);
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

void buf_put8(buf_t *b, uint8_t v)
{
    buf_put(b, &v, 1);
}

void buf_put16(buf_t *b, uint16_t v)
{
    uint8_t t[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    buf_put(b, t, 2);
}

void buf_insert(buf_t *b, size_t pos, const void *p, size_t n)
{
    buf_reserve(b, n);
    memmove(b->data + pos + n, b->data + pos, b->len - pos);
    memcpy(b->data + pos, p, n);
    b->len += n;
}

void buf_consume(buf_t *b, size_t n)
{
    if (n >= b->len) {
        b->len = 0;
        return;
    }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
}

void log_msg(int level, const char *layer, const char *fmt, ...)
{
    if (level > log_level)
        return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[%-4s] ", layer);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

void log_hex(int level, const char *layer, const char *what,
             const uint8_t *p, size_t n)
{
    if (level > log_level)
        return;
    fprintf(stderr, "[%-4s] %s (%zu bytes)\n", layer, what, n);
    for (size_t i = 0; i < n; i += 16) {
        fprintf(stderr, "       %04zx ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < n)
                fprintf(stderr, " %02x", p[i + j]);
            else
                fputs("   ", stderr);
        }
        fputs("  ", stderr);
        for (size_t j = 0; j < 16 && i + j < n; j++)
            fputc(isprint(p[i + j]) ? p[i + j] : '.', stderr);
        fputc('\n', stderr);
    }
}

static char last_error[512];

void set_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(last_error, sizeof last_error, fmt, ap);
    va_end(ap);
    log_msg(LOG_DEBUG, "err", "%s", last_error);
}

const char *get_error(void)
{
    return last_error[0] ? last_error : "unknown error";
}

int parse_hex(const char *s, uint8_t *out, size_t max)
{
    size_t n = 0;
    int hi = -1;

    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    for (; *s; s++) {
        int v;
        if (*s == ' ' || *s == ':' || *s == '.' || *s == '-')
            continue;
        if (*s >= '0' && *s <= '9')
            v = *s - '0';
        else if (*s >= 'a' && *s <= 'f')
            v = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F')
            v = *s - 'A' + 10;
        else
            return -1;
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= max)
                return -1;
            out[n++] = (uint8_t)(hi << 4 | v);
            hi = -1;
        }
    }
    return hi < 0 ? (int)n : -1;
}

int parse_selector(const char *s, uint8_t *out, size_t max)
{
    if (!s)
        return 0;
    if ((s[0] == '0' && (s[1] == 'x' || s[1] == 'X')))
        return parse_hex(s, out, max);
    if (strncmp(s, "hex:", 4) == 0)
        return parse_hex(s + 4, out, max);
    size_t n = strlen(s);
    if (n > max)
        return -1;
    memcpy(out, s, n);
    return (int)n;
}
