/*
 * ber.c - minimal ASN.1 BER encoder/decoder (X.690).
 *
 * The encoder always produces definite lengths.  The decoder accepts
 * both definite and indefinite lengths; for indefinite-length TLVs the
 * reported contents exclude the end-of-contents octets, so callers never
 * need to care which form the peer used.
 */
#include "ber.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- encoder ----------------------------------------------------------- */

static void put_tag(buf_t *b, uint32_t tag)
{
    uint8_t  cls = (uint8_t)(tag >> 24);
    uint32_t n = T_TAGNUM(tag);

    if (n < 31) {
        buf_put8(b, (uint8_t)(cls | n));
        return;
    }
    buf_put8(b, (uint8_t)(cls | 0x1f));
    uint8_t tmp[5];
    int     k = 0;
    do {
        tmp[k++] = n & 0x7f;
        n >>= 7;
    } while (n);
    while (k-- > 0)
        buf_put8(b, (uint8_t)(tmp[k] | (k ? 0x80 : 0)));
}

static size_t len_octets(size_t len, uint8_t out[9])
{
    if (len < 0x80) {
        out[0] = (uint8_t)len;
        return 1;
    }
    int k = 0;
    uint8_t tmp[8];
    while (len) {
        tmp[k++] = (uint8_t)len;
        len >>= 8;
    }
    out[0] = (uint8_t)(0x80 | k);
    for (int i = 0; i < k; i++)
        out[1 + i] = tmp[k - 1 - i];
    return (size_t)k + 1;
}

void ber_enc_init(ber_enc *e, buf_t *b)
{
    e->b = b;
    e->depth = 0;
}

void ber_begin(ber_enc *e, uint32_t tag)
{
    if (e->depth >= BER_MAX_DEPTH) {
        fprintf(stderr, "ber: nesting too deep\n");
        abort();
    }
    put_tag(e->b, tag | BER_TAG(0x20, 0));
    e->stack[e->depth++] = e->b->len;
}

void ber_end(ber_enc *e)
{
    if (e->depth <= 0) {
        fprintf(stderr, "ber: unbalanced ber_end\n");
        abort();
    }
    size_t  start = e->stack[--e->depth];
    uint8_t lo[9];
    size_t  ln = len_octets(e->b->len - start, lo);
    buf_insert(e->b, start, lo, ln);
}

void ber_prim(ber_enc *e, uint32_t tag, const void *p, size_t n)
{
    uint8_t lo[9];
    put_tag(e->b, tag);
    buf_put(e->b, lo, len_octets(n, lo));
    buf_put(e->b, p, n);
}

void ber_int(ber_enc *e, uint32_t tag, long v)
{
    uint8_t tmp[sizeof(long) + 1];
    int     n = 0;
    /* two's complement, minimal octets */
    for (int i = (int)sizeof(long) - 1; i >= 0; i--)
        tmp[n++] = (uint8_t)((unsigned long)v >> (i * 8));
    int s = 0;
    while (s < n - 1 &&
           ((tmp[s] == 0x00 && !(tmp[s + 1] & 0x80)) ||
            (tmp[s] == 0xff && (tmp[s + 1] & 0x80))))
        s++;
    ber_prim(e, tag, tmp + s, (size_t)(n - s));
}

void ber_bool(ber_enc *e, uint32_t tag, int v)
{
    uint8_t b = v ? 0xff : 0x00;
    ber_prim(e, tag, &b, 1);
}

void ber_null(ber_enc *e, uint32_t tag)
{
    ber_prim(e, tag, NULL, 0);
}

void ber_str(ber_enc *e, uint32_t tag, const char *s)
{
    ber_prim(e, tag, s, strlen(s));
}

void ber_bits(ber_enc *e, uint32_t tag, uint32_t mask)
{
    uint8_t tmp[5] = { 0 };
    int     hi = -1;
    for (int i = 31; i >= 0; i--)
        if (mask & (1u << i)) {
            hi = i;
            break;
        }
    if (hi < 0) {
        ber_prim(e, tag, tmp, 1);   /* empty bit string */
        return;
    }
    int nbits = hi + 1;
    int nbytes = (nbits + 7) / 8;
    tmp[0] = (uint8_t)(nbytes * 8 - nbits);
    for (int i = 0; i < nbits; i++)
        if (mask & (1u << i))
            tmp[1 + i / 8] |= (uint8_t)(0x80 >> (i % 8));
    ber_prim(e, tag, tmp, (size_t)nbytes + 1);
}

int ber_oid(ber_enc *e, uint32_t tag, const char *dotted)
{
    unsigned long arcs[64];
    int           n = 0;
    const char   *s = dotted;

    while (*s && n < 64) {
        char *endp;
        arcs[n++] = strtoul(s, &endp, 10);
        if (endp == s)
            return -1;
        s = endp;
        if (*s == '.')
            s++;
        else if (*s)
            return -1;
    }
    if (n < 2)
        return -1;

    uint8_t out[256];
    size_t  k = 0;
    for (int i = 1; i < n; i++) {
        unsigned long v = (i == 1) ? arcs[0] * 40 + arcs[1] : arcs[i];
        uint8_t       tmp[10];
        int           m = 0;
        do {
            tmp[m++] = v & 0x7f;
            v >>= 7;
        } while (v);
        while (m-- > 0) {
            if (k >= sizeof out)
                return -1;
            out[k++] = (uint8_t)(tmp[m] | (m ? 0x80 : 0));
        }
    }
    ber_prim(e, tag, out, k);
    return 0;
}

void ber_raw(ber_enc *e, const void *p, size_t n)
{
    buf_put(e->b, p, n);
}

/* ---- decoder ----------------------------------------------------------- */

void ber_rd_init(ber_rd *r, const uint8_t *p, size_t n)
{
    r->p = p;
    r->end = p + n;
}

/*
 * Parse identifier and length at p.  On success fills tag, header length,
 * and either the definite length (*len, *indef = 0) or *indef = 1.
 */
static int parse_header(const uint8_t *p, const uint8_t *end, uint32_t *tag,
                        size_t *hlen, size_t *len, int *indef)
{
    const uint8_t *q = p;

    if (q >= end)
        return -1;
    uint8_t  id = *q++;
    uint32_t n = id & 0x1f;
    if (n == 0x1f) {
        n = 0;
        for (int i = 0;; i++) {
            if (q >= end || i > 4)
                return -1;
            uint8_t c = *q++;
            n = (n << 7) | (c & 0x7f);
            if (!(c & 0x80))
                break;
        }
    }
    *tag = BER_TAG(id & 0xe0, n);

    if (q >= end)
        return -1;
    uint8_t l0 = *q++;
    *indef = 0;
    if (l0 < 0x80) {
        *len = l0;
    } else if (l0 == 0x80) {
        if (!(id & 0x20))
            return -1;
        *indef = 1;
        *len = 0;
    } else {
        int k = l0 & 0x7f;
        if (k > (int)sizeof(size_t) || q + k > end)
            return -1;
        size_t v = 0;
        while (k--)
            v = (v << 8) | *q++;
        *len = v;
    }
    *hlen = (size_t)(q - p);
    if (!*indef && *len > (size_t)(end - q))
        return -1;
    return 0;
}

/* Return pointer just past the TLV at p (handles nested indefinite). */
static const uint8_t *skip_tlv(const uint8_t *p, const uint8_t *end, int depth)
{
    uint32_t tag;
    size_t   hlen, len;
    int      indef;

    if (depth > 64 || parse_header(p, end, &tag, &hlen, &len, &indef) < 0)
        return NULL;
    p += hlen;
    if (!indef)
        return p + len;
    for (;;) {
        if (p + 2 > end)
            return NULL;
        if (p[0] == 0 && p[1] == 0)
            return p + 2;
        p = skip_tlv(p, end, depth + 1);
        if (!p)
            return NULL;
    }
}

int ber_next(ber_rd *r, ber_tlv *t)
{
    uint32_t tag;
    size_t   hlen, len;
    int      indef;

    if (r->p >= r->end)
        return 0;
    if (r->end - r->p >= 2 && r->p[0] == 0 && r->p[1] == 0)
        return 0;                               /* stray EOC */
    if (parse_header(r->p, r->end, &tag, &hlen, &len, &indef) < 0)
        return -1;
    t->tag = tag;
    t->raw = r->p;
    t->v = r->p + hlen;
    if (indef) {
        const uint8_t *after = skip_tlv(r->p, r->end, 0);
        if (!after)
            return -1;
        t->len = (size_t)(after - 2 - t->v);
        t->rawlen = (size_t)(after - r->p);
    } else {
        t->len = len;
        t->rawlen = hlen + len;
    }
    r->p = t->raw + t->rawlen;
    return 1;
}

void ber_enter(const ber_tlv *t, ber_rd *r)
{
    ber_rd_init(r, t->v, t->len);
}

int ber_find(const ber_tlv *parent, uint32_t tag, ber_tlv *out)
{
    ber_rd  r;
    ber_tlv c;
    ber_enter(parent, &r);
    while (ber_next(&r, &c) > 0)
        if (c.tag == tag) {
            *out = c;
            return 1;
        }
    return 0;
}

int ber_get_int(const ber_tlv *t, long *v)
{
    if (t->len == 0 || t->len > sizeof(long))
        return -1;
    long x = (t->v[0] & 0x80) ? -1 : 0;
    for (size_t i = 0; i < t->len; i++)
        x = (long)(((unsigned long)x << 8) | t->v[i]);
    *v = x;
    return 0;
}

int ber_get_bool(const ber_tlv *t, int *v)
{
    if (t->len != 1)
        return -1;
    *v = t->v[0] != 0;
    return 0;
}

int ber_get_bits(const ber_tlv *t, uint32_t *mask)
{
    *mask = 0;
    if (t->len == 0)
        return -1;
    size_t nbits = (t->len - 1) * 8;
    if (nbits >= t->v[0])
        nbits -= t->v[0];
    for (size_t i = 0; i < nbits && i < 32; i++)
        if (t->v[1 + i / 8] & (0x80 >> (i % 8)))
            *mask |= 1u << i;
    return 0;
}

int ber_get_oid(const ber_tlv *t, char *out, size_t max)
{
    size_t        pos = 0;
    unsigned long v = 0;
    int           first = 1;

    if (max == 0)
        return -1;
    out[0] = 0;
    for (size_t i = 0; i < t->len; i++) {
        v = (v << 7) | (t->v[i] & 0x7f);
        if (t->v[i] & 0x80)
            continue;
        int w;
        if (first) {
            unsigned long a = v < 80 ? v / 40 : 2;
            w = snprintf(out + pos, max - pos, "%lu.%lu", a, v - a * 40);
            first = 0;
        } else {
            w = snprintf(out + pos, max - pos, ".%lu", v);
        }
        if (w < 0 || (size_t)w >= max - pos)
            return -1;
        pos += (size_t)w;
        v = 0;
    }
    return 0;
}

int ber_oid_eq(const ber_tlv *t, const char *dotted)
{
    char s[256];
    return ber_get_oid(t, s, sizeof s) == 0 && strcmp(s, dotted) == 0;
}

int ber_get_string(const ber_tlv *t, buf_t *out)
{
    if (!T_CONSTRUCTED(t->tag)) {
        buf_put(out, t->v, t->len);
        return 0;
    }
    ber_rd  r;
    ber_tlv c;
    int     rc;
    ber_enter(t, &r);
    while ((rc = ber_next(&r, &c)) > 0)
        if (ber_get_string(&c, out) < 0)
            return -1;
    return rc;
}

static int bitstring_seg(const ber_tlv *t, buf_t *out, int *unused, int depth)
{
    if (depth > 16)
        return -1;
    if (!T_CONSTRUCTED(t->tag)) {
        if (t->len == 0 || t->v[0] > 7 || (t->len == 1 && t->v[0] != 0))
            return -1;
        if (*unused)                    /* bits missing in a middle segment */
            return -1;
        buf_put(out, t->v + 1, t->len - 1);
        *unused = t->v[0];
        return 0;
    }
    ber_rd  r;
    ber_tlv c;
    int     rc;
    ber_enter(t, &r);
    while ((rc = ber_next(&r, &c)) > 0)
        if (bitstring_seg(&c, out, unused, depth + 1) < 0)
            return -1;
    return rc;
}

int ber_get_bitstring(const ber_tlv *t, buf_t *out, int *unused)
{
    *unused = 0;
    return bitstring_seg(t, out, unused, 0);
}

int ber_get_cstr(const ber_tlv *t, char *out, size_t max)
{
    buf_t b;
    buf_init(&b);
    int rc = ber_get_string(t, &b);
    size_t n = b.len < max - 1 ? b.len : max - 1;
    if (n)
        memcpy(out, b.data, n);
    out[n] = 0;
    buf_free(&b);
    return rc;
}
