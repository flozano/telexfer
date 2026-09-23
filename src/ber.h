/*
 * ber.h - minimal ASN.1 BER encoder/decoder (X.690).
 *
 * Tags are represented as a single uint32_t: the identifier octet's class
 * and constructed bits in the top byte, the tag number in the low bits.
 * Encoder and decoder use the same representation, so decoded tags can be
 * compared directly against the T_* macros.
 */
#ifndef FTAM_BER_H
#define FTAM_BER_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

#define BER_TAG(cls, n)  (((uint32_t)(cls) << 24) | (uint32_t)(n))
#define T_UNIV(n)        BER_TAG(0x00, n)
#define T_UNIVC(n)       BER_TAG(0x20, n)
#define T_APP(n)         BER_TAG(0x40, n)
#define T_APPC(n)        BER_TAG(0x60, n)
#define T_CTX(n)         BER_TAG(0x80, n)
#define T_CTXC(n)        BER_TAG(0xA0, n)
#define T_TAGNUM(t)      ((t) & 0x00ffffffu)
#define T_CONSTRUCTED(t) (((t) >> 24) & 0x20)
#define T_CLASS(t)       (((t) >> 24) & 0xc0)

#define T_BOOL           T_UNIV(1)
#define T_INT            T_UNIV(2)
#define T_BITS           T_UNIV(3)
#define T_OCTETS         T_UNIV(4)
#define T_NULL           T_UNIV(5)
#define T_OID            T_UNIV(6)
#define T_EXTERNAL       T_UNIVC(8)
#define T_ENUM           T_UNIV(10)
#define T_SEQ            T_UNIVC(16)
#define T_SET            T_UNIVC(17)
#define T_PRINTABLE      T_UNIV(19)
#define T_IA5            T_UNIV(22)
#define T_GENTIME        T_UNIV(24)
#define T_GRAPHIC        T_UNIV(25)
#define T_VISIBLE        T_UNIV(26)
#define T_GENERAL        T_UNIV(27)

/* ---- encoder ----------------------------------------------------------- */

#define BER_MAX_DEPTH 32

typedef struct {
    buf_t  *b;
    size_t  stack[BER_MAX_DEPTH];     /* content start offsets */
    int     depth;
} ber_enc;

void ber_enc_init(ber_enc *e, buf_t *b);
void ber_begin(ber_enc *e, uint32_t tag);          /* open constructed */
void ber_end(ber_enc *e);                          /* close constructed */
void ber_prim(ber_enc *e, uint32_t tag, const void *p, size_t n);
void ber_int(ber_enc *e, uint32_t tag, long v);
void ber_bool(ber_enc *e, uint32_t tag, int v);
void ber_null(ber_enc *e, uint32_t tag);
void ber_str(ber_enc *e, uint32_t tag, const char *s);
/* Named-bit BIT STRING: bit i of mask -> named bit i. Trailing 0s trimmed. */
void ber_bits(ber_enc *e, uint32_t tag, uint32_t mask);
/* OBJECT IDENTIFIER from dotted notation; returns -1 on malformed input. */
int  ber_oid(ber_enc *e, uint32_t tag, const char *dotted);
/* Append pre-encoded TLV(s) verbatim. */
void ber_raw(ber_enc *e, const void *p, size_t n);

/* ---- decoder ----------------------------------------------------------- */

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} ber_rd;

typedef struct {
    uint32_t       tag;
    const uint8_t *v;        /* contents */
    size_t         len;      /* contents length (EOC excluded) */
    const uint8_t *raw;      /* start of identifier octets */
    size_t         rawlen;   /* whole TLV length incl. EOC if indefinite */
} ber_tlv;

void ber_rd_init(ber_rd *r, const uint8_t *p, size_t n);
/* 1 = got a TLV, 0 = end of input (or EOC), -1 = malformed */
int  ber_next(ber_rd *r, ber_tlv *t);
/* Reader over a constructed TLV's contents. */
void ber_enter(const ber_tlv *t, ber_rd *r);
/* Find first child of constructed TLV with given tag; 1 found, 0 not. */
int  ber_find(const ber_tlv *parent, uint32_t tag, ber_tlv *out);

int  ber_get_int(const ber_tlv *t, long *v);
int  ber_get_bool(const ber_tlv *t, int *v);
int  ber_get_bits(const ber_tlv *t, uint32_t *mask);
int  ber_get_oid(const ber_tlv *t, char *out, size_t max);
/* Contents of a (possibly constructed/segmented) string type, appended. */
int  ber_get_string(const ber_tlv *t, buf_t *out);
/* Same, into a NUL-terminated C string (truncates). */
int  ber_get_cstr(const ber_tlv *t, char *out, size_t max);
/* Contents of a (possibly constructed) BIT STRING, appended to out;
 * *unused gets the number of unused bits in the final octet.  Only the
 * last segment of a constructed encoding may have unused bits. */
int  ber_get_bitstring(const ber_tlv *t, buf_t *out, int *unused);

/* Compare an encoded OID TLV against dotted notation. */
int  ber_oid_eq(const ber_tlv *t, const char *dotted);

#endif
