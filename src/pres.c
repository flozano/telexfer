/*
 * pres.c - presentation PPDUs (X.226) and ACSE APDUs (X.227).
 */
#include "pres.h"

#include <string.h>

/* ---- presentation user data -------------------------------------------- */

void pres_ud_begin(ber_enc *e, buf_t *out)
{
    ber_enc_init(e, out);
    ber_begin(e, T_APPC(1));                    /* fully-encoded-data */
}

void pres_ud_pdv(ber_enc *e, int ctx, const uint8_t *val, size_t len)
{
    ber_begin(e, T_SEQ);                        /* PDV-list */
    ber_int(e, T_INT, ctx);
    ber_begin(e, T_CTXC(0));                    /* single-ASN1-type */
    ber_raw(e, val, len);
    ber_end(e);
    ber_end(e);
}

static size_t segment_size = PRES_OCTET_SEGMENT;

void pres_set_segment(size_t n)
{
    segment_size = n ? n : PRES_OCTET_SEGMENT;
}

/*
 * [tagnum] IMPLICIT OCTET STRING or BIT STRING holding encoded values:
 * primitive up to the segment size, constructed (segmented) beyond.
 * BIT STRING contents are always octet-integral (unused bits = 0).
 */
static void enc_segmented(ber_enc *e, unsigned tagnum, int bits,
                          const uint8_t *vals, size_t len)
{
    buf_t tmp;
    buf_init(&tmp);
    if (len <= segment_size) {
        if (bits) {
            buf_put8(&tmp, 0);
            buf_put(&tmp, vals, len);
            ber_prim(e, T_CTX(tagnum), tmp.data, tmp.len);
        } else {
            ber_prim(e, T_CTX(tagnum), vals, len);
        }
    } else {
        ber_begin(e, T_CTXC(tagnum));
        for (size_t off = 0; off < len; off += segment_size) {
            size_t n = len - off < segment_size ? len - off : segment_size;
            if (bits) {
                buf_reset(&tmp);
                buf_put8(&tmp, 0);
                buf_put(&tmp, vals + off, n);
                ber_prim(e, T_BITS, tmp.data, tmp.len);
            } else {
                ber_prim(e, T_OCTETS, vals + off, n);
            }
        }
        ber_end(e);
    }
    buf_free(&tmp);
}

void pres_ud_pdv_enc(ber_enc *e, int ctx, int mode, const uint8_t *vals, size_t len)
{
    if (mode == PDV_SINGLE) {
        pres_ud_pdv(e, ctx, vals, len);
        return;
    }
    ber_begin(e, T_SEQ);                        /* PDV-list */
    ber_int(e, T_INT, ctx);
    enc_segmented(e, mode == PDV_ARBITRARY ? 2 : 1, mode == PDV_ARBITRARY, vals, len);
    ber_end(e);
}

void pres_ud_pdv_octets(ber_enc *e, int ctx, const uint8_t *vals, size_t len)
{
    pres_ud_pdv_enc(e, ctx, PDV_OCTET, vals, len);
}

/*
 * Encoded values carried as octet-aligned ([1]) or arbitrary ([2]) in a
 * PDV-list or an EXTERNAL: joins segments into tmp and points r at the
 * concatenated encodings.  Returns -1 if the TLV is neither or malformed.
 */
static int encoded_values(const ber_tlv *c, buf_t *tmp, ber_rd *r)
{
    if (c->tag == T_CTX(1)) {
        ber_rd_init(r, c->v, c->len);
        return 0;
    }
    if (c->tag == T_CTXC(1)) {
        if (ber_get_string(c, tmp) < 0) {
            set_error("presentation: malformed segmented octet-aligned value");
            return -1;
        }
        ber_rd_init(r, tmp->data, tmp->len);
        return 0;
    }
    if (c->tag == T_CTX(2) || c->tag == T_CTXC(2)) {
        int unused;
        if (ber_get_bitstring(c, tmp, &unused) < 0) {
            set_error("presentation: malformed arbitrary (BIT STRING) value");
            return -1;
        }
        if (unused) {
            set_error("presentation: arbitrary value is not a whole number of "
                      "octets, cannot hold BER encodings");
            return -1;
        }
        ber_rd_init(r, tmp->data, tmp->len);
        return 0;
    }
    set_error("presentation: unknown presentation-data-values choice");
    return -1;
}

void pres_ud_end(ber_enc *e)
{
    ber_end(e);
}

void pres_user_data(buf_t *out, int ctx, const uint8_t *val, size_t len)
{
    ber_enc e;
    pres_ud_begin(&e, out);
    pres_ud_pdv(&e, ctx, val, len);
    pres_ud_end(&e);
}

static int parse_pdv_list(const ber_tlv *pdv, pdv_cb cb, void *arg)
{
    ber_rd  r;
    ber_tlv c;
    long    ctx = -1;
    int     rc;

    ber_enter(pdv, &r);
    while ((rc = ber_next(&r, &c)) > 0) {
        if (c.tag == T_OID)                     /* transfer-syntax-name */
            continue;
        if (c.tag == T_INT) {
            ber_get_int(&c, &ctx);
            continue;
        }
        if (c.tag == T_CTXC(0) || T_TAGNUM(c.tag) == 1 || T_TAGNUM(c.tag) == 2) {
            /* single-ASN1-type: exactly one value; octet-aligned and
             * arbitrary: the encoding of one or more values (we accept
             * several), possibly segmented.  Segmented values only live
             * until the callbacks have run. */
            ber_rd  vr;
            ber_tlv v;
            int     vrc;
            buf_t   tmp;
            buf_init(&tmp);
            if (c.tag == T_CTXC(0)) {
                ber_enter(&c, &vr);
            } else if (T_CLASS(c.tag) != 0x80) {
                continue;                       /* not ours to interpret */
            } else if (encoded_values(&c, &tmp, &vr) < 0) {
                buf_free(&tmp);
                return -1;
            }
            while ((vrc = ber_next(&vr, &v)) > 0) {
                int crc = cb(arg, (int)ctx, &v);
                if (crc < 0) {
                    buf_free(&tmp);
                    return crc;
                }
            }
            buf_free(&tmp);
            if (vrc < 0) {
                set_error("presentation: malformed value in PDV");
                return -1;
            }
            continue;
        }
    }
    return rc;
}

int pres_parse_ud(const uint8_t *p, size_t n, pdv_cb cb, void *arg)
{
    ber_rd  r;
    ber_tlv ud, pdv;
    int     rc;

    ber_rd_init(&r, p, n);
    if (ber_next(&r, &ud) <= 0) {
        set_error("presentation: malformed user data");
        return -1;
    }
    if (ud.tag == T_APP(0) || ud.tag == T_APPC(0)) {
        set_error("presentation: simply-encoded-data not supported");
        return -1;
    }
    if (ud.tag != T_APPC(1)) {
        set_error("presentation: unexpected user data tag");
        return -1;
    }
    ber_enter(&ud, &r);
    while ((rc = ber_next(&r, &pdv)) > 0) {
        if (pdv.tag != T_SEQ)
            continue;
        int prc = parse_pdv_list(&pdv, cb, arg);
        if (prc < 0)
            return prc;
    }
    if (rc < 0)
        set_error("presentation: malformed PDV-list");
    return rc;
}

/* Copy the first presentation data value (the ACSE APDU) into hold. */
static int first_cb(void *arg, int ctx, const ber_tlv *v)
{
    buf_t *hold = arg;
    (void)ctx;
    if (hold->len == 0)
        buf_put(hold, v->raw, v->rawlen);
    return 0;
}

static int ud_first(const ber_tlv *ud, buf_t *hold, ber_tlv *apdu, int *has)
{
    ber_rd r;
    *has = 0;
    buf_reset(hold);
    if (pres_parse_ud(ud->raw, ud->rawlen, first_cb, hold) < 0)
        return -1;
    ber_rd_init(&r, hold->data, hold->len);
    if (hold->len && ber_next(&r, apdu) > 0)
        *has = 1;
    return 0;
}

/* ---- connection PPDUs -------------------------------------------------- */

void pres_build_cp(buf_t *out,
                   const uint8_t *calling, size_t calling_len,
                   const uint8_t *called, size_t called_len,
                   const pctx_t *ctx, int nctx,
                   int acse_ctx, const uint8_t *apdu, size_t apdu_len)
{
    ber_enc e;
    ber_enc_init(&e, out);
    ber_begin(&e, T_SET);                       /* CP-type */
    ber_begin(&e, T_CTXC(0));                   /* mode-selector */
    ber_int(&e, T_CTX(0), 1);                   /* normal-mode */
    ber_end(&e);
    ber_begin(&e, T_CTXC(2));                   /* normal-mode-parameters */
    ber_bits(&e, T_CTX(0), 0x1);                /* protocol-version: version-1 */
    if (calling_len)
        ber_prim(&e, T_CTX(1), calling, calling_len);
    if (called_len)
        ber_prim(&e, T_CTX(2), called, called_len);
    ber_begin(&e, T_CTXC(4));                   /* context definition list */
    for (int i = 0; i < nctx; i++) {
        ber_begin(&e, T_SEQ);
        ber_int(&e, T_INT, ctx[i].id);
        ber_oid(&e, T_OID, ctx[i].abstract);
        ber_begin(&e, T_SEQ);
        ber_oid(&e, T_OID, OID_BER);
        ber_end(&e);
        ber_end(&e);
    }
    ber_end(&e);
    ber_bits(&e, T_CTX(9), 0x2);                /* user-session-req: duplex */
    {
        buf_t ud;
        buf_init(&ud);
        pres_user_data(&ud, acse_ctx, apdu, apdu_len);
        ber_raw(&e, ud.data, ud.len);
        buf_free(&ud);
    }
    ber_end(&e);
    ber_end(&e);
}

int pres_parse_cpa(const uint8_t *p, size_t n, pctx_t *ctx, int nctx,
                   buf_t *hold, ber_tlv *apdu, int *has_apdu)
{
    ber_rd  r;
    ber_tlv cpa, nm, c;
    int     rc;

    *has_apdu = 0;
    ber_rd_init(&r, p, n);
    if (ber_next(&r, &cpa) <= 0 || cpa.tag != T_SET) {
        set_error("presentation: malformed CPA-PPDU");
        return -1;
    }
    if (!ber_find(&cpa, T_CTXC(2), &nm)) {
        set_error("presentation: CPA-PPDU without normal-mode parameters");
        return -1;
    }
    for (int i = 0; i < nctx; i++)
        ctx[i].result = -1;
    ber_enter(&nm, &r);
    while ((rc = ber_next(&r, &c)) > 0) {
        if (c.tag == T_CTXC(5)) {
            ber_rd  lr;
            ber_tlv item;
            int     i = 0;
            ber_enter(&c, &lr);
            while (ber_next(&lr, &item) > 0 && i < nctx) {
                ber_tlv res;
                long    v = -1;
                if (ber_find(&item, T_CTX(0), &res))
                    ber_get_int(&res, &v);
                ctx[i++].result = (int)v;
            }
        } else if (c.tag == T_APPC(1)) {
            if (ud_first(&c, hold, apdu, has_apdu) < 0)
                return -1;
        }
    }
    return rc < 0 ? -1 : 0;
}

int pres_parse_cpr(const uint8_t *p, size_t n, int *reason,
                   buf_t *hold, ber_tlv *apdu, int *has_apdu)
{
    ber_rd  r;
    ber_tlv cpr, c;

    *has_apdu = 0;
    *reason = -1;
    ber_rd_init(&r, p, n);
    if (ber_next(&r, &cpr) <= 0) {
        set_error("presentation: malformed CPR-PPDU");
        return -1;
    }
    if (cpr.tag != T_SEQ)                       /* x400 mode: nothing to see */
        return 0;
    ber_enter(&cpr, &r);
    while (ber_next(&r, &c) > 0) {
        long v;
        if (c.tag == T_CTX(10) && ber_get_int(&c, &v) == 0)
            *reason = (int)v;
        else if (c.tag == T_APPC(1))
            ud_first(&c, hold, apdu, has_apdu);
    }
    return 0;
}

void pres_build_aru(buf_t *out, int acse_ctx, const uint8_t *apdu, size_t len)
{
    ber_enc e;
    buf_t   ud;
    buf_init(&ud);
    pres_user_data(&ud, acse_ctx, apdu, len);
    ber_enc_init(&e, out);
    ber_begin(&e, T_CTXC(0));                   /* normal-mode-parameters */
    ber_raw(&e, ud.data, ud.len);
    ber_end(&e);
    buf_free(&ud);
}

int pres_parse_abort(const uint8_t *p, size_t n, int *provider_reason,
                     buf_t *hold, ber_tlv *apdu, int *has_apdu)
{
    ber_rd  r;
    ber_tlv a, c;

    *has_apdu = 0;
    *provider_reason = -1;
    if (n == 0)
        return 0;
    ber_rd_init(&r, p, n);
    if (ber_next(&r, &a) <= 0)
        return -1;
    if (a.tag == T_CTXC(0)) {                   /* ARU normal mode */
        if (ber_find(&a, T_APPC(1), &c))
            return ud_first(&c, hold, apdu, has_apdu);
        return 0;
    }
    if (a.tag == T_SEQ) {                       /* ARP */
        long v = 0;
        if (ber_find(&a, T_CTX(0), &c))
            ber_get_int(&c, &v);
        *provider_reason = (int)v;
        return 0;
    }
    return 0;
}

const char *pres_provider_reason(int r)
{
    switch (r) {
    case 0: return "reason not specified";
    case 1: return "temporary congestion";
    case 2: return "local limit exceeded";
    case 3: return "called presentation address unknown";
    case 4: return "protocol version not supported";
    case 5: return "default context not supported";
    case 6: return "user data not readable";
    case 7: return "no PSAP available";
    default: return "unknown";
    }
}

const char *pres_abort_reason(int r)
{
    switch (r) {
    case 0: return "reason not specified";
    case 1: return "unrecognized PPDU";
    case 2: return "unexpected PPDU";
    case 3: return "unexpected session service primitive";
    case 4: return "unrecognized PPDU parameter";
    case 5: return "unexpected PPDU parameter";
    case 6: return "invalid PPDU parameter value";
    default: return "unknown";
    }
}

/* ---- responder side ---------------------------------------------------- */

int pres_parse_cp(const uint8_t *p, size_t n, pctx_list *ctxs,
                  buf_t *hold, ber_tlv *apdu, int *has_apdu)
{
    ber_rd  r;
    ber_tlv cp, nm, c;

    memset(ctxs, 0, sizeof *ctxs);
    *has_apdu = 0;
    ber_rd_init(&r, p, n);
    if (ber_next(&r, &cp) <= 0 || cp.tag != T_SET ||
        !ber_find(&cp, T_CTXC(2), &nm)) {
        set_error("presentation: malformed CP-type");
        return -1;
    }
    ber_enter(&nm, &r);
    while (ber_next(&r, &c) > 0) {
        if (c.tag == T_CTXC(4)) {
            ber_rd  lr;
            ber_tlv item;
            ber_enter(&c, &lr);
            while (ber_next(&lr, &item) > 0 && ctxs->n < 16) {
                ber_rd  ir;
                ber_tlv f;
                long    id = 0;
                ctxs->as[ctxs->n][0] = 0;
                ber_enter(&item, &ir);
                while (ber_next(&ir, &f) > 0) {
                    if (f.tag == T_INT)
                        ber_get_int(&f, &id);
                    else if (f.tag == T_OID)
                        ber_get_oid(&f, ctxs->as[ctxs->n], 64);
                }
                ctxs->id[ctxs->n++] = (int)id;
            }
        } else if (c.tag == T_APPC(1)) {
            if (ud_first(&c, hold, apdu, has_apdu) < 0)
                return -1;
        }
    }
    return 0;
}

void pres_build_cpa(buf_t *out, const pctx_list *ctxs, const int *accept,
                    int acse_ctx, const uint8_t *apdu, size_t apdu_len)
{
    ber_enc e;
    ber_enc_init(&e, out);
    ber_begin(&e, T_SET);
    ber_begin(&e, T_CTXC(0));
    ber_int(&e, T_CTX(0), 1);
    ber_end(&e);
    ber_begin(&e, T_CTXC(2));
    ber_bits(&e, T_CTX(0), 0x1);
    ber_begin(&e, T_CTXC(5));
    for (int i = 0; i < ctxs->n; i++) {
        ber_begin(&e, T_SEQ);
        ber_int(&e, T_CTX(0), accept[i] ? 0 : 2);
        if (accept[i])
            ber_oid(&e, T_CTX(1), OID_BER);
        else
            ber_int(&e, T_CTX(2), 2);           /* abstract syntax not supported */
        ber_end(&e);
    }
    ber_end(&e);
    ber_bits(&e, T_CTX(9), 0x2);
    {
        buf_t ud;
        buf_init(&ud);
        pres_user_data(&ud, acse_ctx, apdu, apdu_len);
        ber_raw(&e, ud.data, ud.len);
        buf_free(&ud);
    }
    ber_end(&e);
    ber_end(&e);
}

/* ---- ACSE -------------------------------------------------------------- */

static int user_encoding = PDV_SINGLE;

void acse_set_user_encoding(int mode)
{
    user_encoding = mode;
}

static void user_info(ber_enc *e, int user_ctx, const uint8_t *val, size_t len)
{
    if (!val)
        return;
    ber_begin(e, T_CTXC(30));                   /* user-information */
    ber_begin(e, T_EXTERNAL);
    ber_int(e, T_INT, user_ctx);                /* indirect-reference */
    if (user_encoding == PDV_SINGLE) {
        ber_begin(e, T_CTXC(0));                /* single-ASN1-type */
        ber_raw(e, val, len);
        ber_end(e);
    } else {
        enc_segmented(e, user_encoding == PDV_ARBITRARY ? 2 : 1,
                      user_encoding == PDV_ARBITRARY, val, len);
    }
    ber_end(e);
    ber_end(e);
}

void acse_build_aarq(buf_t *out, const acse_params *ap, int user_ctx,
                     const uint8_t *val, size_t len)
{
    ber_enc e;
    ber_enc_init(&e, out);
    ber_begin(&e, T_APPC(0));
    ber_bits(&e, T_CTX(0), 0x1);                /* version1 */
    ber_begin(&e, T_CTXC(1));
    ber_oid(&e, T_OID, ap->app_context);
    ber_end(&e);
    if (ap->called_ap_title) {
        ber_begin(&e, T_CTXC(2));
        ber_oid(&e, T_OID, ap->called_ap_title);
        ber_end(&e);
    }
    if (ap->called_ae_qual >= 0) {
        ber_begin(&e, T_CTXC(3));
        ber_int(&e, T_INT, ap->called_ae_qual);
        ber_end(&e);
    }
    if (ap->calling_ap_title) {
        ber_begin(&e, T_CTXC(6));
        ber_oid(&e, T_OID, ap->calling_ap_title);
        ber_end(&e);
    }
    if (ap->calling_ae_qual >= 0) {
        ber_begin(&e, T_CTXC(7));
        ber_int(&e, T_INT, ap->calling_ae_qual);
        ber_end(&e);
    }
    user_info(&e, user_ctx, val, len);
    ber_end(&e);
}

void acse_build_aare(buf_t *out, const char *app_context, long result,
                     long diag, int user_ctx, const uint8_t *val, size_t len)
{
    ber_enc e;
    ber_enc_init(&e, out);
    ber_begin(&e, T_APPC(1));
    ber_bits(&e, T_CTX(0), 0x1);
    ber_begin(&e, T_CTXC(1));
    ber_oid(&e, T_OID, app_context);
    ber_end(&e);
    ber_begin(&e, T_CTXC(2));
    ber_int(&e, T_INT, result);
    ber_end(&e);
    ber_begin(&e, T_CTXC(3));
    ber_begin(&e, T_CTXC(1));                   /* acse-service-user */
    ber_int(&e, T_INT, diag);
    ber_end(&e);
    ber_end(&e);
    user_info(&e, user_ctx, val, len);
    ber_end(&e);
}

void acse_build_rlrq(buf_t *out, int user_ctx, const uint8_t *val, size_t len)
{
    ber_enc e;
    ber_enc_init(&e, out);
    ber_begin(&e, T_APPC(2));
    ber_int(&e, T_CTX(0), 0);                   /* normal */
    user_info(&e, user_ctx, val, len);
    ber_end(&e);
}

void acse_build_rlre(buf_t *out, int user_ctx, const uint8_t *val, size_t len)
{
    ber_enc e;
    ber_enc_init(&e, out);
    ber_begin(&e, T_APPC(3));
    ber_int(&e, T_CTX(0), 0);                   /* normal */
    user_info(&e, user_ctx, val, len);
    ber_end(&e);
}

void acse_build_abrt(buf_t *out, int source, int user_ctx,
                     const uint8_t *val, size_t len)
{
    ber_enc e;
    ber_enc_init(&e, out);
    ber_begin(&e, T_APPC(4));
    ber_int(&e, T_CTX(0), source);
    user_info(&e, user_ctx, val, len);
    ber_end(&e);
}

int acse_parse(const ber_tlv *t, acse_apdu *a)
{
    ber_rd  r;
    ber_tlv c;
    int     rc;

    memset(a, 0, sizeof *a);
    buf_init(&a->own);
    a->tag = t->tag;
    a->result = a->diag_source = a->diag = a->reason = -1;
    a->user_ctx = -1;
    if (T_CLASS(t->tag) != 0x40 || T_TAGNUM(t->tag) > 4) {
        set_error("ACSE: unexpected APDU tag");
        return -1;
    }
    unsigned kind = T_TAGNUM(t->tag);
    ber_enter(t, &r);
    while ((rc = ber_next(&r, &c)) > 0) {
        ber_tlv in;
        if (c.tag == T_CTXC(30)) {
            ber_tlv ext;
            if (!ber_find(&c, T_EXTERNAL, &ext))
                continue;
            ber_rd  er;
            ber_tlv f;
            ber_enter(&ext, &er);
            while (ber_next(&er, &f) > 0) {
                long v;
                if (f.tag == T_INT && ber_get_int(&f, &v) == 0) {
                    a->user_ctx = (int)v;
                } else if (f.tag == T_CTXC(0)) {
                    ber_rd vr;
                    ber_enter(&f, &vr);
                    if (ber_next(&vr, &a->user) > 0)
                        a->has_user = 1;
                } else if (T_CLASS(f.tag) == 0x80 &&
                           (T_TAGNUM(f.tag) == 1 || T_TAGNUM(f.tag) == 2)) {
                    /* octet-aligned or arbitrary, possibly segmented:
                     * the joined encoding is kept in a->own */
                    ber_rd vr;
                    buf_reset(&a->own);
                    if (encoded_values(&f, &a->own, &vr) < 0) {
                        set_error("ACSE: malformed user-information encoding");
                        return -1;
                    }
                    if (ber_next(&vr, &a->user) > 0)
                        a->has_user = 1;
                }
            }
            continue;
        }
        if (kind == 1 && c.tag == T_CTXC(2)) {
            ber_rd ir;
            ber_enter(&c, &ir);
            if (ber_next(&ir, &in) > 0)
                ber_get_int(&in, &a->result);
        } else if (kind == 1 && c.tag == T_CTXC(3)) {
            ber_rd ir;
            ber_tlv d;
            ber_enter(&c, &ir);
            if (ber_next(&ir, &in) > 0) {
                a->diag_source = (long)T_TAGNUM(in.tag);
                ber_rd dr;
                ber_enter(&in, &dr);
                if (ber_next(&dr, &d) > 0)
                    ber_get_int(&d, &a->diag);
            }
        } else if ((kind == 2 || kind == 3 || kind == 4) && c.tag == T_CTX(0)) {
            ber_get_int(&c, &a->reason);
        }
    }
    return rc < 0 ? -1 : 0;
}

void acse_free(acse_apdu *a)
{
    buf_free(&a->own);
}

const char *acse_diag_str(long source, long diag)
{
    if (source == 1) {
        switch (diag) {
        case 0:  return "null";
        case 1:  return "no reason given";
        case 2:  return "application context name not supported";
        case 3:  return "calling AP title not recognized";
        case 4:  return "calling AP invocation identifier not recognized";
        case 5:  return "calling AE qualifier not recognized";
        case 6:  return "calling AE invocation identifier not recognized";
        case 7:  return "called AP title not recognized";
        case 8:  return "called AP invocation identifier not recognized";
        case 9:  return "called AE qualifier not recognized";
        case 10: return "called AE invocation identifier not recognized";
        case 11: return "authentication mechanism name not recognized";
        case 12: return "authentication mechanism name required";
        case 13: return "authentication failure";
        case 14: return "authentication required";
        }
    } else if (source == 2) {
        switch (diag) {
        case 0: return "null";
        case 1: return "no reason given";
        case 2: return "no common ACSE version";
        }
    }
    return "unknown";
}
