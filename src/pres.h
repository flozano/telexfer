/*
 * pres.h - ISO 8823 / X.226 presentation protocol (normal mode, kernel
 * functional unit) and ISO 8650 / X.227 ACSE APDUs.
 */
#ifndef FTAM_PRES_H
#define FTAM_PRES_H

#include "ber.h"

#define OID_BER         "2.1.1"
#define OID_ACSE_AS     "2.2.1.0.1"

typedef struct {
    int         id;             /* presentation context identifier (odd) */
    const char *abstract;       /* abstract syntax OID */
    int         result;         /* 0 accepted, 1 user-rej, 2 provider-rej, -1 n/a */
} pctx_t;

/* ---- presentation ------------------------------------------------------ */

/* User-data ::= fully-encoded-data with a single PDV-list. */
void pres_user_data(buf_t *out, int ctx, const uint8_t *val, size_t len);
/* Append one PDV-list; wrap several with pres_ud_begin/end. */
void pres_ud_begin(ber_enc *e, buf_t *out);
void pres_ud_pdv(ber_enc *e, int ctx, const uint8_t *val, size_t len);
/* presentation-data-values / EXTERNAL encoding choices */
enum { PDV_SINGLE = 0, PDV_OCTET = 1, PDV_ARBITRARY = 2 };

/*
 * One PDV-list whose values are carried octet-aligned or arbitrary (BIT
 * STRING): vals is the concatenated BER encoding of one or more values.
 * Longer than the segment size (default PRES_OCTET_SEGMENT, as CER) it is
 * sent constructed, in segments.  PDV_SINGLE: vals must be one value.
 */
#define PRES_OCTET_SEGMENT 1000
void pres_set_segment(size_t n);
void pres_ud_pdv_enc(ber_enc *e, int ctx, int mode, const uint8_t *vals, size_t len);
void pres_ud_pdv_octets(ber_enc *e, int ctx, const uint8_t *vals, size_t len);
void pres_ud_end(ber_enc *e);

/*
 * Iterate over presentation data values in User-data.  The callback is
 * invoked once for each ASN.1 value found (single-ASN1-type, or each
 * value inside octet-aligned or arbitrary, segmented or not).  Values
 * are only valid during the callback.  Returns 0, -1 on error or the
 * callback's negative return value.
 */
typedef int (*pdv_cb)(void *arg, int ctx, const ber_tlv *value);
int  pres_parse_ud(const uint8_t *p, size_t n, pdv_cb cb, void *arg);

/* CP-type PPDU carrying ACSE (ctx acse_ctx) user data. */
void pres_build_cp(buf_t *out,
                   const uint8_t *calling, size_t calling_len,
                   const uint8_t *called, size_t called_len,
                   const pctx_t *ctx, int nctx,
                   int acse_ctx, const uint8_t *apdu, size_t apdu_len);
/*
 * Parse CPA-PPDU (accepted) or CPR-PPDU (refused): context results are
 * stored in ctx[], *reason gets the provider-reason (or -1).  The ACSE
 * APDU in the user data (if any) is copied into hold and apdu points into
 * it, so it stays valid after the input buffer goes away.  Returns 0 if
 * parsed.
 */
int  pres_parse_cpa(const uint8_t *p, size_t n, pctx_t *ctx, int nctx,
                    buf_t *hold, ber_tlv *apdu, int *has_apdu);
int  pres_parse_cpr(const uint8_t *p, size_t n, int *reason,
                    buf_t *hold, ber_tlv *apdu, int *has_apdu);
/* ARU-PPDU (user abort) carrying an ACSE ABRT. */
void pres_build_aru(buf_t *out, int acse_ctx, const uint8_t *apdu, size_t len);
/* Parse ARU/ARP: *provider_reason = -1 for ARU. */
int  pres_parse_abort(const uint8_t *p, size_t n, int *provider_reason,
                      buf_t *hold, ber_tlv *apdu, int *has_apdu);

const char *pres_provider_reason(int r);
const char *pres_abort_reason(int r);

/* Responder side (test server). */
typedef struct {
    int     n;
    int     id[16];
    char    as[16][64];
} pctx_list;
int  pres_parse_cp(const uint8_t *p, size_t n, pctx_list *ctxs,
                   buf_t *hold, ber_tlv *apdu, int *has_apdu);
void pres_build_cpa(buf_t *out, const pctx_list *ctxs, const int *accept,
                    int acse_ctx, const uint8_t *apdu, size_t apdu_len);

/* ---- ACSE -------------------------------------------------------------- */

typedef struct {
    const char *app_context;        /* application context name OID */
    const char *called_ap_title;    /* OID form, optional */
    long        called_ae_qual;     /* < 0: absent */
    const char *calling_ap_title;
    long        calling_ae_qual;
} acse_params;

/* user-information EXTERNAL uses indirect-reference = user_ctx, and the
 * encoding set here (PDV_SINGLE by default) for the embedded value */
void acse_set_user_encoding(int mode);
void acse_build_aarq(buf_t *out, const acse_params *ap, int user_ctx,
                     const uint8_t *val, size_t len);
void acse_build_aare(buf_t *out, const char *app_context, long result,
                     long diag, int user_ctx, const uint8_t *val, size_t len);
void acse_build_rlrq(buf_t *out, int user_ctx, const uint8_t *val, size_t len);
void acse_build_rlre(buf_t *out, int user_ctx, const uint8_t *val, size_t len);
void acse_build_abrt(buf_t *out, int source, int user_ctx,
                     const uint8_t *val, size_t len);

typedef struct {
    uint32_t tag;               /* APDU tag: T_APPC(0..4) */
    long     result;            /* AARE result, -1 absent */
    long     diag_source;       /* 1 = service-user, 2 = service-provider */
    long     diag;
    long     reason;            /* RLRQ/RLRE reason, ABRT source */
    int      has_user;          /* user-information present */
    int      user_ctx;          /* its indirect-reference, -1 absent */
    ber_tlv  user;              /* the embedded value */
    buf_t    own;               /* storage for a segmented embedded value */
} acse_apdu;

/* Parse an APDU; a->user may point into a->own: call acse_free() after. */
int  acse_parse(const ber_tlv *t, acse_apdu *a);
void acse_free(acse_apdu *a);
const char *acse_diag_str(long source, long diag);

#endif
