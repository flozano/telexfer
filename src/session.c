/*
 * session.c - ISO 8327-1 session protocol (subset).
 *
 * SPDU layout: SI (1 octet), LI (1 octet, or 0xff + 2 octets), then
 * parameters encoded as PI/PGI units (code, length, value).  For DT the
 * user information follows the parameter field and is not counted in LI.
 * Data transfer uses basic concatenation: GT SPDU (category 0) + DT.
 */
#include "session.h"

#include <string.h>

/* SPDU identifiers */
#define SPDU_DT 1           /* also GT (category 0) */
#define SPDU_PT 2
#define SPDU_FN 9
#define SPDU_DN 10
#define SPDU_NF 8
#define SPDU_RF 12
#define SPDU_CN 13
#define SPDU_AC 14
#define SPDU_AB 25
#define SPDU_AA 26
#define SPDU_CDO 15         /* connect data overflow */
#define SPDU_OA 16          /* overflow accept */

/* parameter identifiers */
#define PGI_CONN_ID         1
#define PGI_CONN_ACCEPT     5
#define PI_TRANSPORT_DISC   17
#define PI_PROTOCOL_OPTIONS 19
#define PI_SUR              20
#define PI_TSDU_MAX         21
#define PI_VERSION          22
#define PI_ENCLOSURE        25
#define PI_CALLING_SSEL     51
#define PI_CALLED_SSEL      52
#define PI_REASON           50
#define PI_DATA_OVERFLOW    60
#define PGI_USER_DATA       193
#define PGI_EXT_USER_DATA   194

/* PI 19 protocol options */
#define OPT_EXT_CONCAT      0x01    /* able to receive extended concatenation */

#define ENC_BEGIN 0x01          /* Enclosure Item: beginning of SSDU */
#define ENC_END   0x02          /* Enclosure Item: end of SSDU */

/* connect user data carried in CN itself; the rest goes into CDO SPDUs */
#define CN_UD_MAX           10240
#define CDO_UD_MAX          10240

static const char *L = "ses";

/* ---- encoding helpers -------------------------------------------------- */

static void put_li(buf_t *b, size_t len)
{
    if (len < 255) {
        buf_put8(b, (uint8_t)len);
    } else {
        buf_put8(b, 0xff);
        buf_put16(b, (uint16_t)len);
    }
}

static void put_param(buf_t *b, uint8_t code, const void *v, size_t len)
{
    buf_put8(b, code);
    put_li(b, len);
    buf_put(b, v, len);
}

/* Wrap a parameter field into an SPDU. */
static void make_spdu(buf_t *out, uint8_t si, const buf_t *params)
{
    buf_put8(out, si);
    put_li(out, params->len);
    buf_put(out, params->data, params->len);
}

/* ---- decoding helpers -------------------------------------------------- */

typedef struct {
    uint8_t        si;
    const uint8_t *params;
    size_t         plen;
    size_t         hdrlen;      /* SI + LI + params */
} spdu_t;

static int get_li(const uint8_t *p, size_t n, size_t *len, size_t *used)
{
    if (n < 1)
        return -1;
    if (p[0] != 0xff) {
        *len = p[0];
        *used = 1;
        return 0;
    }
    if (n < 3)
        return -1;
    *len = (size_t)(p[1] << 8 | p[2]);
    *used = 3;
    return 0;
}

static int spdu_parse(const uint8_t *p, size_t n, spdu_t *s)
{
    size_t len, used;
    if (n < 2 || get_li(p + 1, n - 1, &len, &used) < 0)
        return -1;
    if (1 + used + len > n)
        return -1;
    s->si = p[0];
    s->params = p + 1 + used;
    s->plen = len;
    s->hdrlen = 1 + used + len;
    return 0;
}

/* Find a PI/PGI; also looks inside PGI 1 and PGI 5 groups. */
static int param_find(const uint8_t *p, size_t n, uint8_t code,
                      const uint8_t **v, size_t *vlen)
{
    size_t off = 0;
    while (off < n) {
        size_t len, used;
        uint8_t c = p[off];
        if (get_li(p + off + 1, n - off - 1, &len, &used) < 0)
            return 0;
        const uint8_t *val = p + off + 1 + used;
        if (off + 1 + used + len > n)
            return 0;
        if (c == code) {
            *v = val;
            *vlen = len;
            return 1;
        }
        if ((c == PGI_CONN_ID || c == PGI_CONN_ACCEPT) &&
            param_find(val, len, code, v, vlen))
            return 1;
        off += 1 + used + len;
    }
    return 0;
}

static void get_user_data(const spdu_t *s, buf_t *ud)
{
    const uint8_t *v;
    size_t         len;
    buf_reset(ud);
    if (param_find(s->params, s->plen, PGI_USER_DATA, &v, &len) ||
        param_find(s->params, s->plen, PGI_EXT_USER_DATA, &v, &len))
        buf_put(ud, v, len);
}

static const char *rf_reason(int r)
{
    switch (r) {
    case 0:   return "rejected by called SS-user";
    case 1:   return "rejected by called SS-user: temporary congestion";
    case 2:   return "rejected by called SS-user (with user data)";
    case 129: return "session selector unknown";
    case 130: return "SS-user not attached to SSAP";
    case 131: return "SPM congestion at connect time";
    case 132: return "proposed protocol versions not supported";
    case 133: return "rejected by SPM, no reason";
    case 134: return "rejected by SPM, implementation restriction";
    default:  return "unknown reason";
    }
}

/* ---- connection establishment ------------------------------------------ */

/* The lower of two TSDU sizes where 0 means "no limit". */
static int lower_nz(int a, int b)
{
    if (a == 0)
        return b;
    if (b == 0)
        return a;
    return a < b ? a : b;
}

/* PI 21: initiator->responder in the first two octets, then the reverse. */
static void put_tsdu_max(buf_t *grp, int init_to_resp, int resp_to_init)
{
    uint8_t v[4] = { (uint8_t)(init_to_resp >> 8), (uint8_t)init_to_resp,
                     (uint8_t)(resp_to_init >> 8), (uint8_t)resp_to_init };
    put_param(grp, PI_TSDU_MAX, v, 4);
}

static int get_tsdu_max(const spdu_t *sp, int out[2])
{
    const uint8_t *v;
    size_t         vl;
    if (!param_find(sp->params, sp->plen, PI_TSDU_MAX, &v, &vl) || vl != 4)
        return 0;
    out[0] = v[0] << 8 | v[1];
    out[1] = v[2] << 8 | v[3];
    return 1;
}

/* Parameters common to CN, AC and OA: version, SUR, TSDU sizes. */
static void read_common(ses_conn *s, const spdu_t *sp)
{
    const uint8_t *v;
    size_t         vl;
    s->version = 2;
    if (param_find(sp->params, sp->plen, PI_VERSION, &v, &vl) && vl == 1)
        s->version = (v[0] & 0x02) ? 2 : 1;
    if (param_find(sp->params, sp->plen, PI_SUR, &v, &vl) && vl == 2)
        s->sur = (uint16_t)(v[0] << 8 | v[1]);
}

static int apply_tsdu_answer(ses_conn *s, const spdu_t *sp, int proposed)
{
    int tm[2];
    if (!proposed)
        return 0;
    if (!get_tsdu_max(sp, tm)) {
        log_msg(LOG_INFO, L, "responder did not accept segmenting");
        s->tsdu_max_tx = s->tsdu_max_rx = 0;
        return 0;
    }
    /* the responder may only lower what we proposed */
    s->tsdu_max_tx = lower_nz(tm[0], proposed);
    s->tsdu_max_rx = tm[1];
    if ((s->tsdu_max_tx && s->tsdu_max_tx < SES_MIN_TSDU) ||
        (s->tsdu_max_rx && s->tsdu_max_rx < SES_MIN_TSDU)) {
        set_error("session: responder selected unusable TSDU size %d/%d", tm[0], tm[1]);
        return -1;
    }
    log_msg(LOG_INFO, L, "segmenting: TSDU max %d (send), %d (receive)",
            s->tsdu_max_tx, s->tsdu_max_rx);
    return 0;
}

/*
 * Send the connect user data that did not fit into CN as CDO SPDUs, each
 * with an Enclosure Item (end bit on the last) and user data PGI 193.
 * The SSDU began in CN, so no CDO carries the beginning bit.
 */
static int send_cdo(ses_conn *s, const uint8_t *ud, size_t n)
{
    size_t max = CDO_UD_MAX;
    if (s->tsdu_max_tx && (size_t)s->tsdu_max_tx - 12 < max)
        max = (size_t)s->tsdu_max_tx - 12;      /* SI, LI(3), PI 25, PGI 193 hdr */
    buf_t params, spdu;
    buf_init(&params);
    buf_init(&spdu);
    int    rc = 0, count = 0;
    size_t off = 0;
    while (off < n) {
        size_t  chunk = n - off > max ? max : n - off;
        uint8_t enc = off + chunk == n ? ENC_END : 0;
        buf_reset(&params);
        buf_reset(&spdu);
        put_param(&params, PI_ENCLOSURE, &enc, 1);
        put_param(&params, PGI_USER_DATA, ud + off, chunk);
        make_spdu(&spdu, SPDU_CDO, &params);
        if ((rc = tp0_send(s->tc, spdu.data, spdu.len)) < 0)
            break;
        off += chunk;
        count++;
    }
    log_msg(LOG_INFO, L, "CDO: %zu octets of connect data overflow in %d SPDU(s)",
            n, count);
    buf_free(&params);
    buf_free(&spdu);
    return rc;
}

int ses_connect(ses_conn *s, tp0_conn *tc,
                const uint8_t *calling, size_t calling_len,
                const uint8_t *called, size_t called_len,
                const uint8_t *ud, size_t udlen, const ses_params *prm,
                buf_t *resp_ud, int *reason)
{
    buf_t params, grp, spdu;
    int   tsdu_max = prm ? prm->tsdu_max : 0;

    memset(s, 0, sizeof *s);
    s->tc = tc;
    s->sur = SUR_HALF_DUPLEX;
    buf_init(&s->tsdu);
    buf_init(&s->ssdu);
    if (tsdu_max != 0 && (tsdu_max < SES_MIN_TSDU || tsdu_max > 65535)) {
        set_error("session TSDU maximum size must be %d..65535", SES_MIN_TSDU);
        return -1;
    }
    if (calling_len > 16 || called_len > 16) {
        set_error("session selectors are limited to 16 octets");
        return -1;
    }
    /* more than 10240 octets: the rest follows in CDO SPDUs (version 2) */
    int overflow = udlen > CN_UD_MAX;

    buf_init(&params);
    buf_init(&grp);
    buf_init(&spdu);
    uint8_t opt = (uint8_t)(prm && prm->ext_concat ? OPT_EXT_CONCAT : 0x00);
    uint8_t ver = udlen > 512 ? 0x02 : 0x03;
    put_param(&grp, PI_PROTOCOL_OPTIONS, &opt, 1);
    if (tsdu_max)
        put_tsdu_max(&grp, tsdu_max, tsdu_max);
    put_param(&grp, PI_VERSION, &ver, 1);
    put_param(&params, PGI_CONN_ACCEPT, grp.data, grp.len);
    uint8_t sur[2] = { 0x00, SUR_DUPLEX };
    put_param(&params, PI_SUR, sur, 2);
    if (calling_len)
        put_param(&params, PI_CALLING_SSEL, calling, calling_len);
    if (called_len)
        put_param(&params, PI_CALLED_SSEL, called, called_len);
    if (overflow) {
        uint8_t more = 0x01;
        put_param(&params, PI_DATA_OVERFLOW, &more, 1);
    }
    size_t first = overflow ? CN_UD_MAX : udlen;
    put_param(&params, udlen > 512 ? PGI_EXT_USER_DATA : PGI_USER_DATA, ud, first);
    make_spdu(&spdu, SPDU_CN, &params);

    log_msg(LOG_INFO, L, "CN (versions %s, duplex, %zu octets user data%s%s%s)",
            ver == 3 ? "1+2" : "2", udlen, tsdu_max ? ", segmenting proposed" : "",
            overflow ? ", data overflow" : "",
            opt & OPT_EXT_CONCAT ? ", extended concatenation" : "");
    log_hex(LOG_DUMP, L, "CN SPDU", spdu.data, spdu.len);
    int rc = tp0_send(tc, spdu.data, spdu.len);
    buf_free(&params);
    buf_free(&grp);
    buf_free(&spdu);
    if (rc < 0)
        return -1;

    for (;;) {
        if (tp0_recv(tc, &s->tsdu) < 0)
            return -1;
        log_hex(LOG_DUMP, L, "received SPDU", s->tsdu.data, s->tsdu.len);
        spdu_t sp;
        if (spdu_parse(s->tsdu.data, s->tsdu.len, &sp) < 0) {
            set_error("session: malformed SPDU in reply to CN");
            return -1;
        }
        const uint8_t *v;
        size_t         vl;
        if (sp.si == SPDU_OA && overflow) {
            read_common(s, &sp);
            log_msg(LOG_INFO, L, "OA: responder accepts connect data overflow");
            if (apply_tsdu_answer(s, &sp, tsdu_max) < 0 ||
                send_cdo(s, ud + first, udlen - first) < 0)
                return -1;
            overflow = 0;
            continue;
        }
        if (sp.si == SPDU_AC) {
            if (overflow) {
                set_error("session: AC before the connect data overflow was sent");
                return -1;
            }
            read_common(s, &sp);
            get_user_data(&sp, resp_ud);
            log_msg(LOG_INFO, L, "AC: version %d, requirements 0x%04x", s->version, s->sur);
            if (param_find(sp.params, sp.plen, PI_PROTOCOL_OPTIONS, &v, &vl) && vl == 1)
                s->peer_ext_concat = v[0] & OPT_EXT_CONCAT;
            if (apply_tsdu_answer(s, &sp, tsdu_max) < 0)
                return -1;
            return 0;
        }
        if (sp.si == SPDU_RF) {
            int r = -1;
            buf_reset(resp_ud);
            if (param_find(sp.params, sp.plen, PI_REASON, &v, &vl) && vl >= 1) {
                r = v[0];
                buf_put(resp_ud, v + 1, vl - 1);
            }
            if (reason)
                *reason = r;
            log_msg(LOG_INFO, L, "RF: %s (%d)", rf_reason(r), r);
            set_error("session connection refused: %s (%d)", rf_reason(r), r);
            return 1;
        }
        if (sp.si == SPDU_AB) {
            set_error("session connection aborted by peer during connect");
            return -1;
        }
        set_error("session: unexpected SPDU %u in reply to CN", sp.si);
        return -1;
    }
}

int ses_wait_connect(ses_conn *s, tp0_conn *tc, buf_t *cn_ud, int tsdu_limit)
{
    memset(s, 0, sizeof *s);
    s->tc = tc;
    s->tsdu_limit = tsdu_limit;
    s->sur = SUR_HALF_DUPLEX;
    buf_init(&s->tsdu);
    buf_init(&s->ssdu);
    if (tp0_recv(tc, &s->tsdu) < 0)
        return -1;
    spdu_t sp;
    if (spdu_parse(s->tsdu.data, s->tsdu.len, &sp) < 0 || sp.si != SPDU_CN) {
        set_error("session: expected CN SPDU");
        return -1;
    }
    const uint8_t *v;
    size_t         vl;
    read_common(s, &sp);
    if (param_find(sp.params, sp.plen, PI_PROTOCOL_OPTIONS, &v, &vl) && vl == 1)
        s->peer_ext_concat = v[0] & OPT_EXT_CONCAT;
    s->cn_has_tsdu = get_tsdu_max(&sp, s->cn_tsdu);
    if (s->cn_has_tsdu) {
        /* segmenting only if the initiator proposed it */
        s->tsdu_max_rx = lower_nz(s->cn_tsdu[0], s->tsdu_limit);
        s->tsdu_max_tx = s->cn_tsdu[1];
        if (s->tsdu_max_rx && s->tsdu_max_rx < SES_MIN_TSDU)
            s->tsdu_max_rx = SES_MIN_TSDU;
    }
    get_user_data(&sp, cn_ud);

    if (!param_find(sp.params, sp.plen, PI_DATA_OVERFLOW, &v, &vl) || vl != 1 ||
        !(v[0] & 0x01))
        return 0;

    /* connect data overflow: accept it, then collect the CDO SPDUs */
    buf_t params, grp, spdu;
    buf_init(&params);
    buf_init(&grp);
    buf_init(&spdu);
    uint8_t ver = 0x02;
    if (s->cn_has_tsdu)
        put_tsdu_max(&params, s->tsdu_max_rx, s->tsdu_max_tx);
    put_param(&params, PI_VERSION, &ver, 1);
    make_spdu(&spdu, SPDU_OA, &params);
    log_msg(LOG_INFO, L, "connect data overflow: OA");
    int rc = tp0_send(tc, spdu.data, spdu.len);
    buf_free(&params);
    buf_free(&grp);
    buf_free(&spdu);
    if (rc < 0)
        return -1;
    for (int count = 1;; count++) {
        if (tp0_recv(tc, &s->tsdu) < 0)
            return -1;
        if (spdu_parse(s->tsdu.data, s->tsdu.len, &sp) < 0 || sp.si != SPDU_CDO) {
            set_error("session: expected CDO SPDU");
            return -1;
        }
        if (param_find(sp.params, sp.plen, PGI_USER_DATA, &v, &vl))
            buf_put(cn_ud, v, vl);
        if (param_find(sp.params, sp.plen, PI_ENCLOSURE, &v, &vl) && vl == 1 &&
            (v[0] & ENC_END)) {
            log_msg(LOG_INFO, L, "connect data complete: %zu octets in CN + %d CDO",
                    cn_ud->len, count);
            return 0;
        }
    }
}

void ses_free(ses_conn *s)
{
    buf_free(&s->tsdu);
    buf_free(&s->ssdu);
}

int ses_accept(ses_conn *s, const uint8_t *ud, size_t udlen)
{
    buf_t params, grp, spdu;
    buf_init(&params);
    buf_init(&grp);
    buf_init(&spdu);
    uint8_t opt = OPT_EXT_CONCAT;               /* we parse any concatenation */
    uint8_t ver = (uint8_t)(s->version == 2 ? 0x02 : 0x01);
    put_param(&grp, PI_PROTOCOL_OPTIONS, &opt, 1);
    if (s->cn_has_tsdu) {
        put_tsdu_max(&grp, s->tsdu_max_rx, s->tsdu_max_tx);
        log_msg(LOG_INFO, L, "segmenting: TSDU max %d (send), %d (receive)",
                s->tsdu_max_tx, s->tsdu_max_rx);
    }
    put_param(&grp, PI_VERSION, &ver, 1);
    put_param(&params, PGI_CONN_ACCEPT, grp.data, grp.len);
    uint8_t sur[2] = { (uint8_t)(s->sur >> 8), (uint8_t)s->sur };
    put_param(&params, PI_SUR, sur, 2);
    put_param(&params, PGI_USER_DATA, ud, udlen);
    make_spdu(&spdu, SPDU_AC, &params);
    int rc = tp0_send(s->tc, spdu.data, spdu.len);
    buf_free(&params);
    buf_free(&grp);
    buf_free(&spdu);
    return rc;
}

/* ---- data transfer & release ------------------------------------------- */

static int send_dt(ses_conn *s, const uint8_t *cat2, size_t cat2len,
                   const uint8_t *p, size_t n)
{
    buf_t tsdu;
    int   rc = 0;

    buf_init(&tsdu);
    if (!s->tsdu_max_tx) {
        /* GT (category 0, empty) [+ other category 2 SPDUs, extended
         * concatenation] + DT (no parameters) + user information */
        static const uint8_t gt[2] = { SPDU_DT, 0 }, dt[2] = { SPDU_DT, 0 };
        buf_put(&tsdu, gt, 2);
        buf_put(&tsdu, cat2, cat2len);
        buf_put(&tsdu, dt, 2);
        buf_put(&tsdu, p, n);
        rc = tp0_send(s->tc, tsdu.data, tsdu.len);
        buf_free(&tsdu);
        return rc;
    }
    if (cat2len) {
        set_error("session: extended concatenation with segmenting not supported");
        buf_free(&tsdu);
        return -1;
    }

    /* segmenting: each TSDU is GT + DT with an Enclosure Item, and the
     * whole TSDU must fit the negotiated maximum */
    size_t max = (size_t)s->tsdu_max_tx - 7;
    size_t off = 0;
    int    nseg = 0;
    do {
        size_t  chunk = n - off > max ? max : n - off;
        uint8_t enc = (uint8_t)((off == 0 ? ENC_BEGIN : 0) |
                                (off + chunk == n ? ENC_END : 0));
        uint8_t hdr[7] = { SPDU_DT, 0, SPDU_DT, 3, PI_ENCLOSURE, 1, enc };
        buf_reset(&tsdu);
        buf_put(&tsdu, hdr, sizeof hdr);
        buf_put(&tsdu, p + off, chunk);
        if ((rc = tp0_send(s->tc, tsdu.data, tsdu.len)) < 0)
            break;
        off += chunk;
        nseg++;
    } while (off < n);
    if (nseg > 1)
        log_msg(LOG_DEBUG, L, "SSDU of %zu octets sent in %d segments", n, nseg);
    buf_free(&tsdu);
    return rc;
}

int ses_send_data(ses_conn *s, const uint8_t *p, size_t n)
{
    return send_dt(s, NULL, 0, p, n);
}

int ses_send_data_concat(ses_conn *s, const uint8_t *cat2, size_t cat2len,
                         const uint8_t *p, size_t n)
{
    if (!s->peer_ext_concat) {
        set_error("session: peer cannot receive extended concatenation");
        return -1;
    }
    return send_dt(s, cat2, cat2len, p, n);
}

static int send_with_ud(ses_conn *s, uint8_t si, uint8_t tdisc,
                        const uint8_t *ud, size_t n)
{
    buf_t params, spdu;
    buf_init(&params);
    buf_init(&spdu);
    if (tdisc != 0xff)
        put_param(&params, PI_TRANSPORT_DISC, &tdisc, 1);
    if (ud)
        put_param(&params, PGI_USER_DATA, ud, n);
    make_spdu(&spdu, si, &params);
    int rc = tp0_send(s->tc, spdu.data, spdu.len);
    buf_free(&params);
    buf_free(&spdu);
    return rc;
}

int ses_finish(ses_conn *s, const uint8_t *ud, size_t n)
{
    log_msg(LOG_INFO, L, "FN (release transport connection)");
    return send_with_ud(s, SPDU_FN, 0x01, ud, n);
}

int ses_disconnect(ses_conn *s, const uint8_t *ud, size_t n)
{
    log_msg(LOG_INFO, L, "DN");
    return send_with_ud(s, SPDU_DN, 0xff, ud, n);
}

int ses_abort(ses_conn *s, const uint8_t *ud, size_t n)
{
    log_msg(LOG_INFO, L, "AB (user abort)");
    /* transport connection released | user abort */
    return send_with_ud(s, SPDU_AB, 0x03, ud, n);
}

/*
 * SPDU identifiers that are category 2 (always follow a category 0 SPDU
 * in the same TSDU).  Several share a code with a category 1 SPDU (e.g.
 * AI = AB = 25); position in the TSDU tells them apart.
 */
static int is_cat2(uint8_t si)
{
    switch (si) {
    case 1:  /* DT */
    case 25: /* AI */
    case 26: /* AIA */
    case 29: /* AR */
    case 34: /* RA */
    case 41: /* MAP / AE */
    case 42: /* MAA / AEA */
    case 45: /* AS */
    case 48: /* ED */
    case 49: /* MIP */
    case 50: /* MIA */
    case 53: /* RS */
    case 57: /* AD */
    case 58: /* ADA */
    case 61: /* CD */
    case 62: /* CDA */
        return 1;
    }
    return 0;
}

/* Handle a DT SPDU (user information = rest of the TSDU). */
static int handle_dt(ses_conn *s, const spdu_t *sp, const uint8_t *info,
                     size_t infolen, size_t tsdulen, int *ev, buf_t *ud)
{
    const uint8_t *v;
    size_t         vl;
    if (param_find(sp->params, sp->plen, PI_ENCLOSURE, &v, &vl) && vl == 1) {
        if (!s->tsdu_max_rx && !s->tsdu_max_tx) {
            set_error("session: segmented DT but segmenting was not negotiated");
            return -1;
        }
        if (s->tsdu_max_rx && tsdulen > (size_t)s->tsdu_max_rx)
            log_msg(LOG_INFO, L, "TSDU of %zu octets exceeds negotiated %d",
                    tsdulen, s->tsdu_max_rx);
        if (v[0] & ENC_BEGIN) {
            if (s->in_ssdu)
                log_msg(LOG_INFO, L, "new SSDU before end of previous one");
            buf_reset(&s->ssdu);
            s->in_ssdu = 1;
        } else if (!s->in_ssdu) {
            set_error("session: DT segment without beginning of SSDU");
            return -1;
        }
        buf_put(&s->ssdu, info, infolen);
        if (!(v[0] & ENC_END))
            return 1;                           /* more segments to come */
        s->in_ssdu = 0;
        buf_reset(ud);
        buf_put(ud, s->ssdu.data, s->ssdu.len);
        buf_reset(&s->ssdu);
        *ev = SES_EV_DATA;
        return 0;
    }
    buf_reset(ud);
    buf_put(ud, info, infolen);
    *ev = SES_EV_DATA;
    return 0;
}

int ses_recv(ses_conn *s, int *ev, buf_t *ud)
{
    for (;;) {
        if (tp0_recv(s->tc, &s->tsdu) < 0)
            return -1;
        const uint8_t *p = s->tsdu.data;
        size_t         n = s->tsdu.len;
        size_t         total = n;
        spdu_t         sp;

        log_hex(LOG_DUMP, L, "received TSDU", p, n);
        if (spdu_parse(p, n, &sp) < 0) {
            set_error("session: malformed SPDU");
            return -1;
        }

        if ((sp.si == SPDU_DT || sp.si == SPDU_PT) && sp.hdrlen < n) {
            /* A DT sent without the leading GT (seen in the wild) is
             * followed directly by presentation data, not by an SPDU. */
            if (sp.si == SPDU_DT && !is_cat2(p[sp.hdrlen])) {
                int rc = handle_dt(s, &sp, p + sp.hdrlen, n - sp.hdrlen, total, ev, ud);
                if (rc == 1)
                    continue;
                return rc;
            }
            /* category 0, then one or more category 2 SPDUs; with
             * extended concatenation only the last may be DT */
            p += sp.hdrlen;
            n -= sp.hdrlen;
            int got = 0, rc = 0;
            while (n > 0) {
                if (spdu_parse(p, n, &sp) < 0) {
                    set_error("session: malformed concatenated SPDU");
                    return -1;
                }
                if (sp.si == SPDU_DT) {
                    rc = handle_dt(s, &sp, p + sp.hdrlen, n - sp.hdrlen, total, ev, ud);
                    got = 1;
                    break;
                }
                /* only possible with functional units we never negotiate
                 * (synchronization, activities, ...): nothing to do */
                log_msg(LOG_INFO, L, "ignoring concatenated category 2 SPDU %u", sp.si);
                p += sp.hdrlen;
                n -= sp.hdrlen;
            }
            if (!got || rc == 1)
                continue;
            return rc;
        }
        switch (sp.si) {
        case SPDU_DT:
        case SPDU_PT:
            log_msg(LOG_DEBUG, L, "token SPDU %u ignored", sp.si);
            continue;
        case SPDU_FN:
            get_user_data(&sp, ud);
            *ev = SES_EV_FINISH;
            return 0;
        case SPDU_DN:
            get_user_data(&sp, ud);
            *ev = SES_EV_DISCONNECT;
            return 0;
        case SPDU_NF:
            get_user_data(&sp, ud);
            *ev = SES_EV_NOT_FINISHED;
            return 0;
        case SPDU_AB:
            get_user_data(&sp, ud);
            *ev = SES_EV_ABORT;
            return 0;
        case SPDU_AA:
            continue;
        default:
            set_error("session: unsupported SPDU %u", sp.si);
            return -1;
        }
    }
}
