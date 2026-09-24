/*
 * ftam.c - FTAM initiator protocol machine (ISO 8571-4), kernel,
 * read, write, limited/enhanced file management and grouping.
 */
#include "ftam.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

static const char *L = "ftam";

void ftam_opts_default(ftam_opts *o)
{
    memset(o, 0, sizeof *o);
    o->port = XOT_PORT;
    o->x25.pkt_size = 128;
    o->x25.window = 2;
    o->x25.lcn = 1;
    /* ISO/TR 9577 protocol identifier for ISO 8073 transport */
    static const uint8_t cud[] = { 0x03, 0x01, 0x01, 0x00 };
    memcpy(o->x25.cud, cud, sizeof cud);
    o->x25.cud_len = sizeof cud;
    o->timeout_ms = 60000;
    o->tpdu_size = 2048;
    o->acse.app_context = OID_FTAM_APP_CTX;
    o->acse.called_ae_qual = -1;
    o->acse.calling_ae_qual = -1;
    o->service_class = SC_MANAGEMENT | SC_TRANSFER | SC_TRANSFER_MGMT;
    o->functional_units = FU_READ | FU_WRITE | FU_LIMITED_MGMT |
                          FU_ENHANCED_MGMT | FU_GROUPING;
    o->attribute_groups = AG_STORAGE;
    o->chunk_size = 4096;
}

/* ---- receive queue ----------------------------------------------------- */

static int enqueue_cb(void *arg, int ctx, const ber_tlv *v)
{
    ftam_conn *fc = arg;
    item_q    *q = xmalloc(sizeof *q + v->rawlen);
    q->next = NULL;
    q->ctx = ctx;
    q->len = v->rawlen;
    memcpy(q->data, v->raw, v->rawlen);
    if (fc->qtail)
        fc->qtail->next = q;
    else
        fc->qhead = q;
    fc->qtail = q;
    return 0;
}

static void flush_queue(ftam_conn *fc)
{
    while (fc->qhead) {
        item_q *q = fc->qhead;
        fc->qhead = q->next;
        free(q);
    }
    fc->qtail = NULL;
}

/* Build an error message from a received (A-/P-) abort. */
static void report_abort(ftam_conn *fc, const buf_t *ud)
{
    int     preason, has;
    ber_tlv apdu;
    char    diag[1024] = "";
    buf_t   hold;

    (void)fc;
    buf_init(&hold);
    if (pres_parse_abort(ud->data, ud->len, &preason, &hold, &apdu, &has) < 0) {
        set_error("association aborted by peer");
        buf_free(&hold);
        return;
    }
    if (preason >= 0) {
        set_error("association aborted by presentation provider: %s",
                  pres_abort_reason(preason));
        return;
    }
    if (has) {
        acse_apdu a;
        if (acse_parse(&apdu, &a) == 0 && a.has_user &&
            T_CLASS(a.user.tag) == 0x80) {
            unsigned t = T_TAGNUM(a.user.tag);
            ftam_fmt_diagnostic(&a.user, diag, sizeof diag);
            set_error("association aborted by peer (%s)%s%s",
                      ftam_pdu_name(t), diag[0] ? ": " : "", diag);
            acse_free(&a);
            buf_free(&hold);
            return;
        }
        acse_free(&a);
    }
    buf_free(&hold);
    set_error("association aborted by peer");
}

static int next_item(ftam_conn *fc, item_q **out)
{
    buf_t ud;
    buf_init(&ud);
    while (!fc->qhead) {
        int ev;
        if (ses_recv(&fc->ses, &ev, &ud) < 0) {
            fc->associated = 0;
            buf_free(&ud);
            return -1;
        }
        if (ev == SES_EV_DATA) {
            if (pres_parse_ud(ud.data, ud.len, enqueue_cb, fc) < 0) {
                buf_free(&ud);
                return -1;
            }
            continue;
        }
        if (ev == SES_EV_ABORT) {
            report_abort(fc, &ud);
            fc->associated = 0;
            buf_free(&ud);
            return -1;
        }
        set_error("unexpected session event %d during FTAM exchange", ev);
        buf_free(&ud);
        return -1;
    }
    buf_free(&ud);
    *out = fc->qhead;
    fc->qhead = fc->qhead->next;
    if (!fc->qhead)
        fc->qtail = NULL;
    return 0;
}

/* Receive the next FTAM PDU; caller frees *holder. */
static int recv_pdu(ftam_conn *fc, item_q **holder, ber_tlv *pdu)
{
    ber_rd r;
    *holder = NULL;
    if (next_item(fc, holder) < 0)
        return -1;
    if ((*holder)->ctx != fc->ctx[CTX_PCI].id) {
        set_error("unexpected data value (presentation context %d)", (*holder)->ctx);
        free(*holder);
        *holder = NULL;
        return -1;
    }
    ber_rd_init(&r, (*holder)->data, (*holder)->len);
    if (ber_next(&r, pdu) <= 0 || T_CLASS(pdu->tag) != 0x80) {
        set_error("malformed FTAM PDU");
        free(*holder);
        *holder = NULL;
        return -1;
    }
    log_msg(LOG_INFO, L, "<- %s", ftam_pdu_name(T_TAGNUM(pdu->tag)));
    return 0;
}

static int expect_pdu(ftam_conn *fc, unsigned tag, item_q **holder, ber_tlv *pdu)
{
    if (recv_pdu(fc, holder, pdu) < 0)
        return -1;
    if (T_TAGNUM(pdu->tag) != tag) {
        set_error("protocol error: expected %s, received %s",
                  ftam_pdu_name(tag), ftam_pdu_name(T_TAGNUM(pdu->tag)));
        free(*holder);
        *holder = NULL;
        return -1;
    }
    return 0;
}

/* ---- sending ----------------------------------------------------------- */

static int send_pdu(ftam_conn *fc, const buf_t *pdu)
{
    buf_t ud;
    ber_rd r;
    ber_tlv t;
    buf_init(&ud);
    ber_rd_init(&r, pdu->data, pdu->len);
    if (ber_next(&r, &t) > 0)
        log_msg(LOG_INFO, L, "-> %s", ftam_pdu_name(T_TAGNUM(t.tag)));
    pres_user_data(&ud, fc->ctx[CTX_PCI].id, pdu->data, pdu->len);
    int rc = ses_send_data(&fc->ses, ud.data, ud.len);
    buf_free(&ud);
    return rc;
}

/*
 * Several FTAM PDUs in one P-DATA, one PDV-list each.  Grouped requests
 * (F-BEGIN-GROUP ... F-END-GROUP) are sent this way: ISODE, for one,
 * aborts a group that is spread over several P-DATAs.
 */
static int send_pdus(ftam_conn *fc, const buf_t *pdus, int n)
{
    buf_t   ud;
    ber_enc e;
    buf_init(&ud);
    pres_ud_begin(&e, &ud);
    for (int i = 0; i < n; i++) {
        ber_rd  r;
        ber_tlv t;
        ber_rd_init(&r, pdus[i].data, pdus[i].len);
        if (ber_next(&r, &t) > 0)
            log_msg(LOG_INFO, L, "-> %s", ftam_pdu_name(T_TAGNUM(t.tag)));
        pres_ud_pdv(&e, fc->ctx[CTX_PCI].id, pdus[i].data, pdus[i].len);
    }
    pres_ud_end(&e);
    int rc = ses_send_data(&fc->ses, ud.data, ud.len);
    buf_free(&ud);
    return rc;
}

static int send_simple_pdu(ftam_conn *fc, unsigned tag)
{
    buf_t   b;
    ber_enc e;
    buf_init(&b);
    ber_enc_init(&e, &b);
    ber_begin(&e, T_CTXC(tag));
    ber_end(&e);
    int rc = send_pdu(fc, &b);
    buf_free(&b);
    return rc;
}

/* ---- PDU builders ------------------------------------------------------ */

static void enc_filename(ber_enc *e, const char *name)
{
    ber_begin(e, T_CTXC(0));                    /* Filename-Attribute */
    ber_str(e, T_GRAPHIC, name);
    ber_end(e);
}

static void pdu_simple(buf_t *b, unsigned tag)
{
    ber_enc e;
    ber_enc_init(&e, b);
    ber_begin(&e, T_CTXC(tag));
    ber_end(&e);
}

static void pdu_select(buf_t *b, const char *name, uint32_t access)
{
    ber_enc e;
    ber_enc_init(&e, b);
    ber_begin(&e, T_CTXC(F_SELECT_RQ));
    ber_begin(&e, FT_SELECT_ATTRS);
    enc_filename(&e, name);
    ber_end(&e);
    ber_bits(&e, FT_ACCESS_REQUEST, access);
    ber_end(&e);
}

static void pdu_create(buf_t *b, const char *name, int override,
                       const contents_type *ct, uint32_t permitted,
                       uint32_t access)
{
    ber_enc e;
    ber_enc_init(&e, b);
    ber_begin(&e, T_CTXC(F_CREATE_RQ));
    if (override)
        ber_int(&e, T_CTX(0), override);
    ber_begin(&e, FT_CREATE_ATTRS);
    enc_filename(&e, name);
    ber_bits(&e, T_CTX(1), permitted);
    ber_begin(&e, T_CTXC(2));
    ftam_enc_contents_type(&e, ct);
    ber_end(&e);
    ber_end(&e);
    ber_bits(&e, FT_ACCESS_REQUEST, access);
    ber_end(&e);
}

static void pdu_open(buf_t *b, uint32_t mode, const contents_type *ct)
{
    ber_enc e;
    ber_enc_init(&e, b);
    ber_begin(&e, T_CTXC(F_OPEN_RQ));
    ber_bits(&e, T_CTX(0), mode);
    ber_begin(&e, T_CTXC(1));                   /* contents-type */
    if (ct) {
        ber_begin(&e, T_CTXC(1));               /* proposed */
        ftam_enc_contents_type(&e, ct);
        ber_end(&e);
    } else {
        ber_null(&e, T_CTX(0));                 /* unknown */
    }
    ber_end(&e);
    ber_end(&e);
}

static void enc_fadu_first(ber_enc *e)
{
    ber_begin(e, FT_FADU_IDENTITY);
    ber_int(e, T_CTX(0), 0);                    /* first-last: first */
    ber_end(e);
}

static void pdu_read(buf_t *b, int access_context)
{
    ber_enc e;
    ber_enc_init(&e, b);
    ber_begin(&e, T_CTXC(F_READ_RQ));
    enc_fadu_first(&e);
    ber_begin(&e, FT_ACCESS_CONTEXT);
    ber_int(&e, T_CTX(0), access_context);
    ber_end(&e);
    ber_end(&e);
}

static void pdu_write(buf_t *b, int op)
{
    ber_enc e;
    ber_enc_init(&e, b);
    ber_begin(&e, T_CTXC(F_WRITE_RQ));
    ber_int(&e, T_CTX(0), op);
    enc_fadu_first(&e);
    ber_end(&e);
}

static void pdu_read_attrib(buf_t *b, uint32_t names)
{
    ber_enc e;
    ber_enc_init(&e, b);
    ber_begin(&e, T_CTXC(F_READ_ATTRIB_RQ));
    ber_bits(&e, T_CTX(0), names);
    ber_end(&e);
}

static void pdu_change_attrib(buf_t *b, const char *newname)
{
    ber_enc e;
    ber_enc_init(&e, b);
    ber_begin(&e, T_CTXC(F_CHANGE_ATTRIB_RQ));
    ber_begin(&e, FT_CHANGE_ATTRS);
    enc_filename(&e, newname);
    ber_end(&e);
    ber_end(&e);
}

/* ---- grouping ---------------------------------------------------------- */

typedef int (*resp_fn)(void *arg, unsigned tag, const ber_tlv *pdu);

typedef struct {
    int     got[64];
    int     ok[64];
    char    err[1024];
    long    err_id;             /* ISO 8571 error of the first failure */
    resp_fn on_resp;
    void   *arg;
} group_res;

static void note_result(group_res *gr, unsigned tag, const ber_tlv *pdu)
{
    if (tag >= 64)
        return;
    gr->got[tag] = 1;
    gr->ok[tag] = ftam_check_result(pdu, ftam_pdu_name(tag - 1)) == 0;
    if (!gr->ok[tag] && !gr->err[0]) {
        snprintf(gr->err, sizeof gr->err, "%s", get_error());
        gr->err_id = ftam_first_diag_id(pdu);
    }
    if (gr->ok[tag] && gr->on_resp)
        gr->on_resp(gr->arg, tag, pdu);
}

/*
 * Send a set of requests, as an FTAM group if the grouping functional
 * unit is in effect, otherwise one by one (stopping at the first
 * failure).  Returns 0 if all succeeded, -1 on failure (details in gr),
 * -2 on a fatal (association level) error.
 */
static int run_group(ftam_conn *fc, buf_t *reqs, int n, group_res *gr)
{
    item_q *h;
    ber_tlv pdu;

    memset(gr->got, 0, sizeof gr->got);
    memset(gr->ok, 0, sizeof gr->ok);
    gr->err[0] = 0;
    gr->err_id = -1;

    if (fc->fu & FU_GROUPING) {
        /* the whole group in one P-DATA */
        buf_t   all[8];
        ber_enc e;
        int     k = 0;
        if (n > 6) {
            set_error("internal: group of %d requests", n);
            return -2;
        }
        buf_init(&all[k]);
        ber_enc_init(&e, &all[k]);
        ber_begin(&e, T_CTXC(F_BEGIN_GROUP_RQ));
        ber_int(&e, T_CTX(0), n);               /* threshold */
        ber_end(&e);
        k++;
        for (int i = 0; i < n; i++)
            all[k++] = reqs[i];                 /* shallow: not freed here */
        buf_init(&all[k]);
        ber_enc_init(&e, &all[k]);
        ber_begin(&e, T_CTXC(F_END_GROUP_RQ));
        ber_end(&e);
        k++;
        int rc = send_pdus(fc, all, k);
        buf_free(&all[0]);
        buf_free(&all[k - 1]);
        if (rc < 0 || expect_pdu(fc, F_BEGIN_GROUP_RP, &h, &pdu) < 0)
            return -2;
        free(h);
        for (;;) {
            if (recv_pdu(fc, &h, &pdu) < 0)
                return -2;
            unsigned tag = T_TAGNUM(pdu.tag);
            if (tag == F_END_GROUP_RP) {
                free(h);
                break;
            }
            note_result(gr, tag, &pdu);
            free(h);
        }
    } else {
        for (int i = 0; i < n; i++) {
            unsigned rq = reqs[i].data[0] & 0x1f;
            if (send_pdu(fc, &reqs[i]) < 0 ||
                expect_pdu(fc, rq + 1, &h, &pdu) < 0)
                return -2;
            note_result(gr, rq + 1, &pdu);
            free(h);
            if (!gr->ok[rq + 1])
                break;
        }
    }
    if (gr->err[0]) {
        set_error("%s", gr->err);
        return -1;
    }
    return 0;
}

/* Run a group built from up to 3 requests. */
static int group3(ftam_conn *fc, group_res *gr, buf_t *a, buf_t *b, buf_t *c)
{
    buf_t reqs[3];
    int   n = 0;
    if (a) reqs[n++] = *a;
    if (b) reqs[n++] = *b;
    if (c) reqs[n++] = *c;
    return run_group(fc, reqs, n, gr);
}

/* Terminate the selection regime (after a failure). Keeps last error. */
static int deselect(ftam_conn *fc)
{
    char      saved[1024];
    group_res gr = { .on_resp = NULL };
    buf_t     b;
    snprintf(saved, sizeof saved, "%s", get_error());
    buf_init(&b);
    pdu_simple(&b, F_DESELECT_RQ);
    int rc = group3(fc, &gr, &b, NULL, NULL);
    buf_free(&b);
    set_error("%s", saved);
    return rc == -2 ? -2 : 0;
}

/* F-CLOSE + F-DESELECT. */
static int close_and_deselect(ftam_conn *fc)
{
    group_res gr = { .on_resp = NULL };
    buf_t     a, b;
    buf_init(&a);
    buf_init(&b);
    pdu_simple(&a, F_CLOSE_RQ);
    pdu_simple(&b, F_DESELECT_RQ);
    int rc = group3(fc, &gr, &a, &b, NULL);
    if (rc == -1 && gr.ok[F_CLOSE_RP] && !gr.got[F_DESELECT_RP])
        rc = deselect(fc);
    buf_free(&a);
    buf_free(&b);
    return rc;
}

/* ---- association ------------------------------------------------------- */

static void build_finit(buf_t *b, const ftam_opts *o)
{
    ber_enc e;
    ber_enc_init(&e, b);
    ber_begin(&e, T_CTXC(F_INITIALIZE_RQ));
    ber_bits(&e, T_CTX(0), o->propose_v2 ? PV_VERSION_1 | PV_VERSION_2
                                         : PV_VERSION_1);
    if (o->impl_pad) {
        /* test hook: long implementation-information, used to exercise
         * the session connect data overflow procedure */
        char *s = xmalloc(o->impl_pad + 16);
        size_t n = (size_t)snprintf(s, 16, "TELEXFER 1.0 ");
        memset(s + n, 'x', o->impl_pad);
        s[n + o->impl_pad] = 0;
        ber_str(&e, T_CTX(1), s);
        free(s);
    } else {
        ber_str(&e, T_CTX(1), "TELEXFER 1.0");  /* implementation-information */
    }
    ber_bits(&e, T_CTX(3), o->service_class);
    ber_bits(&e, T_CTX(4), o->functional_units | (o->propose_v2 ? FU_LIMITED_FS : 0));
    ber_bits(&e, T_CTX(5), o->attribute_groups);
    ber_int(&e, T_CTX(6), 0);                   /* QoS: no-recovery */
    ber_begin(&e, T_CTXC(7));                   /* contents-type-list */
    ber_oid(&e, FT_DOC_TYPE_NAME, OID_FTAM_1);
    ber_oid(&e, FT_DOC_TYPE_NAME, OID_FTAM_3);
    ber_oid(&e, FT_DOC_TYPE_NAME, OID_NBS9_DOC);
    ber_end(&e);
    if (o->user)
        ber_str(&e, FT_USER_IDENTITY, o->user);
    if (o->account)
        ber_str(&e, FT_ACCOUNT, o->account);
    if (o->password) {
        ber_begin(&e, FT_PASSWORD);
        ber_str(&e, T_GRAPHIC, o->password);
        ber_end(&e);
    }
    ber_end(&e);
}

static void log_bits(const char *what, uint32_t m, const char *const *names, int n)
{
    char buf[512];
    size_t pos = 0;
    buf[0] = 0;
    for (int i = 0; i < n && pos < sizeof buf; i++)
        if (m & (1u << i) && names[i][0])
            pos += (size_t)snprintf(buf + pos, sizeof buf - pos, "%s%s",
                                    pos ? "," : "", names[i]);
    log_msg(LOG_INFO, L, "%s: %s", what, pos ? buf : "(none)");
}

static int check_finit_rp(ftam_conn *fc, const acse_apdu *a)
{
    if (!a->has_user || a->user.tag != T_CTXC(F_INITIALIZE_RP))
        return 1;                               /* nothing to check */
    const ber_tlv *p = &a->user;
    log_msg(LOG_INFO, L, "<- F-INITIALIZE-response");
    if (ftam_check_result(p, "F-INITIALIZE") < 0)
        return -1;
    ber_tlv t;
    fc->version = PV_VERSION_1;                 /* DEFAULT {version-1} */
    if (ber_find(p, T_CTX(0), &t))
        ber_get_bits(&t, &fc->version);
    if (ber_find(p, T_CTX(3), &t))
        ber_get_bits(&t, &fc->service_class);
    if (ber_find(p, T_CTX(4), &t))
        ber_get_bits(&t, &fc->fu);
    fc->attr_groups = 0;
    if (ber_find(p, T_CTX(5), &t))
        ber_get_bits(&t, &fc->attr_groups);
    static const char *const sc[] = {
        "unconstrained", "management", "transfer", "transfer-and-management", "access" };
    static const char *const fu[] = {
        "", "", "read", "write", "file-access", "limited-file-management",
        "enhanced-file-management", "grouping", "fadu-locking", "recovery",
        "restart-data-transfer", "limited-filestore-management" };
    static const char *const pv[] = { "version-1", "version-2" };
    static const char *const ag[] = { "storage", "security", "private" };
    log_bits("service class", fc->service_class, sc, 5);
    log_bits("protocol version", fc->version, pv, 2);
    log_bits("functional units", fc->fu, fu, 12);
    log_bits("attribute groups", fc->attr_groups, ag, 3);
    return 0;
}

int ftam_connect(ftam_conn *fc, const ftam_opts *o)
{
    memset(fc, 0, sizeof *fc);
    fc->fd = -1;
    fc->vc.fd = -1;
    fc->tpkt.fd = -1;
    fc->chunk_size = o->chunk_size ? o->chunk_size : 4096;
    fc->ctx[CTX_ACSE] = (pctx_t){ 1, OID_ACSE_AS, -1 };
    fc->ctx[CTX_PCI] = (pctx_t){ 3, OID_FTAM_PCI, -1 };
    fc->ctx[CTX_TEXT] = (pctx_t){ 5, OID_FTAM_UNSTR_TEXT, -1 };
    fc->ctx[CTX_BIN] = (pctx_t){ 7, OID_FTAM_UNSTR_BIN, -1 };
    fc->ctx[CTX_NBS9] = (pctx_t){ 9, OID_NBS9_AS, -1 };

    fc->fd = tcp_connect(o->host, o->port, o->timeout_ms);
    if (fc->fd < 0)
        return -1;
    fc->pdv_mode = o->pdv_mode;
    acse_set_user_encoding(o->acse_encoding);
    pres_set_segment(o->pdv_segment);
    if (o->pcap_path) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        uint16_t  lport = 40000;
        if (getsockname(fc->fd, (struct sockaddr *)&ss, &sl) == 0) {
            if (ss.ss_family == AF_INET)
                lport = ntohs(((struct sockaddr_in *)&ss)->sin_port);
            else if (ss.ss_family == AF_INET6)
                lport = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
        }
        if (trace_open(&fc->trace, o->pcap_path, lport, (uint16_t)o->port) == 0)
            fc->tracing = 1;
        else
            log_msg(LOG_ERROR, L, "cannot open pcap file %s", o->pcap_path);
    }
    net_conn net;
    if (o->transport == TRANSPORT_RFC1006) {
        /* no network connection establishment: TCP is up, TP0 goes next */
        tpkt_init(&fc->tpkt, fc->fd, o->timeout_ms, fc->tracing ? &fc->trace : NULL);
        fc->fd = -1;                            /* owned by tpkt now */
        net = tpkt_net(&fc->tpkt);
        log_msg(LOG_INFO, L, "transport: RFC 1006 (TPKT over TCP)");
    } else {
        if (x25_call(&fc->vc, fc->fd, &o->x25, o->timeout_ms,
                     fc->tracing ? &fc->trace : NULL) < 0)
            return -1;
        fc->fd = -1;                            /* owned by vc now */
        net = x25_net(&fc->vc);
        fc->vc.test_drop = o->test_drop;
        if (o->interrupt_len &&
            x25_interrupt(&fc->vc, o->interrupt_data, o->interrupt_len) < 0)
            goto fail;
        if (o->qdata_len &&
            x25_send_qualified(&fc->vc, o->qdata, o->qdata_len) < 0)
            goto fail;
    }

    if (tp0_connect(&fc->tc, net, o->tsel_calling, o->tsel_calling_len,
                    o->tsel_called, o->tsel_called_len, o->tpdu_size) < 0)
        goto fail;

    buf_t finit, aarq, cp, resp;
    buf_init(&finit);
    buf_init(&aarq);
    buf_init(&cp);
    buf_init(&resp);
    build_finit(&finit, o);
    acse_build_aarq(&aarq, &o->acse, fc->ctx[CTX_PCI].id, finit.data, finit.len);
    pres_build_cp(&cp, o->psel_calling, o->psel_calling_len,
                  o->psel_called, o->psel_called_len,
                  fc->ctx, CTX_COUNT, fc->ctx[CTX_ACSE].id, aarq.data, aarq.len);
    log_msg(LOG_INFO, L, "-> F-INITIALIZE-request (A-ASSOCIATE, P-CONNECT)");
    int reason = -1;
    ses_params sp = { .tsdu_max = o->tsdu_size, .ext_concat = o->ext_concat };
    int rc = ses_connect(&fc->ses, &fc->tc, o->ssel_calling, o->ssel_calling_len,
                         o->ssel_called, o->ssel_called_len,
                         cp.data, cp.len, &sp, &resp, &reason);
    buf_free(&finit);
    buf_free(&aarq);
    buf_free(&cp);

    if (rc < 0) {
        buf_free(&resp);
        goto fail;
    }

    ber_tlv   apdu;
    int       has = 0;
    acse_apdu a;
    buf_t     hold;         /* keeps the ACSE APDU for the rest of connect */
    buf_init(&hold);
    memset(&a, 0, sizeof a);
    if (rc == 1) {                              /* session refused */
        char sesmsg[512];
        snprintf(sesmsg, sizeof sesmsg, "%s", get_error());
        int preason = -1;
        if (resp.len && pres_parse_cpr(resp.data, resp.len, &preason, &hold, &apdu, &has) == 0) {
            if (has && acse_parse(&apdu, &a) == 0) {
                if (check_finit_rp(fc, &a) < 0) {
                    char m[1024];
                    snprintf(m, sizeof m, "%s", get_error());
                    set_error("association rejected: %s", m);
                } else {
                    set_error("association rejected by peer ACSE: %s",
                              acse_diag_str(a.diag_source, a.diag));
                }
            } else if (preason >= 0) {
                set_error("presentation connection refused: %s",
                          pres_provider_reason(preason));
            } else {
                set_error("%s", sesmsg);
            }
        }
        buf_free(&resp);
        buf_free(&hold);
        acse_free(&a);
        goto fail;
    }

    if (pres_parse_cpa(resp.data, resp.len, fc->ctx, CTX_COUNT, &hold, &apdu, &has) < 0 || !has) {
        if (!has)
            set_error("presentation: CPA without ACSE response");
        buf_free(&resp);
        buf_free(&hold);
        acse_free(&a);
        goto fail;
    }
    for (int i = 0; i < CTX_COUNT; i++)
        log_msg(LOG_INFO, "pres", "context %d (%s): %s", fc->ctx[i].id,
                fc->ctx[i].abstract,
                fc->ctx[i].result == 0 ? "accepted" :
                fc->ctx[i].result == 1 ? "user-rejection" :
                fc->ctx[i].result == 2 ? "provider-rejection" : "no result");
    if (acse_parse(&apdu, &a) < 0 || a.tag != T_APPC(1)) {
        set_error("ACSE: expected AARE");
        buf_free(&resp);
        buf_free(&hold);
        acse_free(&a);
        goto fail;
    }
    if (a.result != 0) {
        char m[1024] = "";
        if (check_finit_rp(fc, &a) < 0)
            snprintf(m, sizeof m, ": %s", get_error());
        set_error("association rejected (%s, %s)%s",
                  a.result == 1 ? "permanent" : "transient",
                  acse_diag_str(a.diag_source, a.diag), m);
        buf_free(&resp);
        buf_free(&hold);
        acse_free(&a);
        /* the peer has refused; the transport is going away anyway */
        goto fail;
    }
    rc = check_finit_rp(fc, &a);
    buf_free(&resp);
    buf_free(&hold);
    acse_free(&a);
    if (rc > 0) {
        set_error("AARE carries no F-INITIALIZE-response");
        goto fail;
    }
    if (rc < 0)
        goto fail_abort;
    if (fc->ctx[CTX_PCI].result != 0) {
        set_error("FTAM PCI presentation context was rejected");
        goto fail_abort;
    }
    fc->associated = 1;
    return 0;

fail_abort:
    fc->associated = 1;
    ftam_abort(fc);
    return -1;
fail:
    tp0_disconnect(&fc->tc);
    return -1;
}

/* ---- data transfer ----------------------------------------------------- */

static int is_string_tag(uint32_t tag)
{
    if (T_CLASS(tag) != 0)
        return 0;
    unsigned n = T_TAGNUM(tag);
    return n == 4 || n == 12 || (n >= 18 && n <= 22) || (n >= 25 && n <= 30);
}

/* Called for each data value of a read; returns -1 on a local failure
 * (with the error set), which fails the transfer but still completes it
 * at protocol level. */
typedef int (*data_fn)(void *arg, int ctx, const ber_tlv *value);

/* File contents: strings written to a stdio stream. */
typedef struct {
    FILE      *out;
    int        text;
    long long *bytes;
    buf_t      s;
    buf_t      conv;            /* text: CR LF -> LF */
    int        pending_cr;
} file_sink;

/*
 * FTAM-1: whether a string carries its own line ends follows from its
 * type.  GraphicString, PrintableString and VisibleString cannot contain
 * control characters, so each one is a line; GeneralString, IA5String,
 * T61String and VideotexString carry format effectors (CR, LF) inside.
 * This is also how ISODE's responder reads and writes text files.
 */
static int is_line_string(uint32_t tag)
{
    return tag == T_GRAPHIC || tag == T_PRINTABLE || tag == T_VISIBLE;
}

static int write_value(void *arg, int ctx, const ber_tlv *v)
{
    file_sink *fs = arg;
    (void)ctx;
    if (!is_string_tag(v->tag)) {
        log_msg(LOG_INFO, L, "skipping non-string data element");
        return 0;
    }
    buf_reset(&fs->s);
    ber_get_string(v, &fs->s);
    buf_t *data = &fs->s;
    int    line = fs->text && is_line_string(v->tag & ~BER_TAG(0x20, 0));
    if (fs->text && !line) {
        /* line ends travel as CR LF: back to the local LF */
        buf_reset(&fs->conv);
        text_from_crlf(fs->s.data, fs->s.len, &fs->conv, &fs->pending_cr);
        data = &fs->conv;
    }
    if (data->len && fwrite(data->data, 1, data->len, fs->out) != data->len) {
        set_error("local write error");
        return -1;
    }
    *fs->bytes += (long long)data->len;
    if (line) {
        fputc('\n', fs->out);
        (*fs->bytes)++;
    }
    return 0;
}

/* cancel_id (may be NULL): error-identifier of a responder's F-CANCEL */
static int read_transfer(ftam_conn *fc, int access_context, data_fn fn, void *arg,
                         long *cancel_id)
{
    buf_t   b;
    item_q *h;
    ber_tlv pdu;
    int     failed = 0;
    char    saved[1024] = "";

    buf_init(&b);
    pdu_read(&b, access_context);
    int rc = send_pdu(fc, &b);
    buf_free(&b);
    if (rc < 0)
        return -2;

    for (;;) {
        if (next_item(fc, &h) < 0)
            return -2;
        if (h->ctx != fc->ctx[CTX_PCI].id) {
            ber_rd  r;
            ber_tlv v;
            ber_rd_init(&r, h->data, h->len);
            if (ber_next(&r, &v) > 0 && fn(arg, h->ctx, &v) < 0 && !failed) {
                failed = 1;
                snprintf(saved, sizeof saved, "%s", get_error());
            }
            free(h);
            continue;
        }
        ber_rd r;
        ber_rd_init(&r, h->data, h->len);
        if (ber_next(&r, &pdu) <= 0) {
            free(h);
            set_error("malformed FTAM PDU during transfer");
            return -2;
        }
        unsigned tag = T_TAGNUM(pdu.tag);
        log_msg(LOG_INFO, L, "<- %s", ftam_pdu_name(tag));
        if (tag == F_DATA_END_RQ) {
            if (ftam_check_result(&pdu, "data transfer") < 0 && !failed) {
                failed = 1;
                snprintf(saved, sizeof saved, "%s", get_error());
            }
            free(h);
            break;
        }
        if (tag == F_CANCEL_RQ) {
            char d[1024];
            ftam_fmt_diagnostic(&pdu, d, sizeof d);
            if (cancel_id)
                *cancel_id = ftam_first_diag_id(&pdu);
            free(h);
            send_simple_pdu(fc, F_CANCEL_RP);
            set_error("transfer cancelled by responder%s%s", d[0] ? ": " : "", d);
            return -1;
        }
        free(h);
        set_error("protocol error: unexpected %s during read", ftam_pdu_name(tag));
        return -2;
    }

    if (send_simple_pdu(fc, F_TRANSFER_END_RQ) < 0 ||
        expect_pdu(fc, F_TRANSFER_END_RP, &h, &pdu) < 0)
        return -2;
    if (ftam_check_result(&pdu, "F-TRANSFER-END") < 0 && !failed) {
        failed = 1;
        snprintf(saved, sizeof saved, "%s", get_error());
    }
    free(h);
    if (failed) {
        set_error("%s", saved);
        return -1;
    }
    return 0;
}

/* Flush the pending data elements as one P-DATA. */
static int flush_data(ftam_conn *fc, ber_enc *e, buf_t *ud, int *pending)
{
    if (!*pending)
        return 0;
    pres_ud_end(e);
    int rc = ses_send_data(&fc->ses, ud->data, ud->len);
    buf_reset(ud);
    *pending = 0;
    return rc;
}

/* Send the pending values as one octet-aligned or arbitrary PDV in one
 * P-DATA. */
static int flush_octets(ftam_conn *fc, int ctx, buf_t *vals)
{
    buf_t   ud;
    ber_enc e;
    if (!vals->len)
        return 0;
    buf_init(&ud);
    pres_ud_begin(&e, &ud);
    pres_ud_pdv_enc(&e, ctx, fc->pdv_mode, vals->data, vals->len);
    pres_ud_end(&e);
    int rc = ses_send_data(&fc->ses, ud.data, ud.len);
    buf_free(&ud);
    buf_reset(vals);
    return rc;
}

static int write_transfer(ftam_conn *fc, FILE *in, int text, int op,
                          long long *bytes)
{
    buf_t   b, ud, elem, vals;
    ber_enc e, ee;
    item_q *h;
    ber_tlv pdu;
    int     ctx = fc->ctx[text ? CTX_TEXT : CTX_BIN].id;
    int     pending = 0;
    int     rc = 0;

    buf_init(&b);
    pdu_write(&b, op);
    rc = send_pdu(fc, &b);
    buf_free(&b);
    if (rc < 0)
        return -2;

    buf_t crlf;
    int   prev = 0;
    buf_init(&ud);
    buf_init(&elem);
    buf_init(&vals);
    buf_init(&crlf);
    uint8_t *chunk = xmalloc(fc->chunk_size);
    for (;;) {
        buf_reset(&elem);
        ber_enc_init(&ee, &elem);
        if (text) {
            /* GeneralString with the line ends inside, as CR LF */
            size_t n = fread(chunk, 1, fc->chunk_size, in);
            if (n == 0)
                break;
            *bytes += (long long)n;
            buf_reset(&crlf);
            text_to_crlf(chunk, n, &crlf, &prev);
            ber_prim(&ee, T_GENERAL, crlf.data, crlf.len);
        } else {
            size_t n = fread(chunk, 1, fc->chunk_size, in);
            if (n == 0)
                break;
            *bytes += (long long)n;
            ber_prim(&ee, T_OCTETS, chunk, n);
        }
        if (fc->pdv_mode != PDV_SINGLE) {
            if (vals.len && vals.len + elem.len > fc->chunk_size + 64)
                if ((rc = flush_octets(fc, ctx, &vals)) < 0)
                    break;
            buf_put(&vals, elem.data, elem.len);
            if (vals.len >= fc->chunk_size)
                if ((rc = flush_octets(fc, ctx, &vals)) < 0)
                    break;
            continue;
        }
        if (pending && ud.len + elem.len > fc->chunk_size + 64)
            if ((rc = flush_data(fc, &e, &ud, &pending)) < 0)
                break;
        if (!pending) {
            pres_ud_begin(&e, &ud);
            pending = 1;
        }
        pres_ud_pdv(&e, ctx, elem.data, elem.len);
        if (ud.len >= fc->chunk_size)
            if ((rc = flush_data(fc, &e, &ud, &pending)) < 0)
                break;
    }
    if (rc == 0)
        rc = flush_data(fc, &e, &ud, &pending);
    if (rc == 0)
        rc = flush_octets(fc, ctx, &vals);
    free(chunk);
    buf_free(&ud);
    buf_free(&elem);
    buf_free(&vals);
    buf_free(&crlf);
    if (rc < 0)
        return -2;
    if (ferror(in)) {
        /* tell the responder the data is incomplete */
        buf_init(&b);
        ber_enc_init(&e, &b);
        ber_begin(&e, T_CTXC(F_CANCEL_RQ));
        ber_int(&e, FT_ACTION_RESULT, 2);
        ber_end(&e);
        rc = send_pdu(fc, &b);
        buf_free(&b);
        if (rc < 0 || expect_pdu(fc, F_CANCEL_RP, &h, &pdu) < 0)
            return -2;
        free(h);
        set_error("local read error; transfer cancelled");
        return -1;
    }

    if (send_simple_pdu(fc, F_DATA_END_RQ) < 0 ||
        send_simple_pdu(fc, F_TRANSFER_END_RQ) < 0)
        return -2;
    if (recv_pdu(fc, &h, &pdu) < 0)
        return -2;
    unsigned tag = T_TAGNUM(pdu.tag);
    if (tag == F_CANCEL_RQ) {
        char d[1024];
        ftam_fmt_diagnostic(&pdu, d, sizeof d);
        free(h);
        send_simple_pdu(fc, F_CANCEL_RP);
        set_error("transfer cancelled by responder%s%s", d[0] ? ": " : "", d);
        return -1;
    }
    if (tag != F_TRANSFER_END_RP) {
        free(h);
        set_error("protocol error: unexpected %s after write", ftam_pdu_name(tag));
        return -2;
    }
    rc = ftam_check_result(&pdu, "F-TRANSFER-END");
    free(h);
    return rc;
}

/* ---- file operations --------------------------------------------------- */

static int require(ftam_conn *fc, uint32_t fu, const char *what)
{
    if (!fc->associated) {
        set_error("not associated");
        return -1;
    }
    if ((fc->fu & fu) != fu) {
        set_error("%s: required functional unit not negotiated with responder", what);
        return -1;
    }
    return 0;
}

static int data_ctx_ok(ftam_conn *fc, int doctype)
{
    int i = doctype == 1 ? CTX_TEXT : doctype == 9 ? CTX_NBS9 : CTX_BIN;
    if (fc->ctx[i].result != 0) {
        set_error("presentation context for %s was not accepted by the responder",
                  doctype == 1 ? "FTAM-1 (text)" : doctype == 9 ?
                  "NBS-9 directory entries" : "FTAM-3 (binary)");
        return 0;
    }
    return 1;
}

static int open_resp(void *arg, unsigned tag, const ber_tlv *pdu)
{
    contents_type *ct = arg;
    ber_tlv        w, in;
    if (tag != F_OPEN_RP || !ber_find(pdu, T_CTXC(1), &w))
        return 0;
    ber_rd r;
    ber_enter(&w, &r);
    if (ber_next(&r, &in) > 0)
        ftam_dec_contents_type(&in, ct);
    return 0;
}

int ftam_get(ftam_conn *fc, const char *remote, FILE *out, int doctype,
             long long *bytes)
{
    contents_type ct = { .doctype = 0, .significance = -1 };
    group_res     gr = { .on_resp = open_resp, .arg = &ct };
    buf_t         sel, opn;
    int           rc;

    *bytes = 0;
    if (require(fc, FU_READ, "read") < 0)
        return -1;
    buf_init(&sel);
    buf_init(&opn);
    pdu_select(&sel, remote, AR_READ);
    pdu_open(&opn, PM_READ, NULL);
    rc = group3(fc, &gr, &sel, &opn, NULL);
    buf_free(&sel);
    buf_free(&opn);
    if (rc == -2)
        return -1;
    if (!gr.ok[F_SELECT_RP])
        return -1;
    if (!gr.ok[F_OPEN_RP]) {
        deselect(fc);
        return -1;
    }
    if (ct.doctype == 0)
        ct.doctype = doctype;
    log_msg(LOG_INFO, L, "file contents type: %s", ct.doctype == 1 ? "FTAM-1" :
            ct.doctype == 3 ? "FTAM-3" : ct.oid);
    if (!data_ctx_ok(fc, ct.doctype)) {
        close_and_deselect(fc);
        return -1;
    }

    file_sink fs = { .out = out, .text = ct.doctype == 1, .bytes = bytes };
    buf_init(&fs.s);
    buf_init(&fs.conv);
    rc = read_transfer(fc, AC_UNSTRUCTURED_ALL, write_value, &fs, NULL);
    if (fs.pending_cr) {                        /* the file ended in a lone CR */
        fputc('\r', out);
        (*bytes)++;
    }
    buf_free(&fs.s);
    buf_free(&fs.conv);
    if (rc == -2)
        return -1;
    char saved[1024];
    snprintf(saved, sizeof saved, "%s", get_error());
    int crc = close_and_deselect(fc);
    if (rc < 0) {
        set_error("%s", saved);
        return -1;
    }
    return crc < 0 ? -1 : 0;
}

int ftam_put(ftam_conn *fc, FILE *in, const char *remote, int doctype,
             int override, int append, long long *bytes)
{
    contents_type ct = { .doctype = doctype, .universal_class = -1,
                         .max_string_length = -1, .significance = -1 };
    group_res     gr = { .on_resp = NULL };
    buf_t         cre, opn;
    int           rc;

    *bytes = 0;
    if (require(fc, FU_WRITE | FU_LIMITED_MGMT, "write") < 0)
        return -1;
    if (!data_ctx_ok(fc, doctype))
        return -1;
    if (doctype == 1) {
        /* GeneralString, line ends in the data: what ISODE uses too */
        ct.universal_class = 27;
        ct.significance = SS_NOT_SIGNIFICANT;
    } else {
        ct.significance = SS_NOT_SIGNIFICANT;
    }
    if (append && override == OVR_CREATE_FAILURE)
        override = OVR_SELECT_OLD;

    uint32_t permitted = AR_READ | AR_REPLACE | AR_EXTEND | AR_ERASE |
                         AR_READ_ATTR | AR_CHANGE_ATTR | AR_DELETE | PA_TRAVERSAL;
    uint32_t access = append ? AR_EXTEND : AR_REPLACE;
    buf_init(&cre);
    buf_init(&opn);
    pdu_create(&cre, remote, override, &ct, permitted, access);
    pdu_open(&opn, append ? PM_EXTEND : PM_REPLACE, &ct);
    rc = group3(fc, &gr, &cre, &opn, NULL);
    buf_free(&cre);
    buf_free(&opn);
    if (rc == -2)
        return -1;
    if (!gr.ok[F_CREATE_RP])
        return -1;
    if (!gr.ok[F_OPEN_RP]) {
        deselect(fc);
        return -1;
    }

    rc = write_transfer(fc, in, doctype == 1,
                        append ? FADU_OP_EXTEND : FADU_OP_REPLACE, bytes);
    if (rc == -2)
        return -1;
    char saved[1024];
    snprintf(saved, sizeof saved, "%s", get_error());
    int crc = close_and_deselect(fc);
    if (rc < 0) {
        set_error("%s", saved);
        return -1;
    }
    return crc < 0 ? -1 : 0;
}

int ftam_delete(ftam_conn *fc, const char *remote)
{
    group_res gr = { .on_resp = NULL };
    buf_t     sel, del;

    if (require(fc, FU_LIMITED_MGMT, "delete") < 0)
        return -1;
    buf_init(&sel);
    buf_init(&del);
    pdu_select(&sel, remote, AR_DELETE);
    pdu_simple(&del, F_DELETE_RQ);
    int rc = group3(fc, &gr, &sel, &del, NULL);
    buf_free(&sel);
    buf_free(&del);
    if (rc == -1 && gr.ok[F_SELECT_RP] && !gr.ok[F_DELETE_RP])
        deselect(fc);
    return rc < 0 ? -1 : 0;
}

static int attr_resp(void *arg, unsigned tag, const ber_tlv *pdu)
{
    FILE   *out = arg;
    ber_tlv attrs;
    if (tag == F_READ_ATTRIB_RP && ber_find(pdu, FT_READ_ATTRS, &attrs))
        ftam_print_attributes(out, &attrs);
    return 0;
}

int ftam_attributes(ftam_conn *fc, const char *remote, FILE *out)
{
    group_res gr = { .on_resp = attr_resp, .arg = out };
    buf_t     sel, rd, des;

    if (require(fc, FU_LIMITED_MGMT, "read attributes") < 0)
        return -1;
    /* kernel attributes + whatever groups were negotiated */
    uint32_t names = 0x7;                       /* filename, actions, contents */
    if (fc->attr_groups & AG_STORAGE)
        names |= 0x7ff8;                        /* bits 3..14 */
    if (fc->attr_groups & AG_SECURITY)
        names |= (1u << 15) | (1u << 16);
    if (fc->attr_groups & AG_PRIVATE)
        names |= 1u << 17;
    buf_init(&sel);
    buf_init(&rd);
    buf_init(&des);
    pdu_select(&sel, remote, AR_READ_ATTR);
    pdu_read_attrib(&rd, names);
    pdu_simple(&des, F_DESELECT_RQ);
    fprintf(out, "%s:\n", remote);
    int rc = group3(fc, &gr, &sel, &rd, &des);
    buf_free(&sel);
    buf_free(&rd);
    buf_free(&des);
    if (rc == -1 && gr.ok[F_SELECT_RP] && !gr.ok[F_DESELECT_RP])
        deselect(fc);
    return rc < 0 ? -1 : 0;
}

int ftam_rename(ftam_conn *fc, const char *from, const char *to)
{
    group_res gr = { .on_resp = NULL };
    buf_t     sel, chg, des;

    if (require(fc, FU_ENHANCED_MGMT, "rename") < 0)
        return -1;
    buf_init(&sel);
    buf_init(&chg);
    buf_init(&des);
    pdu_select(&sel, from, AR_CHANGE_ATTR);
    pdu_change_attrib(&chg, to);
    pdu_simple(&des, F_DESELECT_RQ);
    int rc = group3(fc, &gr, &sel, &chg, &des);
    buf_free(&sel);
    buf_free(&chg);
    buf_free(&des);
    if (rc == -1 && gr.ok[F_SELECT_RP] && !gr.ok[F_DESELECT_RP])
        deselect(fc);
    return rc < 0 ? -1 : 0;
}

/* ---- file status ---------------------------------------------------------- */

static int stat_resp(void *arg, unsigned tag, const ber_tlv *pdu)
{
    ftam_dirent *e = arg;
    ber_tlv      attrs;
    if (tag == F_READ_ATTRIB_RP && ber_find(pdu, FT_READ_ATTRS, &attrs))
        ftam_parse_dirent(&attrs, e);
    return 0;
}

int ftam_stat(ftam_conn *fc, const char *remote, ftam_dirent *info)
{
    group_res gr = { .on_resp = stat_resp, .arg = info };
    buf_t     sel, rd, des;

    memset(info, 0, sizeof *info);
    info->size = -1;
    if (!fc->associated) {
        set_error("not associated");
        return -1;
    }
    if (!(fc->fu & FU_LIMITED_MGMT)) {
        /* no F-READ-ATTRIB without limited file management: selecting
         * the file still tells whether it exists (no size, no dates) */
        buf_init(&sel);
        buf_init(&des);
        pdu_select(&sel, remote, AR_READ);
        pdu_simple(&des, F_DESELECT_RQ);
        int rc = group3(fc, &gr, &sel, &des, NULL);
        buf_free(&sel);
        buf_free(&des);
        if (rc == -2)
            return -1;
        if (!gr.ok[F_SELECT_RP])
            return (gr.err_id == 3000 || gr.err_id == 3001 || gr.err_id == 3004) ? 1 : -1;
        snprintf(info->name, sizeof info->name, "%s", remote);
        return 0;
    }
    uint32_t names = AN_PATHNAME;
    if (fc->attr_groups & AG_STORAGE)
        names |= AN_CREATED | AN_MODIFIED | AN_SIZE;
    buf_init(&sel);
    buf_init(&rd);
    buf_init(&des);
    pdu_select(&sel, remote, AR_READ_ATTR);
    pdu_read_attrib(&rd, names);
    pdu_simple(&des, F_DESELECT_RQ);
    int rc = group3(fc, &gr, &sel, &rd, &des);
    buf_free(&sel);
    buf_free(&rd);
    buf_free(&des);
    if (rc == -2)
        return -1;
    if (!gr.ok[F_SELECT_RP]) {
        /* "no such file" diagnostics mean absent; anything else is an error */
        if (gr.err_id == 3000 || gr.err_id == 3001 || gr.err_id == 3004)
            return 1;
        return -1;
    }
    if (rc == -1 && !gr.ok[F_DESELECT_RP])
        deselect(fc);
    if (!gr.ok[F_READ_ATTRIB_RP])
        return -1;
    if (!info->name[0])
        snprintf(info->name, sizeof info->name, "%s", remote);
    return 0;
}

/* ---- directory listing -------------------------------------------------- */

typedef struct {
    ftam_dirent *v;
    size_t       n, cap;
} dirent_list;

static void dl_add(dirent_list *l, const ftam_dirent *e)
{
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 64;
        l->v = xrealloc(l->v, l->cap * sizeof *l->v);
    }
    l->v[l->n++] = *e;
}

static int dl_add_value(dirent_list *l, const ber_tlv *v)
{
    ber_tlv     attrs;
    ftam_dirent e;
    if (!ftam_find_attributes(v, &attrs) || ftam_parse_dirent(&attrs, &e) < 0) {
        log_msg(LOG_INFO, L, "skipping directory entry without a filename");
        return 0;
    }
    dl_add(l, &e);
    return 0;
}

static int dirent_cmp(const void *a, const void *b)
{
    return strcmp(((const ftam_dirent *)a)->name, ((const ftam_dirent *)b)->name);
}

/* Attributes worth asking for, given what the responder negotiated. */
static uint32_t list_attr_names(ftam_conn *fc)
{
    uint32_t n = AN_PATHNAME | AN_CONTENTS_TYPE;
    if (fc->attr_groups & AG_STORAGE)
        n |= AN_MODIFIED | AN_SIZE;
    if (fc->version & PV_VERSION_2)
        n |= AN_OBJECT_TYPE;
    return n;
}

static int nbs9_value(void *arg, int ctx, const ber_tlv *v)
{
    (void)ctx;
    return dl_add_value(arg, v);
}

/* Read the directory as an NBS-9 file directory file. */
static int list_nbs9(ftam_conn *fc, const char *dir, dirent_list *l)
{
    contents_type ct = { .doctype = 9, .universal_class = -1,
                         .max_string_length = -1, .significance = -1,
                         .nbs9_names = list_attr_names(fc) };
    group_res     gr = { .on_resp = NULL };
    buf_t         sel, opn;

    if (require(fc, FU_READ, "list") < 0 || !data_ctx_ok(fc, 9))
        return -1;
    buf_init(&sel);
    buf_init(&opn);
    pdu_select(&sel, dir ? dir : ".", AR_READ);
    pdu_open(&opn, PM_READ, &ct);
    int rc = group3(fc, &gr, &sel, &opn, NULL);
    buf_free(&sel);
    buf_free(&opn);
    if (rc == -2 || !gr.ok[F_SELECT_RP])
        return -1;
    if (!gr.ok[F_OPEN_RP]) {
        deselect(fc);
        return -1;
    }
    /* One data element per entry.  ISODE, the reference for NBS-9, only
     * reads directories with unstructured-all-data-units and cancels any
     * other access context (5025); the textbook one for a sequential flat
     * file is flat-all-data-units, tried if UA is refused. */
    long cancel_id = -1;
    rc = read_transfer(fc, AC_UNSTRUCTURED_ALL, nbs9_value, l, &cancel_id);
    if (rc == -1 && cancel_id == 5025) {
        log_msg(LOG_INFO, L, "access context UA refused, reading with FA");
        l->n = 0;
        rc = read_transfer(fc, AC_FLAT_ALL, nbs9_value, l, NULL);
    }
    if (rc == -2)
        return -1;
    char saved[1024];
    snprintf(saved, sizeof saved, "%s", get_error());
    int crc = close_and_deselect(fc);
    if (rc < 0) {
        set_error("%s", saved);
        return -1;
    }
    return crc < 0 ? -1 : 0;
}

/* F-LIST: all objects in dir (not recursive). */
static int list_flist(ftam_conn *fc, const char *dir, dirent_list *l)
{
    buf_t   b;
    ber_enc e;
    item_q *h;
    ber_tlv pdu, objs, obj;

    if (!(fc->version & PV_VERSION_2) || !(fc->fu & FU_LIMITED_FS)) {
        set_error("F-LIST needs FTAM version 2 and limited filestore management, "
                  "which the responder did not grant");
        return -1;
    }
    buf_init(&b);
    ber_enc_init(&e, &b);
    ber_begin(&e, T_CTXC(F_LIST_RQ));
    ber_begin(&e, FT_ATTR_ASSERTIONS);          /* OR-Set */
    ber_begin(&e, T_SEQ);                       /* AND-Set */
    ber_begin(&e, T_CTXC(0));                   /* pathname-Pattern */
    ber_bits(&e, T_CTX(0), 1u << 1);            /* equality: equals-matches */
    ber_begin(&e, T_CTXC(1));                   /* pathname-value */
    ber_null(&e, T_CTX(3));                     /* any-match */
    ber_end(&e);
    ber_end(&e);
    ber_end(&e);
    ber_end(&e);
    ber_begin(&e, FT_SCOPE);
    ber_begin(&e, T_SEQ);
    if (dir) {
        ber_begin(&e, T_CTXC(0));               /* root-directory */
        ber_begin(&e, T_CTXC(0));               /* incomplete-pathname */
        ber_str(&e, T_GRAPHIC, dir);
        ber_end(&e);
        ber_end(&e);
    }
    ber_int(&e, T_CTX(1), 0);                   /* retrieval-scope: child */
    ber_end(&e);
    ber_end(&e);
    ber_bits(&e, T_CTX(0), list_attr_names(fc));
    ber_end(&e);
    int rc = send_pdu(fc, &b);
    buf_free(&b);
    if (rc < 0 || expect_pdu(fc, F_LIST_RP, &h, &pdu) < 0)
        return -1;
    if (ftam_check_result(&pdu, "F-LIST") < 0) {
        free(h);
        return -1;
    }
    if (ber_find(&pdu, FT_OBJECTS_ATTRS, &objs)) {
        ber_rd r;
        ber_enter(&objs, &r);
        while (ber_next(&r, &obj) > 0)
            dl_add_value(l, &obj);
    }
    free(h);
    return 0;
}

/* "20260923201004Z" -> "2026-09-23 20:10" */
static void fmt_time(const char *gt, char *out, size_t max)
{
    if (strlen(gt) >= 12 && strspn(gt, "0123456789") >= 12)
        snprintf(out, max, "%.4s-%.2s-%.2s %.2s:%.2s", gt, gt + 4, gt + 6, gt + 8, gt + 10);
    else
        snprintf(out, max, "%s", gt[0] ? gt : "-");
}

int ftam_list(ftam_conn *fc, const char *dir, int method, int long_format, FILE *out)
{
    dirent_list l = { NULL, 0, 0 };
    int         rc;

    if (!fc->associated) {
        set_error("not associated");
        return -1;
    }
    if (method == LIST_AUTO)
        method = ((fc->version & PV_VERSION_2) && (fc->fu & FU_LIMITED_FS)) ?
                 LIST_FLIST : LIST_NBS9;
    log_msg(LOG_INFO, L, "listing %s with %s", dir ? dir : "current directory",
            method == LIST_FLIST ? "F-LIST" : "NBS-9");
    rc = method == LIST_FLIST ? list_flist(fc, dir, &l) : list_nbs9(fc, dir, &l);
    if (rc == 0 && dir && dir[0] && strcmp(dir, ".") != 0) {
        /* some responders (ISODE) name entries by their path from the
         * home directory: show them relative to the directory listed */
        size_t dl = strlen(dir);
        while (dl > 1 && dir[dl - 1] == '/')
            dl--;
        for (size_t i = 0; i < l.n; i++) {
            char *nm = l.v[i].name;
            if (strncmp(nm, dir, dl) == 0 && nm[dl] == '/' && nm[dl + 1])
                memmove(nm, nm + dl + 1, strlen(nm + dl + 1) + 1);
        }
    }
    if (rc == 0) {
        qsort(l.v, l.n, sizeof *l.v, dirent_cmp);
        for (size_t i = 0; i < l.n; i++) {
            const ftam_dirent *d = &l.v[i];
            if (!long_format) {
                fprintf(out, "%s%s\n", d->name, d->is_dir ? "/" : "");
                continue;
            }
            char when[32], size[32];
            fmt_time(d->mtime, when, sizeof when);
            if (d->size >= 0)
                snprintf(size, sizeof size, "%lld", d->size);
            else
                snprintf(size, sizeof size, "-");
            fprintf(out, "%c %12s  %-16s  %s%s\n", d->is_dir ? 'd' : '-', size, when,
                    d->name, d->is_dir ? "/" : "");
        }
    }
    free(l.v);
    return rc;
}

/* ---- release / abort --------------------------------------------------- */

static void log_charging(const ber_tlv *pdu)
{
    ber_tlv ch, ent;
    ber_rd  r;
    if (!ber_find(pdu, FT_CHARGING, &ch))
        return;
    ber_enter(&ch, &r);
    while (ber_next(&r, &ent) > 0) {
        char    res[128] = "", unit[128] = "";
        long    val = 0;
        ber_tlv f;
        if (ber_find(&ent, T_CTX(0), &f)) ber_get_cstr(&f, res, sizeof res);
        if (ber_find(&ent, T_CTX(1), &f)) ber_get_cstr(&f, unit, sizeof unit);
        if (ber_find(&ent, T_CTX(2), &f)) ber_get_int(&f, &val);
        log_msg(LOG_INFO, L, "charging: %s %ld %s", res, val, unit);
    }
}

/* Copy the first presentation data value into a buffer. */
static int first_value_cb(void *arg, int ctx, const ber_tlv *v)
{
    buf_t *hold = arg;
    (void)ctx;
    if (hold->len == 0)
        buf_put(hold, v->raw, v->rawlen);
    return 0;
}

int ftam_release(ftam_conn *fc)
{
    buf_t term, rlrq, ud;
    int   rc = -1;

    if (!fc->associated)
        return 0;
    buf_init(&term);
    buf_init(&rlrq);
    buf_init(&ud);
    pdu_simple(&term, F_TERMINATE_RQ);
    acse_build_rlrq(&rlrq, fc->ctx[CTX_PCI].id, term.data, term.len);
    pres_user_data(&ud, fc->ctx[CTX_ACSE].id, rlrq.data, rlrq.len);
    log_msg(LOG_INFO, L, "-> F-TERMINATE-request (A-RELEASE)");
    if (ses_finish(&fc->ses, ud.data, ud.len) < 0)
        goto out;
    for (;;) {
        int ev;
        if (ses_recv(&fc->ses, &ev, &ud) < 0)
            goto out;
        if (ev == SES_EV_DATA)
            continue;                           /* stray data, drop */
        if (ev == SES_EV_ABORT) {
            report_abort(fc, &ud);
            goto out;
        }
        if (ev == SES_EV_NOT_FINISHED) {
            set_error("release refused by responder");
            goto out;
        }
        if (ev == SES_EV_DISCONNECT)
            break;
        set_error("unexpected session event %d during release", ev);
        goto out;
    }
    rc = 0;
    if (ud.len) {
        buf_t     hold;
        ber_tlv   apdu;
        acse_apdu a;
        buf_init(&hold);
        memset(&a, 0, sizeof a);
        if (pres_parse_ud(ud.data, ud.len, first_value_cb, &hold) == 0 && hold.len) {
            ber_rd r;
            ber_rd_init(&r, hold.data, hold.len);
            if (ber_next(&r, &apdu) > 0 && acse_parse(&apdu, &a) == 0 &&
                a.tag == T_APPC(3) && a.has_user &&
                a.user.tag == T_CTXC(F_TERMINATE_RP)) {
                log_msg(LOG_INFO, L, "<- F-TERMINATE-response");
                log_charging(&a.user);
            }
        }
        acse_free(&a);
        buf_free(&hold);
    }
out:
    fc->associated = 0;
    tp0_disconnect(&fc->tc);
    buf_free(&term);
    buf_free(&rlrq);
    buf_free(&ud);
    return rc;
}

void ftam_abort(ftam_conn *fc)
{
    buf_t   ab, abrt, aru;
    ber_enc e;

    if (fc->associated) {
        buf_init(&ab);
        buf_init(&abrt);
        buf_init(&aru);
        ber_enc_init(&e, &ab);
        ber_begin(&e, T_CTXC(F_U_ABORT_RQ));
        ber_int(&e, FT_ACTION_RESULT, 2);       /* permanent-error */
        ber_end(&e);
        acse_build_abrt(&abrt, 0, fc->ctx[CTX_PCI].id, ab.data, ab.len);
        pres_build_aru(&aru, fc->ctx[CTX_ACSE].id, abrt.data, abrt.len);
        log_msg(LOG_INFO, L, "-> F-U-ABORT-request (A-ABORT)");
        ses_abort(&fc->ses, aru.data, aru.len);
        buf_free(&ab);
        buf_free(&abrt);
        buf_free(&aru);
        fc->associated = 0;
    }
    tp0_disconnect(&fc->tc);
}

void ftam_close(ftam_conn *fc)
{
    flush_queue(fc);
    ses_free(&fc->ses);
    if (fc->vc.fd >= 0 || fc->vc.state != X25_IDLE)
        x25_close(&fc->vc);
    tpkt_close(&fc->tpkt);
    if (fc->fd >= 0)
        close(fc->fd);
    fc->fd = -1;
    if (fc->tracing)
        trace_close(&fc->trace);
    fc->tracing = 0;
}
