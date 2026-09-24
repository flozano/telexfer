/*
 * ftam_pdu.c - FTAM common type encoders/decoders and diagnostics.
 */
#include "ftam_pdu.h"

#include <string.h>

/* ---- contents type ----------------------------------------------------- */

void ftam_enc_contents_type(ber_enc *e, const contents_type *ct)
{
    ber_begin(e, T_CTXC(0));                    /* document-type */
    ber_oid(e, FT_DOC_TYPE_NAME, ct->oid[0] ? ct->oid :
            ct->doctype == 1 ? OID_FTAM_1 :
            ct->doctype == 9 ? OID_NBS9_DOC : OID_FTAM_3);
    if (ct->doctype == 9) {
        /* NBS-9-Parameters ::= [0] IMPLICIT Attribute-Names: the
         * attributes each directory entry carries */
        if (ct->nbs9_names > 0) {
            ber_begin(e, T_CTXC(0));            /* parameter */
            ber_bits(e, T_CTX(0), (uint32_t)ct->nbs9_names);
            ber_end(e);
        }
    } else if (ct->universal_class >= 0 || ct->max_string_length >= 0 ||
               ct->significance >= 0) {
        ber_begin(e, T_CTXC(0));                /* parameter */
        ber_begin(e, T_SEQ);
        if (ct->doctype == 1 && ct->universal_class >= 0)
            ber_int(e, T_CTX(0), ct->universal_class);
        if (ct->max_string_length >= 0)
            ber_int(e, T_CTX(1), ct->max_string_length);
        if (ct->significance >= 0)
            ber_int(e, T_CTX(2), ct->significance);
        ber_end(e);
        ber_end(e);
    }
    ber_end(e);
}

int ftam_dec_contents_type(const ber_tlv *t, contents_type *ct)
{
    ber_tlv name, param;

    memset(ct, 0, sizeof *ct);
    ct->universal_class = ct->max_string_length = ct->significance = -1;
    ct->nbs9_names = -1;
    if (t->tag == T_CTXC(1)) {                  /* constraint set + AS */
        ber_tlv as;
        if (ber_find(t, FT_ABSTRACT_SYNTAX, &as))
            ber_get_oid(&as, ct->oid, sizeof ct->oid);
        if (strcmp(ct->oid, OID_FTAM_UNSTR_TEXT) == 0)
            ct->doctype = 1;
        else if (strcmp(ct->oid, OID_FTAM_UNSTR_BIN) == 0)
            ct->doctype = 3;
        return 0;
    }
    if (t->tag != T_CTXC(0))
        return -1;
    if (!ber_find(t, FT_DOC_TYPE_NAME, &name))
        return -1;
    ber_get_oid(&name, ct->oid, sizeof ct->oid);
    if (strcmp(ct->oid, OID_FTAM_1) == 0)
        ct->doctype = 1;
    else if (strcmp(ct->oid, OID_FTAM_3) == 0)
        ct->doctype = 3;
    else if (strcmp(ct->oid, OID_NBS9_DOC) == 0)
        ct->doctype = 9;
    if (ct->doctype == 9 && ber_find(t, T_CTXC(0), &param)) {
        /* Attribute-Names, as a plain or [0]-tagged BIT STRING */
        ber_rd   r;
        ber_tlv  bits;
        uint32_t m;
        ber_enter(&param, &r);
        if (ber_next(&r, &bits) > 0 && !T_CONSTRUCTED(bits.tag) &&
            ber_get_bits(&bits, &m) == 0)
            ct->nbs9_names = (long)m;
    } else if (ber_find(t, T_CTXC(0), &param)) {
        ber_rd  r;
        ber_tlv seq, f;
        ber_enter(&param, &r);
        if (ber_next(&r, &seq) > 0 && seq.tag == T_SEQ) {
            ber_enter(&seq, &r);
            while (ber_next(&r, &f) > 0) {
                long v;
                if (ber_get_int(&f, &v) < 0)
                    continue;
                if (f.tag == T_CTX(0))
                    ct->universal_class = v;
                else if (f.tag == T_CTX(1))
                    ct->max_string_length = v;
                else if (f.tag == T_CTX(2))
                    ct->significance = v;
            }
        }
    }
    return 0;
}

/* ---- diagnostics ------------------------------------------------------- */

void ftam_enc_diagnostic(ber_enc *e, int type, int id, int observer,
                         int source, const char *details)
{
    ber_begin(e, FT_DIAGNOSTIC);
    ber_begin(e, T_SEQ);
    ber_int(e, T_CTX(0), type);
    ber_int(e, T_CTX(1), id);
    ber_int(e, T_CTX(2), observer);
    ber_int(e, T_CTX(3), source);
    if (details)
        ber_str(e, T_CTX(5), details);
    ber_end(e);
    ber_end(e);
}

static const struct {
    long        id;
    const char *text;
} ftam_errors[] = {
    { 0, "no reason" },
    { 1, "responder error (unspecific)" },
    { 2, "system shutdown" },
    { 3, "FTAM management problem (unspecific)" },
    { 4, "FTAM management, bad account" },
    { 5, "FTAM management, security not passed" },
    { 6, "delay may be encountered" },
    { 7, "initiator error (unspecific)" },
    { 8, "subsequent error" },
    { 9, "temporal insufficiency of resources" },
    { 10, "access request violates VFS security" },
    { 11, "access request violates local security" },
    { 1000, "conflicting parameter values" },
    { 1001, "unsupported parameter values" },
    { 1002, "mandatory parameter not set" },
    { 1003, "unsupported parameter" },
    { 1004, "duplicated parameter" },
    { 1005, "illegal parameter type" },
    { 1006, "unsupported parameter types" },
    { 1007, "FTAM protocol error (unspecific)" },
    { 1008, "FTAM protocol error, procedure error" },
    { 1009, "FTAM protocol error, functional unit error" },
    { 1010, "FTAM protocol error, corruption error" },
    { 1011, "lower layer failure" },
    { 1012, "lower layer addressing error" },
    { 1013, "timeout" },
    { 1014, "system shutdown" },
    { 1015, "illegal grouping sequence" },
    { 1016, "grouping threshold violation" },
    { 1017, "specific PDU request inconsistent with the current requested access" },
    { 2000, "association with user not allowed" },
    { 2002, "unsupported service class" },
    { 2003, "unsupported functional unit" },
    { 2004, "attribute group error (unspecific)" },
    { 2005, "attribute group not supported" },
    { 2006, "attribute group not allowed" },
    { 2007, "bad account" },
    { 2008, "association management (unspecific)" },
    { 2009, "association management, bad address" },
    { 2010, "association management, bad account" },
    { 2011, "checkpoint window error, too large" },
    { 2012, "checkpoint window error, too small" },
    { 2013, "checkpoint window error, unsupported" },
    { 2014, "communications QoS not supported" },
    { 2015, "initiator identity unacceptable" },
    { 2016, "context management refused" },
    { 2017, "rollback not available" },
    { 2018, "contents type list cut by responder" },
    { 2019, "contents type list cut by presentation service" },
    { 2020, "invalid filestore password" },
    { 2021, "incompatible service classes" },
    { 3000, "filename not found" },
    { 3001, "selection attributes not matched" },
    { 3002, "initial attributes not possible" },
    { 3003, "bad attribute name" },
    { 3004, "non-existent file" },
    { 3005, "file already exists" },
    { 3006, "file cannot be created" },
    { 3007, "file cannot be deleted" },
    { 3008, "concurrency control not available" },
    { 3009, "concurrency control not supported" },
    { 3010, "concurrency control not possible" },
    { 3011, "more restrictive lock" },
    { 3012, "file busy" },
    { 3013, "file not available" },
    { 3014, "access control not available" },
    { 3015, "access control not supported" },
    { 3016, "access control inconsistent" },
    { 3017, "filename truncated" },
    { 3018, "initial attributes altered" },
    { 3019, "bad account" },
    { 3020, "override selected existing file" },
    { 3021, "override deleted and recreated file with old attributes" },
    { 3022, "create override deleted and recreated file with new attributes" },
    { 3023, "create override not possible" },
    { 3024, "ambiguous file specification" },
    { 3025, "invalid create password" },
    { 3026, "invalid delete password on override" },
    { 3027, "bad attribute value" },
    { 3028, "requested access violates permitted actions" },
    { 3029, "functional unit not available for requested access" },
    { 3030, "file created but not selected" },
    { 4000, "attribute non-existent" },
    { 4001, "attribute cannot be read" },
    { 4002, "attribute cannot be changed" },
    { 4003, "attribute not supported" },
    { 4004, "bad attribute name" },
    { 4005, "bad attribute value" },
    { 5000, "bad FADU (unspecific)" },
    { 5001, "bad FADU, size error" },
    { 5002, "bad FADU, type error" },
    { 5003, "bad FADU, poorly specified" },
    { 5004, "bad FADU, bad location" },
    { 5005, "FADU does not exist" },
    { 5006, "FADU not available (unspecific)" },
    { 5007, "FADU not available for reading" },
    { 5008, "FADU not available for writing" },
    { 5009, "FADU not available for location" },
    { 5010, "FADU not available for erasure" },
    { 5011, "FADU cannot be inserted" },
    { 5012, "FADU cannot be replaced" },
    { 5013, "FADU cannot be located" },
    { 5014, "bad data element type" },
    { 5015, "operation not available" },
    { 5016, "operation not supported" },
    { 5017, "operation inconsistent" },
    { 5021, "processing mode not available" },
    { 5022, "processing mode not supported" },
    { 5023, "processing mode inconsistent" },
    { 5024, "access context not available" },
    { 5025, "access context not supported" },
    { 5026, "bad write (unspecific)" },
    { 5027, "bad read (unspecific)" },
    { 5028, "local failure (unspecific)" },
    { 5029, "local failure, filespace exhausted" },
    { 5030, "local failure, data corrupted" },
    { 5031, "local failure, device failure" },
    { 5032, "future file size exceeded" },
    { 5036, "contents type inconsistent" },
    { 5037, "contents type simplified" },
};

const char *ftam_error_str(long id)
{
    for (size_t i = 0; i < sizeof ftam_errors / sizeof ftam_errors[0]; i++)
        if (ftam_errors[i].id == id)
            return ftam_errors[i].text;
    return "unknown error";
}

static const char *entity_str(long v)
{
    switch (v) {
    case 0: return "no categorization";
    case 1: return "initiating user";
    case 2: return "initiating FPM";
    case 3: return "supporting service";
    case 4: return "responding FPM";
    case 5: return "responding user";
    default: return "?";
    }
}

int ftam_fmt_diagnostic(const ber_tlv *pdu, char *out, size_t max)
{
    ber_tlv diag, ent;
    ber_rd  r;
    int     count = 0;
    size_t  pos = 0;

    out[0] = 0;
    if (!ber_find(pdu, FT_DIAGNOSTIC, &diag))
        return 0;
    ber_enter(&diag, &r);
    while (ber_next(&r, &ent) > 0 && pos < max) {
        long    type = -1, id = -1, obs = -1, src = -1;
        char    details[256] = "";
        ber_rd  er;
        ber_tlv f;
        ber_enter(&ent, &er);
        while (ber_next(&er, &f) > 0) {
            switch (T_TAGNUM(f.tag)) {
            case 0: ber_get_int(&f, &type); break;
            case 1: ber_get_int(&f, &id); break;
            case 2: ber_get_int(&f, &obs); break;
            case 3: ber_get_int(&f, &src); break;
            case 5: ber_get_cstr(&f, details, sizeof details); break;
            }
        }
        int w = snprintf(out + pos, max - pos,
                         "%s[%s] error %ld: %s (source: %s)%s%s%s",
                         count ? "; " : "",
                         type == 0 ? "informative" : type == 1 ? "transient" :
                         type == 2 ? "permanent" : "?",
                         id, ftam_error_str(id), entity_str(src),
                         details[0] ? " \"" : "", details, details[0] ? "\"" : "");
        (void)obs;
        if (w < 0)
            break;
        pos += (size_t)w;
        count++;
    }
    return count;
}

long ftam_first_diag_id(const ber_tlv *pdu)
{
    ber_tlv diag, ent, id;
    ber_rd  r;
    long    v = -1;
    if (!ber_find(pdu, FT_DIAGNOSTIC, &diag))
        return -1;
    ber_enter(&diag, &r);
    if (ber_next(&r, &ent) > 0 && ber_find(&ent, T_CTX(1), &id))
        ber_get_int(&id, &v);
    return v;
}

int ftam_check_result(const ber_tlv *pdu, const char *what)
{
    ber_tlv t;
    long    state = 0, action = 0;
    char    diag[1024];

    if (ber_find(pdu, FT_STATE_RESULT, &t))
        ber_get_int(&t, &state);
    if (ber_find(pdu, FT_ACTION_RESULT, &t))
        ber_get_int(&t, &action);
    int nd = ftam_fmt_diagnostic(pdu, diag, sizeof diag);
    if (state == 0 && action == 0) {
        if (nd)
            log_msg(LOG_INFO, "ftam", "%s: %s", what, diag);
        return 0;
    }
    set_error("%s failed (%s%s)%s%s", what,
              state ? "state-result failure" : "",
              action == 1 ? (state ? ", transient error" : "transient error") :
              action == 2 ? (state ? ", permanent error" : "permanent error") : "",
              nd ? ": " : "", diag);
    return -1;
}

const char *ftam_pdu_name(unsigned tag)
{
    static const char *names[] = {
        "F-INITIALIZE-request", "F-INITIALIZE-response",
        "F-TERMINATE-request", "F-TERMINATE-response",
        "F-U-ABORT-request", "F-P-ABORT-request",
        "F-SELECT-request", "F-SELECT-response",
        "F-DESELECT-request", "F-DESELECT-response",
        "F-CREATE-request", "F-CREATE-response",
        "F-DELETE-request", "F-DELETE-response",
        "F-READ-ATTRIB-request", "F-READ-ATTRIB-response",
        "F-CHANGE-ATTRIB-request", "F-CHANGE-ATTRIB-response",
        "F-OPEN-request", "F-OPEN-response",
        "F-CLOSE-request", "F-CLOSE-response",
        "F-BEGIN-GROUP-request", "F-BEGIN-GROUP-response",
        "F-END-GROUP-request", "F-END-GROUP-response",
        "F-RECOVER-request", "F-RECOVER-response",
        "F-LOCATE-request", "F-LOCATE-response",
        "F-ERASE-request", "F-ERASE-response",
        "F-READ-request", "F-WRITE-request", "F-DATA-END-request",
        "F-TRANSFER-END-request", "F-TRANSFER-END-response",
        "F-CANCEL-request", "F-CANCEL-response",
        "F-RESTART-request", "F-RESTART-response",
    };
    static const char *fsm[] = {
        "F-CHANGE-PREFIX-request", "F-CHANGE-PREFIX-response",
        "F-LIST-request", "F-LIST-response",
    };
    if (tag < sizeof names / sizeof names[0])
        return names[tag];
    if (tag >= 41 && tag - 41 < sizeof fsm / sizeof fsm[0])
        return fsm[tag - 41];
    return "unknown FTAM PDU";
}

/* ---- directory entries -------------------------------------------------- */

void ftam_fix_gtime(char *gt)
{
    if (strlen(gt) < 4 || strspn(gt, "0123456789") < 4)
        return;
    int year = (gt[0] - '0') * 1000 + (gt[1] - '0') * 100 + (gt[2] - '0') * 10 + (gt[3] - '0');
    if (year < 100 || year > 999)
        return;
    char y[8];
    snprintf(y, sizeof y, "%04d", year + 1900);
    memcpy(gt, y, 4);
}

/* A constructed value whose first element is a filename/pathname [0]. */
static int looks_like_attributes(const ber_tlv *t)
{
    ber_rd  r;
    ber_tlv c;
    if (!T_CONSTRUCTED(t->tag))
        return 0;
    ber_enter(t, &r);
    return ber_next(&r, &c) > 0 && c.tag == T_CTXC(0);
}

int ftam_find_attributes(const ber_tlv *v, ber_tlv *attrs)
{
    if (v->tag == FT_READ_ATTRS || (looks_like_attributes(v) && v->tag != T_CTXC(0))) {
        *attrs = *v;
        return 1;
    }
    if (!T_CONSTRUCTED(v->tag))
        return 0;
    ber_rd  r;
    ber_tlv c;
    ber_enter(v, &r);
    while (ber_next(&r, &c) > 0)
        if (ftam_find_attributes(&c, attrs))
            return 1;
    return 0;
}

int ftam_parse_dirent(const ber_tlv *attrs, ftam_dirent *e)
{
    ber_rd  r;
    ber_tlv f, in;

    memset(e, 0, sizeof *e);
    e->size = -1;
    ber_enter(attrs, &r);
    while (ber_next(&r, &f) > 0) {
        if (T_CLASS(f.tag) != 0x80)
            continue;
        unsigned n = T_TAGNUM(f.tag);
        if (n == 0 && T_CONSTRUCTED(f.tag)) {  /* SEQUENCE OF GraphicString */
            ber_rd  nr;
            ber_tlv s;
            size_t  pos = 0;
            ber_enter(&f, &nr);
            while (ber_next(&nr, &s) > 0 && pos < sizeof e->name - 1) {
                char part[512];
                ber_get_cstr(&s, part, sizeof part);
                pos += (size_t)snprintf(e->name + pos, sizeof e->name - pos, "%s%s",
                                        pos ? "/" : "", part);
            }
        } else if (n == 18 && !T_CONSTRUCTED(f.tag)) {   /* object-type */
            long v = 0;
            ber_get_int(&f, &v);
            if (v == 1)
                e->is_dir = 1;
        } else if (n == 2 && T_CONSTRUCTED(f.tag)) {
            contents_type ct;
            ber_rd cr;
            ber_enter(&f, &cr);
            if (ber_next(&cr, &in) > 0 && ftam_dec_contents_type(&in, &ct) == 0) {
                e->doctype = ct.doctype;
                if (ct.doctype == 9)
                    e->is_dir = 1;
            }
        } else if ((n == 4 || n == 5 || n == 13) && T_CONSTRUCTED(f.tag)) {
            ber_rd ar;
            ber_enter(&f, &ar);
            if (ber_next(&ar, &in) <= 0 || (in.tag == T_CTX(0) && in.len == 0))
                continue;                       /* no value available */
            if (n == 4) {
                ber_get_cstr(&in, e->ctime, sizeof e->ctime);
                ftam_fix_gtime(e->ctime);
            } else if (n == 5) {
                ber_get_cstr(&in, e->mtime, sizeof e->mtime);
                ftam_fix_gtime(e->mtime);
            } else {
                long v;
                if (ber_get_int(&in, &v) == 0)
                    e->size = v;
            }
        }
    }
    return e->name[0] ? 0 : -1;
}

/* ---- attribute printing ------------------------------------------------ */

static void print_bits(FILE *f, uint32_t m, const char *const *names, int n)
{
    int first = 1;
    for (int i = 0; i < n; i++)
        if (m & (1u << i)) {
            fprintf(f, "%s%s", first ? "" : ",", names[i]);
            first = 0;
        }
    if (first)
        fputs("(none)", f);
}

/* Unwrap "CHOICE { no-value-available [0] NULL, actual-values ... }". */
static int attr_value(const ber_tlv *field, ber_tlv *inner)
{
    ber_rd r;
    ber_enter(field, &r);
    if (ber_next(&r, inner) <= 0)
        return -1;
    if (inner->tag == T_CTX(0) && inner->len == 0)
        return 0;                               /* no value available */
    return 1;
}

void ftam_print_attributes(FILE *f, const ber_tlv *attrs)
{
    static const char *const actions[] = {
        "read", "insert", "replace", "extend", "erase", "read-attribute",
        "change-attribute", "delete-file", "traversal", "reverse-traversal",
        "random-order",
    };
    static const char *const labels[] = {
        "filename", "permitted-actions", "contents-type", "storage-account",
        "created", "modified", "read", "attribute-modified",
        "creator", "last-modifier", "last-reader", "last-attribute-modifier",
        "availability", "filesize", "future-filesize", "access-control",
        "legal-qualification", "private-use", "object-type",
    };
    ber_rd  r;
    ber_tlv fld, in;

    ber_enter(attrs, &r);
    while (ber_next(&r, &fld) > 0) {
        unsigned n = T_TAGNUM(fld.tag);
        if (T_CLASS(fld.tag) != 0x80 || n >= sizeof labels / sizeof labels[0])
            continue;
        fprintf(f, "  %-24s ", labels[n]);
        if (n == 0) {                           /* SEQUENCE OF GraphicString */
            ber_rd nr;
            ber_tlv s;
            char    buf[1024];
            int     first = 1;
            ber_enter(&fld, &nr);
            while (ber_next(&nr, &s) > 0) {
                ber_get_cstr(&s, buf, sizeof buf);
                fprintf(f, "%s%s", first ? "" : "/", buf);
                first = 0;
            }
        } else if (n == 18) {                  /* object-type (version 2) */
            long v = -1;
            ber_get_int(&fld, &v);
            fputs(v == 0 ? "file" : v == 1 ? "file-directory" :
                  v == 2 ? "reference" : "?", f);
        } else if (n == 1) {
            uint32_t m;
            ber_get_bits(&fld, &m);
            print_bits(f, m, actions, 11);
        } else if (n == 2) {
            contents_type ct;
            if (attr_value(&fld, &in) > 0 && ftam_dec_contents_type(&in, &ct) == 0) {
                fprintf(f, "%s", ct.doctype == 1 ? "FTAM-1 (unstructured text)" :
                                 ct.doctype == 3 ? "FTAM-3 (unstructured binary)" :
                                 ct.oid);
                if (ct.universal_class >= 0)
                    fprintf(f, " class=%ld", ct.universal_class);
                if (ct.max_string_length >= 0)
                    fprintf(f, " maxlen=%ld", ct.max_string_length);
                if (ct.significance >= 0)
                    fprintf(f, " significance=%s",
                            ct.significance == 0 ? "variable" :
                            ct.significance == 1 ? "fixed" : "not-significant");
            } else {
                fputs("?", f);
            }
        } else {
            int rc = attr_value(&fld, &in);
            if (rc == 0) {
                fputs("(no value available)", f);
            } else if (rc < 0) {
                fputs("?", f);
            } else if (n >= 15) {
                fputs("(present)", f);
            } else if (in.tag == T_INT || (n >= 12 && in.tag == T_CTX(1))) {
                long v = 0;
                ber_get_int(&in, &v);
                if (n == 12)
                    fputs(v == 0 ? "immediate" : "deferred", f);
                else
                    fprintf(f, "%ld", v);
            } else {
                char buf[256];
                ber_get_cstr(&in, buf, sizeof buf);
                if (n >= 4 && n <= 7)           /* dates */
                    ftam_fix_gtime(buf);
                fputs(buf, f);
            }
        }
        fputc('\n', f);
    }
}
