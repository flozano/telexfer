/*
 * ftamd.c - minimal FTAM responder over XOT, serving files from a
 * directory.  It exists to exercise the client end to end (and to make
 * pcap captures for tshark); it is not a production responder.
 *
 * Files whose name ends in ".txt" are presented as FTAM-1, everything
 * else as FTAM-3.
 */
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "ftam_pdu.h"
#include "pres.h"
#include "session.h"

static const char *L = "srv";

typedef struct {
    x25_vc    vc;
    tp0_conn  tc;
    ses_conn  ses;
    const char *dir;
    const char *password;       /* required filestore password, or NULL */
    int       ctx_acse, ctx_pci, ctx_text, ctx_bin, ctx_nbs9;
    uint32_t  version;          /* negotiated Protocol-Version bits */
    int       no_v2;            /* -L: refuse FTAM version 2 (no F-LIST) */
    uint32_t  nbs9_names;       /* attributes asked for when opening a dir */
    uint32_t  fu, attr_groups;
    /* regime state */
    char      selected[1024];   /* remote name, "" = none */
    char      reqname[1024];    /* filename of the request being handled */
    char      path[2048];
    int       open;
    int       doctype;
    int       writing;
    FILE     *wf;
    int       group_failed;
    int       in_group;
    buf_t     out;              /* pending P-DATA user data */
    ber_enc   oe;
    int       out_pending;
    int       pdv_mode;         /* -O / -A: file data encoding */
    int       tsdu_limit;       /* -s: session TSDU maximum size */
    int       ext_concat;       /* -X: send extended concatenated TSDUs */
    buf_t     octets;           /* data values pending for octet-aligned */
} srv_t;

typedef struct {
    int         tsdu_limit;     /* -s */
    int         use_rej;        /* -R */
    int         drop;           /* -D */
    int         t25_ms;         /* -T */
    int         hold_ms;        /* -N */
    size_t      rx_limit;       /* -B */
    uint8_t     qdata[128];
    size_t      qdata_len;      /* -Q */
    int         pdv_mode;       /* -O octet-aligned, -A arbitrary */
    int         ext_concat;     /* -X */
    int         no_v2;          /* -L */
    int         acse_encoding;  /* -E octet|arbitrary */
    size_t      segment;        /* -S */
    uint8_t     intr[X25_MAX_INT_DATA];
    size_t      intr_len;       /* -I */
} srv_opts;

static void enc_ct(ber_enc *e, int doctype);

/* ---- output ------------------------------------------------------------ */

static void queue_value(srv_t *s, int ctx, const buf_t *v)
{
    if (!s->out_pending) {
        buf_reset(&s->out);
        pres_ud_begin(&s->oe, &s->out);
        s->out_pending = 1;
    }
    pres_ud_pdv(&s->oe, ctx, v->data, v->len);
}

static int flush_out(srv_t *s)
{
    if (!s->out_pending)
        return 0;
    pres_ud_end(&s->oe);
    s->out_pending = 0;
    if (s->ext_concat && s->ses.peer_ext_concat && !s->ses.tsdu_max_tx) {
        /* test hook: GT + MIP (minor sync point, serial number 1) + DT.
         * Only meaningful with synchronization, which is never
         * negotiated, so the initiator must skip the MIP. */
        static const uint8_t mip[] = { 49, 3, 42, 1, '1' };
        return ses_send_data_concat(&s->ses, mip, sizeof mip, s->out.data, s->out.len);
    }
    return ses_send_data(&s->ses, s->out.data, s->out.len);
}

static void reply(srv_t *s, const buf_t *pdu)
{
    log_msg(LOG_INFO, L, "-> %s", ftam_pdu_name(pdu->data[0] == 0xbf ?
            pdu->data[1] : (unsigned)(pdu->data[0] & 0x1f)));
    queue_value(s, s->ctx_pci, pdu);
}

/* Send pending data values as one constructed octet-aligned PDV. */
static void flush_octets(srv_t *s, int ctx)
{
    buf_t   ud;
    ber_enc e;
    if (!s->octets.len)
        return;
    flush_out(s);                               /* keep the ordering */
    buf_init(&ud);
    pres_ud_begin(&e, &ud);
    pres_ud_pdv_enc(&e, ctx, s->pdv_mode, s->octets.data, s->octets.len);
    pres_ud_end(&e);
    ses_send_data(&s->ses, ud.data, ud.len);
    buf_free(&ud);
    buf_reset(&s->octets);
}

static void queue_data(srv_t *s, int ctx, const buf_t *v)
{
    if (s->pdv_mode == PDV_SINGLE) {
        queue_value(s, ctx, v);
        if (s->out.len > 2048)
            flush_out(s);
        return;
    }
    buf_put(&s->octets, v->data, v->len);
    if (s->octets.len >= 3000)
        flush_octets(s, ctx);
}

/* Response with state/action result and optional diagnostic. */
static void begin_resp(ber_enc *e, buf_t *b, unsigned tag, int fail, int err,
                       int with_state)
{
    buf_reset(b);
    ber_enc_init(e, b);
    ber_begin(e, T_CTXC(tag));
    if (fail) {
        if (with_state)
            ber_int(e, FT_STATE_RESULT, 1);
        ber_int(e, FT_ACTION_RESULT, 2);
    }
    (void)err;
}

static void end_resp(ber_enc *e, int fail, int err, const char *details)
{
    if (fail)
        ftam_enc_diagnostic(e, 2, err, 5, 5, details);
    ber_end(e);
}

static void simple_resp(srv_t *s, unsigned tag, int fail, int err,
                        const char *details, int with_state)
{
    buf_t   b;
    ber_enc e;
    buf_init(&b);
    begin_resp(&e, &b, tag, fail, err, with_state);
    /* mandatory elements of some responses, even on failure */
    if (tag == F_SELECT_RP || tag == F_CREATE_RP) {
        ber_begin(&e, tag == F_SELECT_RP ? FT_SELECT_ATTRS : FT_CREATE_ATTRS);
        ber_begin(&e, T_CTXC(0));
        ber_str(&e, T_GRAPHIC, s->reqname);
        ber_end(&e);
        ber_end(&e);
    } else if (tag == F_OPEN_RP) {
        ber_begin(&e, T_CTXC(1));
        enc_ct(&e, s->doctype ? s->doctype : 3);
        ber_end(&e);
    }
    end_resp(&e, fail, err, details);
    reply(s, &b);
    buf_free(&b);
}

/* ---- helpers ----------------------------------------------------------- */

static int get_filename(const ber_tlv *attrs, char *out, size_t max)
{
    ber_tlv fn, s;
    ber_rd  r;
    if (!ber_find(attrs, T_CTXC(0), &fn))
        return -1;
    ber_enter(&fn, &r);
    if (ber_next(&r, &s) <= 0)
        return -1;
    ber_get_cstr(&s, out, max);
    return strstr(out, "..") || out[0] == '/' || !out[0] ? -1 : 0;
}

static void enc_ct(ber_enc *e, int doctype)
{
    contents_type ct = { .doctype = doctype, .universal_class = -1,
                         .max_string_length = -1, .significance = -1 };
    if (doctype == 1) {
        ct.universal_class = 27;
        ct.significance = SS_VARIABLE;
    }
    ftam_enc_contents_type(e, &ct);
}

static int doctype_of(const char *name)
{
    size_t n = strlen(name);
    return n > 4 && strcmp(name + n - 4, ".txt") == 0 ? 1 : 3;
}

static int group_blocked(srv_t *s, unsigned rsp_tag, int with_state)
{
    if (s->in_group && s->group_failed) {
        simple_resp(s, rsp_tag, 1, 8, "group abandoned", with_state);
        return 1;
    }
    return 0;
}

static void fail_group(srv_t *s)
{
    if (s->in_group)
        s->group_failed = 1;
}

/* ---- request handlers -------------------------------------------------- */

static void do_select(srv_t *s, const ber_tlv *pdu)
{
    ber_tlv attrs;
    char    name[1024];
    struct stat st;

    ber_tlv rattrs;
    s->reqname[0] = 0;
    if (ber_find(pdu, FT_SELECT_ATTRS, &rattrs))
        get_filename(&rattrs, s->reqname, sizeof s->reqname);
    if (group_blocked(s, F_SELECT_RP, 1))
        return;
    if (!ber_find(pdu, FT_SELECT_ATTRS, &attrs) || get_filename(&attrs, name, sizeof name) < 0) {
        simple_resp(s, F_SELECT_RP, 1, 3003, "bad filename", 1);
        fail_group(s);
        return;
    }
    snprintf(s->path, sizeof s->path, "%s/%s", s->dir, name);
    if (stat(s->path, &st) < 0) {
        buf_t b; ber_enc e;
        buf_init(&b);
        begin_resp(&e, &b, F_SELECT_RP, 1, 3000, 1);
        ber_begin(&e, FT_SELECT_ATTRS);
        ber_begin(&e, T_CTXC(0));
        ber_str(&e, T_GRAPHIC, name);
        ber_end(&e);
        ber_end(&e);
        end_resp(&e, 1, 3000, strerror(errno));
        reply(s, &b);
        buf_free(&b);
        fail_group(s);
        return;
    }
    snprintf(s->selected, sizeof s->selected, "%s", name);
    s->doctype = S_ISDIR(st.st_mode) ? 9 : doctype_of(name);
    buf_t b; ber_enc e;
    buf_init(&b);
    begin_resp(&e, &b, F_SELECT_RP, 0, 0, 1);
    ber_begin(&e, FT_SELECT_ATTRS);
    ber_begin(&e, T_CTXC(0));
    ber_str(&e, T_GRAPHIC, name);
    ber_end(&e);
    ber_end(&e);
    end_resp(&e, 0, 0, NULL);
    reply(s, &b);
    buf_free(&b);
}

static void do_create(srv_t *s, const ber_tlv *pdu)
{
    ber_tlv attrs, t;
    char    name[1024];
    long    override = 0;
    struct stat st;

    ber_tlv rattrs;
    s->reqname[0] = 0;
    if (ber_find(pdu, FT_CREATE_ATTRS, &rattrs))
        get_filename(&rattrs, s->reqname, sizeof s->reqname);
    if (group_blocked(s, F_CREATE_RP, 1))
        return;
    if (ber_find(pdu, T_CTX(0), &t))
        ber_get_int(&t, &override);
    if (!ber_find(pdu, FT_CREATE_ATTRS, &attrs) || get_filename(&attrs, name, sizeof name) < 0) {
        simple_resp(s, F_CREATE_RP, 1, 3003, "bad filename", 1);
        fail_group(s);
        return;
    }
    snprintf(s->path, sizeof s->path, "%s/%s", s->dir, name);
    int exists = stat(s->path, &st) == 0;
    if (exists && override == OVR_CREATE_FAILURE) {
        simple_resp(s, F_CREATE_RP, 1, 3005, "file exists", 1);
        fail_group(s);
        return;
    }
    FILE *f = fopen(s->path, (exists && override == OVR_SELECT_OLD) ? "ab" : "wb");
    if (!f) {
        simple_resp(s, F_CREATE_RP, 1, 3006, strerror(errno), 1);
        fail_group(s);
        return;
    }
    fclose(f);
    s->doctype = 3;
    if (ber_find(&attrs, T_CTXC(2), &t)) {
        ber_rd r;
        ber_tlv in;
        contents_type ct;
        ber_enter(&t, &r);
        if (ber_next(&r, &in) > 0 && ftam_dec_contents_type(&in, &ct) == 0 && ct.doctype)
            s->doctype = ct.doctype;
    }
    snprintf(s->selected, sizeof s->selected, "%s", name);
    buf_t b; ber_enc e;
    buf_init(&b);
    begin_resp(&e, &b, F_CREATE_RP, 0, 0, 1);
    ber_begin(&e, FT_CREATE_ATTRS);
    ber_begin(&e, T_CTXC(0));
    ber_str(&e, T_GRAPHIC, name);
    ber_end(&e);
    ber_end(&e);
    end_resp(&e, 0, 0, NULL);
    reply(s, &b);
    buf_free(&b);
}

static void do_open(srv_t *s, const ber_tlv *pdu)
{
    ber_tlv t;
    uint32_t mode = PM_READ;

    if (group_blocked(s, F_OPEN_RP, 1))
        return;
    if (!s->selected[0]) {
        simple_resp(s, F_OPEN_RP, 1, 1008, "no file selected", 1);
        fail_group(s);
        return;
    }
    if (ber_find(pdu, T_CTX(0), &t))
        ber_get_bits(&t, &mode);
    s->nbs9_names = AN_PATHNAME;
    if (s->doctype == 9 && ber_find(pdu, T_CTXC(1), &t)) {
        /* proposed [1] { document-type { NBS-9, parameter } } */
        ber_rd  r;
        ber_tlv prop, in;
        contents_type ct;
        ber_enter(&t, &r);
        if (ber_next(&r, &prop) > 0 && prop.tag == T_CTXC(1)) {
            ber_enter(&prop, &r);
            if (ber_next(&r, &in) > 0 && ftam_dec_contents_type(&in, &ct) == 0 &&
                ct.nbs9_names > 0)
                s->nbs9_names = (uint32_t)ct.nbs9_names;
        }
    }
    if (s->doctype == 9 && (mode & ~PM_READ)) {
        simple_resp(s, F_OPEN_RP, 1, 5021, "directories can only be read", 1);
        fail_group(s);
        return;
    }
    if (mode & PM_REPLACE) {
        FILE *f = fopen(s->path, "wb");
        if (f)
            fclose(f);
    }
    s->open = 1;
    buf_t b; ber_enc e;
    buf_init(&b);
    begin_resp(&e, &b, F_OPEN_RP, 0, 0, 1);
    ber_begin(&e, T_CTXC(1));
    enc_ct(&e, s->doctype);
    ber_end(&e);
    end_resp(&e, 0, 0, NULL);
    reply(s, &b);
    buf_free(&b);
}

/* Sorted names in a directory (without . and ..); returns count or -1. */
static int read_dir(const char *path, char ***out)
{
    DIR           *d = opendir(path);
    struct dirent *de;
    char         **v = NULL;
    int            n = 0, cap = 0;
    if (!d)
        return -1;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 32;
            v = xrealloc(v, (size_t)cap * sizeof *v);
        }
        v[n++] = strdup(de->d_name);
    }
    closedir(d);
    for (int i = 1; i < n; i++)                 /* insertion sort, small */
        for (int j = i; j > 0 && strcmp(v[j - 1], v[j]) > 0; j--) {
            char *t = v[j]; v[j] = v[j - 1]; v[j - 1] = t;
        }
    *out = v;
    return n;
}

/* Read-Attributes for one directory entry, with the requested names. */
static void enc_entry(ber_enc *e, srv_t *s, const char *dir, const char *name,
                      uint32_t names)
{
    char        path[4096];
    struct stat st;
    snprintf(path, sizeof path, "%s/%s", dir, name);
    if (stat(path, &st) < 0)
        return;
    int isdir = S_ISDIR(st.st_mode);
    ber_begin(e, FT_READ_ATTRS);
    ber_begin(e, T_CTXC(0));
    ber_str(e, T_GRAPHIC, name);
    ber_end(e);
    /* version 2 puts object-type right after the pathname */
    if (s->version == PV_VERSION_2 && (names & AN_OBJECT_TYPE))
        ber_int(e, T_CTX(18), isdir ? 1 : 0);
    if (names & AN_PERMITTED)
        ber_bits(e, T_CTX(1), isdir ? AR_READ | AR_READ_ATTR :
                 AR_READ | AR_REPLACE | AR_EXTEND | AR_ERASE | AR_READ_ATTR |
                 AR_CHANGE_ATTR | AR_DELETE);
    if (names & AN_CONTENTS_TYPE) {
        ber_begin(e, T_CTXC(2));
        enc_ct(e, isdir ? 9 : doctype_of(name));
        ber_end(e);
    }
    if ((s->attr_groups & AG_STORAGE) && (names & AN_MODIFIED)) {
        char      tbuf[32];
        struct tm tm;
        gmtime_r(&st.st_mtime, &tm);
        strftime(tbuf, sizeof tbuf, "%Y%m%d%H%M%SZ", &tm);
        ber_begin(e, T_CTXC(5));
        ber_str(e, T_CTX(1), tbuf);
        ber_end(e);
    }
    if ((s->attr_groups & AG_STORAGE) && (names & AN_SIZE) && !isdir) {
        ber_begin(e, T_CTXC(13));
        ber_int(e, T_CTX(1), (long)st.st_size);
        ber_end(e);
    }
    ber_end(e);
}

/* NBS-9: one data element (Read-Attributes) per directory entry. */
static void read_directory(srv_t *s)
{
    char  **names;
    int     n = read_dir(s->path, &names);
    buf_t   v, b;
    ber_enc e;

    buf_init(&v);
    buf_init(&b);
    ber_enc_init(&e, &b);
    ber_begin(&e, T_CTXC(F_DATA_END_RQ));
    if (n < 0) {
        ber_int(&e, FT_ACTION_RESULT, 2);
        ftam_enc_diagnostic(&e, 2, 5027, 5, 5, strerror(errno));
    }
    ber_end(&e);
    for (int i = 0; i < n; i++) {
        buf_reset(&v);
        ber_enc ve;
        ber_enc_init(&ve, &v);
        enc_entry(&ve, s, s->path, names[i], s->nbs9_names);
        if (v.len)
            queue_data(s, s->ctx_nbs9, &v);
        free(names[i]);
    }
    if (n > 0)
        free(names);
    flush_octets(s, s->ctx_nbs9);
    reply(s, &b);
    buf_free(&v);
    buf_free(&b);
}

/* F-LIST: attributes of the objects directly in the scope's root. */
static void do_list(srv_t *s, const ber_tlv *pdu)
{
    char     dir[1024] = ".", rel[1024] = "";
    char     path[2048];
    uint32_t names = AN_PATHNAME;
    ber_tlv  t, seq, root, pn;

    if (ber_find(pdu, T_CTX(0), &t))
        ber_get_bits(&t, &names);
    if (ber_find(pdu, FT_SCOPE, &t)) {
        ber_rd r;
        ber_enter(&t, &r);
        /* root-directory [0] { incomplete-pathname [0] { GraphicString } } */
        if (ber_next(&r, &seq) > 0 && ber_find(&seq, T_CTXC(0), &root)) {
            ber_rd  rr, pr;
            ber_tlv part;
            ber_enter(&root, &rr);
            if (ber_next(&rr, &pn) > 0 && T_CONSTRUCTED(pn.tag)) {
                ber_enter(&pn, &pr);
                if (ber_next(&pr, &part) > 0)
                    ber_get_cstr(&part, rel, sizeof rel);
            }
        }
    }
    if (rel[0])
        snprintf(dir, sizeof dir, "%s", rel);
    buf_t   b;
    ber_enc e;
    buf_init(&b);
    ber_enc_init(&e, &b);
    ber_begin(&e, T_CTXC(F_LIST_RP));
    char **list = NULL;
    int    n = -1;
    if (!strstr(dir, "..") && dir[0] != '/') {
        snprintf(path, sizeof path, "%s/%s", s->dir, dir);
        n = read_dir(path, &list);
    }
    if (n < 0) {
        ber_int(&e, FT_ACTION_RESULT, 2);
        ftam_enc_diagnostic(&e, 2, 3000, 5, 5, "no such directory");
    } else {
        ber_begin(&e, FT_OBJECTS_ATTRS);
        for (int i = 0; i < n; i++) {
            enc_entry(&e, s, path, list[i], names);
            free(list[i]);
        }
        free(list);
        ber_end(&e);
    }
    ber_end(&e);
    reply(s, &b);
    buf_free(&b);
}

static void do_read(srv_t *s)
{
    if (s->doctype == 9) {
        read_directory(s);
        return;
    }
    FILE *f = fopen(s->path, "rb");
    buf_t v;
    ber_enc e;
    int   ctx = s->doctype == 1 ? s->ctx_text : s->ctx_bin;

    buf_init(&v);
    if (!f) {
        buf_t b;
        buf_init(&b);
        ber_enc_init(&e, &b);
        ber_begin(&e, T_CTXC(F_DATA_END_RQ));
        ber_int(&e, FT_ACTION_RESULT, 2);
        ftam_enc_diagnostic(&e, 2, 5027, 5, 5, strerror(errno));
        ber_end(&e);
        reply(s, &b);
        buf_free(&b);
        return;
    }
    if (s->doctype == 1) {
        char   *line = NULL;
        size_t  cap = 0;
        ssize_t n;
        while ((n = getline(&line, &cap, f)) >= 0) {
            while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
                n--;
            buf_reset(&v);
            ber_enc_init(&e, &v);
            ber_prim(&e, T_GENERAL, line, (size_t)n);
            queue_data(s, ctx, &v);
        }
        free(line);
    } else {
        uint8_t chunk[1000];
        size_t  n;
        while ((n = fread(chunk, 1, sizeof chunk, f)) > 0) {
            buf_reset(&v);
            ber_enc_init(&e, &v);
            ber_prim(&e, T_OCTETS, chunk, n);
            queue_data(s, ctx, &v);
        }
    }
    flush_octets(s, ctx);
    fclose(f);
    buf_free(&v);
    buf_t b;
    buf_init(&b);
    ber_enc_init(&e, &b);
    ber_begin(&e, T_CTXC(F_DATA_END_RQ));
    ber_end(&e);
    reply(s, &b);
    buf_free(&b);
}

static void do_read_attrib(srv_t *s, const ber_tlv *pdu)
{
    struct stat st;
    if (group_blocked(s, F_READ_ATTRIB_RP, 0))
        return;
    if (!s->selected[0] || stat(s->path, &st) < 0) {
        simple_resp(s, F_READ_ATTRIB_RP, 1, 4001, "cannot stat", 0);
        fail_group(s);
        return;
    }
    char   tbuf[32];
    struct tm tm;
    gmtime_r(&st.st_mtime, &tm);
    strftime(tbuf, sizeof tbuf, "%Y%m%d%H%M%SZ", &tm);

    buf_t b; ber_enc e;
    buf_init(&b);
    begin_resp(&e, &b, F_READ_ATTRIB_RP, 0, 0, 0);
    ber_begin(&e, FT_READ_ATTRS);
    ber_begin(&e, T_CTXC(0));
    ber_str(&e, T_GRAPHIC, s->selected);
    ber_end(&e);
    ber_bits(&e, T_CTX(1), AR_READ | AR_REPLACE | AR_EXTEND | AR_ERASE |
             AR_READ_ATTR | AR_CHANGE_ATTR | AR_DELETE);
    ber_begin(&e, T_CTXC(2));
    enc_ct(&e, s->doctype);
    ber_end(&e);
    if (s->attr_groups & AG_STORAGE) {
        ber_begin(&e, T_CTXC(5));               /* date of last modification */
        ber_str(&e, T_CTX(1), tbuf);
        ber_end(&e);
        ber_begin(&e, T_CTXC(8));               /* identity of creator */
        ber_null(&e, T_CTX(0));                 /* no value available */
        ber_end(&e);
        ber_begin(&e, T_CTXC(13));              /* filesize */
        ber_int(&e, T_CTX(1), (long)st.st_size);  /* actual-values */
        ber_end(&e);
    }
    ber_end(&e);
    end_resp(&e, 0, 0, NULL);
    reply(s, &b);
    buf_free(&b);
    (void)pdu;
}

static void do_change_attrib(srv_t *s, const ber_tlv *pdu)
{
    ber_tlv attrs;
    char    name[1024], npath[2048];
    if (group_blocked(s, F_CHANGE_ATTRIB_RP, 0))
        return;
    if (!ber_find(pdu, FT_CHANGE_ATTRS, &attrs) || get_filename(&attrs, name, sizeof name) < 0) {
        simple_resp(s, F_CHANGE_ATTRIB_RP, 1, 4005, "bad filename", 0);
        fail_group(s);
        return;
    }
    snprintf(npath, sizeof npath, "%s/%s", s->dir, name);
    if (rename(s->path, npath) < 0) {
        simple_resp(s, F_CHANGE_ATTRIB_RP, 1, 4002, strerror(errno), 0);
        fail_group(s);
        return;
    }
    snprintf(s->path, sizeof s->path, "%s", npath);
    snprintf(s->selected, sizeof s->selected, "%s", name);
    simple_resp(s, F_CHANGE_ATTRIB_RP, 0, 0, NULL, 0);
}

static void handle_pdu(srv_t *s, const ber_tlv *pdu)
{
    unsigned tag = T_TAGNUM(pdu->tag);
    log_msg(LOG_INFO, L, "<- %s", ftam_pdu_name(tag));
    switch (tag) {
    case F_BEGIN_GROUP_RQ:
        s->in_group = 1;
        s->group_failed = 0;
        simple_resp(s, F_BEGIN_GROUP_RP, 0, 0, NULL, 0);
        break;
    case F_END_GROUP_RQ:
        s->in_group = 0;
        simple_resp(s, F_END_GROUP_RP, 0, 0, NULL, 0);
        flush_out(s);
        break;
    case F_SELECT_RQ:       do_select(s, pdu); break;
    case F_CREATE_RQ:       do_create(s, pdu); break;
    case F_OPEN_RQ:         do_open(s, pdu); break;
    case F_READ_ATTRIB_RQ:  do_read_attrib(s, pdu); break;
    case F_CHANGE_ATTRIB_RQ: do_change_attrib(s, pdu); break;
    case F_CLOSE_RQ:
        if (!group_blocked(s, F_CLOSE_RP, 0)) {
            s->open = 0;
            simple_resp(s, F_CLOSE_RP, 0, 0, NULL, 0);
        }
        break;
    case F_DESELECT_RQ:
        if (!group_blocked(s, F_DESELECT_RP, 0)) {
            s->selected[0] = 0;
            simple_resp(s, F_DESELECT_RP, 0, 0, NULL, 0);
        }
        break;
    case F_DELETE_RQ:
        if (group_blocked(s, F_DELETE_RP, 0))
            break;
        if (unlink(s->path) < 0) {
            simple_resp(s, F_DELETE_RP, 1, 3007, strerror(errno), 0);
            fail_group(s);
        } else {
            s->selected[0] = 0;
            simple_resp(s, F_DELETE_RP, 0, 0, NULL, 0);
        }
        break;
    case F_READ_RQ:
        do_read(s);
        flush_out(s);
        break;
    case F_WRITE_RQ:
        s->writing = 1;
        s->wf = fopen(s->path, "ab");
        break;
    case F_DATA_END_RQ:
        s->writing = 0;
        if (s->wf)
            fclose(s->wf);
        s->wf = NULL;
        break;
    case F_TRANSFER_END_RQ:
        simple_resp(s, F_TRANSFER_END_RP, 0, 0, NULL, 0);
        flush_out(s);
        break;
    case F_LIST_RQ:
        if (s->version == PV_VERSION_2)
            do_list(s, pdu);
        else
            log_msg(LOG_ERROR, L, "F-LIST without FTAM version 2");
        break;
    case F_CANCEL_RQ:
        s->writing = 0;
        if (s->wf)
            fclose(s->wf);
        s->wf = NULL;
        simple_resp(s, F_CANCEL_RP, 0, 0, NULL, 0);
        flush_out(s);
        break;
    default:
        log_msg(LOG_ERROR, L, "unsupported PDU %s", ftam_pdu_name(tag));
        break;
    }
    if (!s->in_group)
        flush_out(s);
}

static int item_cb(void *arg, int ctx, const ber_tlv *v)
{
    srv_t *s = arg;
    if (ctx == s->ctx_pci) {
        if (T_CLASS(v->tag) == 0x80)
            handle_pdu(s, v);
        return 0;
    }
    if (s->writing && s->wf) {
        buf_t str;
        buf_init(&str);
        ber_get_string(v, &str);
        if (str.len)                /* empty line: data is NULL */
            fwrite(str.data, 1, str.len, s->wf);
        if (ctx == s->ctx_text)
            fputc('\n', s->wf);
        buf_free(&str);
    }
    return 0;
}

/* ---- association ------------------------------------------------------ */

static int associate(srv_t *s)
{
    buf_t      cn, finit, aare, cpa;
    pctx_list  ctxs;
    ber_tlv    apdu;
    int        has, accept[16];
    acse_apdu  a;

    buf_init(&cn);
    buf_t hold;
    buf_init(&hold);
    memset(&a, 0, sizeof a);
    if (ses_wait_connect(&s->ses, &s->tc, &cn, s->tsdu_limit) < 0 ||
        pres_parse_cp(cn.data, cn.len, &ctxs, &hold, &apdu, &has) < 0 || !has ||
        acse_parse(&apdu, &a) < 0 || a.tag != T_APPC(0) || !a.has_user ||
        a.user.tag != T_CTXC(F_INITIALIZE_RQ)) {
        log_msg(LOG_ERROR, L, "bad connect: %s", get_error());
        buf_free(&cn);
        buf_free(&hold);
        acse_free(&a);
        return -1;
    }
    for (int i = 0; i < ctxs.n; i++) {
        accept[i] = 1;
        if (strcmp(ctxs.as[i], OID_ACSE_AS) == 0)
            s->ctx_acse = ctxs.id[i];
        else if (strcmp(ctxs.as[i], OID_FTAM_PCI) == 0)
            s->ctx_pci = ctxs.id[i];
        else if (strcmp(ctxs.as[i], OID_FTAM_UNSTR_TEXT) == 0)
            s->ctx_text = ctxs.id[i];
        else if (strcmp(ctxs.as[i], OID_NBS9_AS) == 0)
            s->ctx_nbs9 = ctxs.id[i];
        else if (strcmp(ctxs.as[i], OID_FTAM_UNSTR_BIN) == 0)
            s->ctx_bin = ctxs.id[i];
        else
            accept[i] = 0;
        log_msg(LOG_INFO, L, "context %d %s %s", ctxs.id[i], ctxs.as[i],
                accept[i] ? "accepted" : "rejected");
    }

    /* negotiate */
    const ber_tlv *rq = &a.user;
    ber_tlv  t;
    uint32_t sc = SC_TRANSFER, fu = 0, ag = 0, pv = PV_VERSION_1;
    char     pw[256] = "";
    if (ber_find(rq, T_CTX(0), &t))
        ber_get_bits(&t, &pv);
    if (ber_find(rq, T_CTX(3), &t))
        ber_get_bits(&t, &sc);
    if (ber_find(rq, T_CTX(4), &t))
        ber_get_bits(&t, &fu);
    if (ber_find(rq, T_CTX(5), &t))
        ber_get_bits(&t, &ag);
    if (ber_find(rq, FT_PASSWORD, &t)) {
        ber_rd  r;
        ber_tlv in;
        ber_enter(&t, &r);
        if (ber_next(&r, &in) > 0)
            ber_get_cstr(&in, pw, sizeof pw);
    }
    uint32_t chosen = (sc & SC_TRANSFER_MGMT) ? SC_TRANSFER_MGMT :
                      (sc & SC_TRANSFER) ? SC_TRANSFER :
                      (sc & SC_MANAGEMENT) ? SC_MANAGEMENT : SC_UNCONSTRAINED;
    s->version = ((pv & PV_VERSION_2) && !s->no_v2) ? PV_VERSION_2 : PV_VERSION_1;
    s->fu = fu & (FU_READ | FU_WRITE | FU_LIMITED_MGMT | FU_ENHANCED_MGMT | FU_GROUPING |
                  (s->version == PV_VERSION_2 ? FU_LIMITED_FS : 0));
    s->attr_groups = ag & AG_STORAGE;
    int reject = s->password && strcmp(pw, s->password) != 0;

    buf_init(&finit);
    ber_enc e;
    ber_enc_init(&e, &finit);
    ber_begin(&e, T_CTXC(F_INITIALIZE_RP));
    if (reject) {
        ber_int(&e, FT_STATE_RESULT, 1);
        ber_int(&e, FT_ACTION_RESULT, 2);
    }
    ber_bits(&e, T_CTX(0), s->version);
    ber_str(&e, T_CTX(1), "ftamd test responder");
    ber_bits(&e, T_CTX(3), chosen);
    ber_bits(&e, T_CTX(4), s->fu);
    ber_bits(&e, T_CTX(5), s->attr_groups);
    ber_int(&e, T_CTX(6), 0);
    ber_begin(&e, T_CTXC(7));
    ber_oid(&e, FT_DOC_TYPE_NAME, OID_FTAM_1);
    ber_oid(&e, FT_DOC_TYPE_NAME, OID_FTAM_3);
    ber_oid(&e, FT_DOC_TYPE_NAME, OID_NBS9_DOC);
    ber_end(&e);
    if (reject)
        ftam_enc_diagnostic(&e, 2, 2020, 5, 5, "wrong password");
    ber_end(&e);

    buf_init(&aare);
    buf_init(&cpa);
    acse_build_aare(&aare, OID_FTAM_APP_CTX, reject ? 1 : 0, reject ? 1 : 0,
                    s->ctx_pci, finit.data, finit.len);
    pres_build_cpa(&cpa, &ctxs, accept, s->ctx_acse, aare.data, aare.len);
    s->ses.sur = SUR_DUPLEX;
    int rc = ses_accept(&s->ses, cpa.data, cpa.len);
    log_msg(LOG_INFO, L, "association %s", reject ? "rejected (bad password)" : "accepted");
    buf_free(&cn);
    buf_free(&hold);
    acse_free(&a);
    buf_free(&finit);
    buf_free(&aare);
    buf_free(&cpa);
    return rc < 0 ? -1 : (reject ? 1 : 0);
}

static void serve(int fd, const char *dir, const char *password, const char *pcap,
                  const srv_opts *so)
{
    srv_t   s;
    trace_t tr;
    int     tracing = 0;

    memset(&s, 0, sizeof s);
    s.dir = dir;
    s.password = password;
    s.pdv_mode = so->pdv_mode;
    s.ext_concat = so->ext_concat;
    s.no_v2 = so->no_v2;
    acse_set_user_encoding(so->acse_encoding);
    pres_set_segment(so->segment);
    s.tsdu_limit = so->tsdu_limit;
    buf_init(&s.out);
    buf_init(&s.octets);
    if (pcap && trace_open(&tr, pcap, XOT_PORT, 40000) == 0)
        tracing = 1;
    if (x25_accept(&s.vc, fd, 1024, 7, 30000, tracing ? &tr : NULL) < 0) {
        log_msg(LOG_ERROR, L, "call setup failed: %s", get_error());
        goto done;
    }
    s.vc.use_rej = so->use_rej;
    s.vc.test_drop = so->drop;
    s.vc.t25_ms = so->t25_ms;
    s.vc.rx_limit = so->rx_limit;
    if (so->qdata_len && x25_send_qualified(&s.vc, so->qdata, so->qdata_len) < 0) {
        log_msg(LOG_ERROR, L, "qualified data failed: %s", get_error());
        goto done;
    }
    if (so->hold_ms)
        x25_hold(&s.vc, so->hold_ms);
    if (so->intr_len && x25_interrupt(&s.vc, so->intr, so->intr_len) < 0) {
        log_msg(LOG_ERROR, L, "interrupt failed: %s", get_error());
        goto done;
    }
    if (tp0_accept(&s.tc, &s.vc, 2048) < 0) {
        log_msg(LOG_ERROR, L, "connection setup failed: %s", get_error());
        goto done;
    }
    int arc = associate(&s);
    if (arc != 0) {
        /* wait for the initiator to clear the call */
        buf_t tmp;
        buf_init(&tmp);
        while (x25_recv(&s.vc, &tmp) == 0)
            ;
        buf_free(&tmp);
        goto done;
    }

    buf_t ud;
    buf_init(&ud);
    for (;;) {
        int ev;
        if (ses_recv(&s.ses, &ev, &ud) < 0) {
            log_msg(LOG_INFO, L, "connection ended: %s", get_error());
            break;
        }
        if (ev == SES_EV_DATA) {
            if (pres_parse_ud(ud.data, ud.len, item_cb, &s) < 0)
                log_msg(LOG_ERROR, L, "bad P-DATA: %s", get_error());
            flush_out(&s);
            continue;
        }
        if (ev == SES_EV_FINISH) {
            buf_t term, rlre, out;
            ber_enc e;
            buf_init(&term);
            buf_init(&rlre);
            buf_init(&out);
            ber_enc_init(&e, &term);
            ber_begin(&e, T_CTXC(F_TERMINATE_RP));
            ber_begin(&e, FT_CHARGING);
            ber_begin(&e, T_SEQ);
            ber_str(&e, T_CTX(0), "test");
            ber_str(&e, T_CTX(1), "units");
            ber_int(&e, T_CTX(2), 0);
            ber_end(&e);
            ber_end(&e);
            ber_end(&e);
            acse_build_rlre(&rlre, s.ctx_pci, term.data, term.len);
            pres_user_data(&out, s.ctx_acse, rlre.data, rlre.len);
            log_msg(LOG_INFO, L, "release: -> F-TERMINATE-response");
            ses_disconnect(&s.ses, out.data, out.len);
            buf_free(&term);
            buf_free(&rlre);
            buf_free(&out);
            /* initiator clears the network connection */
            while (x25_recv(&s.vc, &ud) == 0)
                ;
            break;
        }
        if (ev == SES_EV_ABORT) {
            log_msg(LOG_INFO, L, "association aborted by initiator");
            while (x25_recv(&s.vc, &ud) == 0)
                ;
            break;
        }
    }
    buf_free(&ud);
done:
    if (s.wf)
        fclose(s.wf);
    buf_free(&s.out);
    buf_free(&s.octets);
    ses_free(&s.ses);
    x25_close(&s.vc);
    if (tracing)
        trace_close(&tr);
}

int main(int argc, char **argv)
{
    int         port = XOT_PORT, once = 0, c;
    const char *dir = ".", *password = NULL, *pcap = NULL, *bind_addr = "127.0.0.1";
    srv_opts    so;

    memset(&so, 0, sizeof so);
    while ((c = getopt(argc, argv, "p:d:P:w:b:1vs:RD:OI:T:AE:S:N:B:Q:XL")) != -1) {
        switch (c) {
        case 'p': port = atoi(optarg); break;
        case 'd': dir = optarg; break;
        case 'P': pcap = optarg; break;
        case 'w': password = optarg; break;
        case 'b': bind_addr = optarg; break;
        case '1': once = 1; break;
        case 'v': log_level++; break;
        case 's': so.tsdu_limit = atoi(optarg); break;
        case 'R': so.use_rej = 1; break;
        case 'D': so.drop = atoi(optarg); so.use_rej = 1; break;
        case 'O': so.pdv_mode = PDV_OCTET; break;
        case 'A': so.pdv_mode = PDV_ARBITRARY; break;
        case 'E': so.acse_encoding = strcmp(optarg, "arbitrary") == 0 ?
                                     PDV_ARBITRARY : PDV_OCTET; break;
        case 'S': so.segment = (size_t)atoi(optarg); break;
        case 'T': so.t25_ms = atoi(optarg); break;
        case 'N': so.hold_ms = atoi(optarg); break;
        case 'X': so.ext_concat = 1; break;
        case 'L': so.no_v2 = 1; break;
        case 'B': so.rx_limit = (size_t)atoi(optarg); break;
        case 'Q': {
            int n = parse_hex(optarg, so.qdata, sizeof so.qdata);
            if (n < 1) {
                fprintf(stderr, "ftamd: -Q needs hex data\n");
                return 2;
            }
            so.qdata_len = (size_t)n;
            break;
        }
        case 'I': {
            int n = parse_hex(optarg, so.intr, sizeof so.intr);
            if (n < 1) {
                fprintf(stderr, "ftamd: -I needs 1..32 octets of hex\n");
                return 2;
            }
            so.intr_len = (size_t)n;
            break;
        }
        default:
            fprintf(stderr,
                "usage: ftamd [-p port] [-d dir] [-w password] [-P pcap] [-b addr]\n"
                "             [-1] [-v] [-s tsdu-limit] [-R] [-D n] [-T ms] [-O|-A]\n"
"             [-E enc] [-S n] [-I hex] [-N ms] [-B n] [-Q hex] [-X]\n"
                "  -s N   session TSDU maximum size (segmenting, if proposed)\n"
                "  -R     answer out-of-sequence X.25 data with REJ\n"
                "  -D N   test: discard the Nth received data packet (implies -R)\n"
"  -T MS  X.25 window rotation timer T25 (retransmission with -R)\n"
"  -N MS  send RNR after the call and stay not ready for MS ms\n"
"  -B N   send RNR when more than N received octets are queued\n"
"  -Q HEX send a qualified (Q-bit) NSDU after the call\n"
"  -L     FTAM version 1 only: no F-LIST, directories via NBS-9\n"
"  -X     test: send P-DATA as GT + MIP + DT (extended concatenation)\n"
"         when the initiator announced it can receive that\n"
                "  -O     send file data as octet-aligned PDVs\n"
"  -A     send file data as arbitrary (BIT STRING) PDVs\n"
"  -E ENC ACSE user-information encoding: octet or arbitrary\n"
"  -S N   segment size for constructed octet-aligned/arbitrary values\n"
                "  -I HEX send an X.25 interrupt with this data after the call\n");
            return 2;
        }
    }
    signal(SIGPIPE, SIG_IGN);
    int lfd = tcp_listen(bind_addr, port);
    if (lfd < 0) {
        fprintf(stderr, "ftamd: %s\n", get_error());
        return 1;
    }
    log_msg(LOG_INFO, L, "listening on %s:%d, serving %s", bind_addr, port, dir);
    do {
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            return 1;
        }
        serve(fd, dir, password, pcap, &so);
    } while (!once);
    close(lfd);
    return 0;
}
