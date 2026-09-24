/*
 * ftam.h - FTAM initiator (ISO 8571) over the OSI upper layers,
 * TP0 and X.25/XOT.
 */
#ifndef FTAM_FTAM_H
#define FTAM_FTAM_H

#include <stdio.h>

#include "ftam_pdu.h"
#include "pres.h"
#include "rfc1006.h"
#include "session.h"
#include "x25.h"
#include "x25linux.h"

/* network service under TP0 */
enum { TRANSPORT_XOT = 0, TRANSPORT_RFC1006, TRANSPORT_X25 };

typedef struct {
    int         transport;          /* TRANSPORT_XOT, _RFC1006 or _X25 (kernel) */
    const char *host;
    int         port;
    /* X.25 (XOT only) */
    x25_params  x25;
    int         timeout_ms;
    const char *pcap_path;
    /* OSI addressing */
    uint8_t     tsel_calling[32], tsel_called[32];
    size_t      tsel_calling_len, tsel_called_len;
    uint8_t     ssel_calling[16], ssel_called[16];
    size_t      ssel_calling_len, ssel_called_len;
    uint8_t     psel_calling[16], psel_called[16];
    size_t      psel_calling_len, psel_called_len;
    int         tpdu_size;
    acse_params acse;
    /* FTAM regime */
    const char *user;
    const char *password;
    const char *account;
    uint32_t    service_class;      /* proposed classes (bits) */
    uint32_t    functional_units;   /* proposed FUs (bits) */
    uint32_t    attribute_groups;
    size_t      chunk_size;         /* bytes per data element on write */
    int         pdv_mode;           /* file data PDVs: PDV_SINGLE/OCTET/ARBITRARY */
    int         acse_encoding;      /* ACSE user-information EXTERNAL encoding */
    size_t      pdv_segment;        /* segment size of constructed encodings */
    int         tsdu_size;          /* session segmenting: TSDU max, 0 = off */
    int         ext_concat;         /* announce extended concatenation */
    int         propose_v2;         /* offer FTAM protocol version 2 (F-LIST) */
    int         x25_pkt_given;      /* --packet-size / --window were given */
    int         x25_win_given;
    size_t      impl_pad;           /* test hook: grow the connect user data */
    uint8_t     interrupt_data[X25_MAX_INT_DATA];
    size_t      interrupt_len;      /* send an X.25 interrupt after call setup */
    uint8_t     qdata[256];
    size_t      qdata_len;          /* send a Q-bit NSDU after call setup */
    int         test_drop;          /* test hook, see x25_vc.test_drop */
} ftam_opts;

typedef struct item_q {
    struct item_q *next;
    int            ctx;
    size_t         len;
    uint8_t        data[];
} item_q;

enum { CTX_ACSE = 0, CTX_PCI, CTX_TEXT, CTX_BIN, CTX_NBS9, CTX_COUNT };

/* how to list a directory */
enum { LIST_AUTO = 0, LIST_FLIST, LIST_NBS9 };

typedef struct {
    int         fd;
    trace_t     trace;
    int         tracing;
    x25_vc      vc;                 /* TRANSPORT_XOT */
    tpkt_conn   tpkt;               /* TRANSPORT_RFC1006 */
    kx25_conn   kx25;               /* TRANSPORT_X25 */
    tp0_conn    tc;
    ses_conn    ses;
    pctx_t      ctx[CTX_COUNT];
    int         associated;
    /* negotiated regime parameters */
    uint32_t    service_class;
    uint32_t    fu;
    uint32_t    attr_groups;
    uint32_t    version;            /* negotiated Protocol-Version bits */
    size_t      chunk_size;
    int         pdv_mode;
    item_q     *qhead, *qtail;
} ftam_conn;

void ftam_opts_default(ftam_opts *o);

int  ftam_connect(ftam_conn *fc, const ftam_opts *o);
/* doctype: 1 = FTAM-1 (text), 3 = FTAM-3 (binary) */
int  ftam_get(ftam_conn *fc, const char *remote, FILE *out, int doctype,
              long long *bytes);
int  ftam_put(ftam_conn *fc, FILE *in, const char *remote, int doctype,
              int override, int append, long long *bytes);
int  ftam_delete(ftam_conn *fc, const char *remote);
int  ftam_attributes(ftam_conn *fc, const char *remote, FILE *out);
int  ftam_rename(ftam_conn *fc, const char *from, const char *to);
/* Attributes of one file: 0 exists (info filled), 1 does not exist,
 * -1 error.  Creation/modification time and size need the storage
 * attribute group. */
int  ftam_stat(ftam_conn *fc, const char *remote, ftam_dirent *info);
/*
 * List a directory (dir may be NULL: the responder's current directory).
 * LIST_FLIST uses F-LIST (FTAM version 2, limited filestore management),
 * LIST_NBS9 reads the directory as an NBS-9 file directory document,
 * LIST_AUTO picks F-LIST when negotiated, NBS-9 otherwise.
 */
int  ftam_list(ftam_conn *fc, const char *dir, int method, int long_format,
               FILE *out);
int  ftam_release(ftam_conn *fc);
void ftam_abort(ftam_conn *fc);
void ftam_close(ftam_conn *fc);

#endif
