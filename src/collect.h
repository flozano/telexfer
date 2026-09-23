/*
 * collect.h - poll a responder for files named with a constant plus a
 * rotating sequence number (e.g. AMA0001 .. AMA9999, then AMA0001 again),
 * the way switches such as a 5ESS present their billing (AMA/CDR) files.
 *
 * Each file is collected once, in sequence order, only once the switch
 * has finished it, and is on local disk (fsync'ed, size checked) before
 * the state is advanced and before any acknowledgement on the switch.
 */
#ifndef FTAM_COLLECT_H
#define FTAM_COLLECT_H

#include "ftam.h"

enum { ACK_NONE = 0, ACK_DELETE, ACK_RENAME };
enum { CLOSED_NEXT = 0, CLOSED_ANY };

/* exit codes of a poll */
enum {
    COLLECT_OK = 0,             /* collected, or nothing new */
    COLLECT_ERROR = 1,
    COLLECT_GAP = 3,            /* a sequence number was missing (logged) */
    COLLECT_BUSY = 4,           /* another collect holds the state lock */
    COLLECT_ACK_FAILED = 5,     /* collected, but acknowledgement failed */
};

typedef struct {
    const char *name_fmt;       /* remote name: one %d with optional 0/width */
    long        seq_min, seq_max;
    long        start;          /* first sequence without state, -1 = none */
    const char *dest;           /* local directory */
    const char *state_path;
    int         ack;            /* ACK_* */
    const char *ack_rename;     /* ACK_RENAME: new name, %s = old name */
    int         closed;         /* CLOSED_*: when is a file finished */
    int         lookahead;      /* sequence numbers probed past a gap */
    int         max_files;      /* per poll, 0 = no limit */
} collect_opts;

/* Validate name_fmt; returns 0 or -1 with the error set. */
int  collect_check_format(const char *fmt);
/* Take the state lock (before connecting, so a busy poll costs no call):
 * returns the lock fd, or -1 with *busy set when another poll holds it. */
int  collect_lock(const collect_opts *o, int *busy);
/* One poll over an established association; returns a COLLECT_* code. */
int  ftam_collect(ftam_conn *fc, const collect_opts *o);

#endif
