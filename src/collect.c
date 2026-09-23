/*
 * collect.c - rotating-sequence file collection (see collect.h).
 *
 * Deciding what to collect when files are never removed (ack none) and
 * names come back after the sequence wraps:
 *
 *  - generation: a file at the next sequence number is new only if it is
 *    not older than the last file collected (creation time, else
 *    modification time); otherwise it is last cycle's file, left in place.
 *    A per-sequence SHA-256 is the second line of defence, and the only
 *    one when the switch gives no times.
 *  - closed: a file is finished once a newer file exists further along
 *    the sequence (the switch has moved on).  Without times this cannot
 *    be told from last cycle's files, so --closed any is required.
 *  - gaps: a missing (or stale) sequence number followed by a newer file
 *    is logged, and collection continues past it.
 *
 * Commit order per file: temp file, fsync, size check, rename into place,
 * state saved atomically, then the acknowledgement on the switch.
 */
#include "collect.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "sha256.h"

static const char *L = "coll";

/* ---- names ---------------------------------------------------------------- */

int collect_check_format(const char *fmt)
{
    int convs = 0;
    for (const char *p = fmt; *p; p++) {
        if (*p != '%')
            continue;
        if (p[1] == '%') {
            p++;
            continue;
        }
        p++;
        if (*p == '0')
            p++;
        int width = 0;
        while (*p >= '0' && *p <= '9')
            width = width * 10 + (*p++ - '0');
        if (*p != 'd' || width > 18) {
            set_error("--name: only one %%d (with optional 0 and width) is allowed");
            return -1;
        }
        convs++;
    }
    if (convs != 1) {
        set_error("--name must contain exactly one %%d for the sequence number");
        return -1;
    }
    return 0;
}

static void fmt_name(const char *fmt, long seq, char *out, size_t max)
{
    size_t pos = 0;
    for (const char *p = fmt; *p && pos + 1 < max; p++) {
        if (*p != '%') {
            out[pos++] = *p;
            continue;
        }
        if (p[1] == '%') {
            out[pos++] = '%';
            p++;
            continue;
        }
        char spec[16] = "%";
        size_t k = 1;
        while (p[1] != 'd' && k < sizeof spec - 3)
            spec[k++] = *++p;
        spec[k++] = 'l';
        spec[k++] = 'd';
        spec[k] = 0;
        p++;                                    /* the 'd' */
        int w = snprintf(out + pos, max - pos, spec, seq);
        if (w > 0)
            pos += (size_t)w < max - pos ? (size_t)w : max - pos - 1;
    }
    out[pos] = 0;
}

/* %s in the rename template = the original name */
static void fmt_rename(const char *tmpl, const char *name, char *out, size_t max)
{
    size_t pos = 0;
    for (const char *p = tmpl; *p && pos + 1 < max; p++) {
        if (p[0] == '%' && p[1] == 's') {
            int w = snprintf(out + pos, max - pos, "%s", name);
            if (w > 0)
                pos += (size_t)w < max - pos ? (size_t)w : max - pos - 1;
            p++;
        } else {
            out[pos++] = *p;
        }
    }
    out[pos] = 0;
}

static long seq_next(const collect_opts *o, long s)
{
    return s >= o->seq_max ? o->seq_min : s + 1;
}

/* ---- GeneralizedTime ---------------------------------------------------- */

/* "YYYYMMDDHH[MM[SS]][.fff][Z|+hhmm|-hhmm]" -> epoch seconds, -1 if unknown */
static long long gtime(const char *s)
{
    int f[6] = { 0, 0, 0, 0, 0, 0 };
    int widths[6] = { 4, 2, 2, 2, 2, 2 };
    const char *p = s;
    int got = 0;
    for (int i = 0; i < 6; i++) {
        int v = 0;
        for (int k = 0; k < widths[i]; k++) {
            if (*p < '0' || *p > '9')
                goto done;
            v = v * 10 + (*p++ - '0');
        }
        f[i] = v;
        got++;
    }
done:
    if (got < 4)
        return -1;
    if (*p == '.' || *p == ',')
        for (p++; *p >= '0' && *p <= '9'; p++)
            ;
    long off = 0;
    if ((*p == '+' || *p == '-') && strlen(p) >= 5) {
        int hh = (p[1] - '0') * 10 + (p[2] - '0'), mm = (p[3] - '0') * 10 + (p[4] - '0');
        off = (hh * 60 + mm) * 60 * (*p == '+' ? 1 : -1);
    }
    /* no zone: local time of the switch; consistent for comparisons */
    struct tm tm;
    memset(&tm, 0, sizeof tm);
    tm.tm_year = f[0] - 1900;
    tm.tm_mon = f[1] - 1;
    tm.tm_mday = f[2];
    tm.tm_hour = f[3];
    tm.tm_min = f[4];
    tm.tm_sec = f[5];
    return (long long)timegm(&tm) - off;
}

/* the time that orders generations: creation, else modification */
static long long file_time(const ftam_dirent *e)
{
    long long t = e->ctime[0] ? gtime(e->ctime) : -1;
    return t >= 0 ? t : (e->mtime[0] ? gtime(e->mtime) : -1);
}

/* ---- state ---------------------------------------------------------------- */

typedef struct {
    int       have;
    long long time;             /* -1 unknown */
    long long size;
    char      sha[65];
} seq_rec;

typedef struct {
    int      have;              /* a state file existed */
    long     next;
    long     last_seq;          /* -1 = nothing collected yet */
    seq_rec *rec;               /* indexed by seq - seq_min */
    long     nrec;
} coll_state;

static seq_rec *rec_of(const collect_opts *o, coll_state *st, long s)
{
    return &st->rec[s - o->seq_min];
}

static int state_load(const collect_opts *o, coll_state *st)
{
    memset(st, 0, sizeof *st);
    st->nrec = o->seq_max - o->seq_min + 1;
    st->rec = calloc((size_t)st->nrec, sizeof *st->rec);
    st->last_seq = -1;
    if (!st->rec) {
        set_error("out of memory for %ld sequence numbers", st->nrec);
        return -1;
    }
    FILE *f = fopen(o->state_path, "r");
    if (!f) {
        if (errno == ENOENT)
            return 0;
        set_error("%s: %s", o->state_path, strerror(errno));
        return -1;
    }
    char line[512];
    int  lineno = 0;
    while (fgets(line, sizeof line, f)) {
        lineno++;
        if (line[0] == '#' || line[0] == '\n')
            continue;
        long      seq;
        char      t[32], sha[80];
        long long size;
        if (sscanf(line, "next %ld", &seq) == 1) {
            st->next = seq;
            st->have = 1;
        } else if (sscanf(line, "last %ld", &seq) == 1) {
            st->last_seq = seq;
        } else if (sscanf(line, "seq %ld %31s %lld %79s", &seq, t, &size, sha) == 4) {
            if (seq < o->seq_min || seq > o->seq_max || strlen(sha) != 64)
                continue;                       /* range changed: ignore */
            seq_rec *r = rec_of(o, st, seq);
            r->have = 1;
            r->time = strcmp(t, "-") == 0 ? -1 : atoll(t);
            r->size = size;
            memcpy(r->sha, sha, 65);
        } else {
            fclose(f);
            set_error("%s:%d: unrecognised line", o->state_path, lineno);
            return -1;
        }
    }
    fclose(f);
    if (st->last_seq >= 0 && (st->last_seq < o->seq_min || st->last_seq > o->seq_max ||
                              !rec_of(o, st, st->last_seq)->have))
        st->last_seq = -1;                      /* range changed: start over */
    if (st->have && (st->next < o->seq_min || st->next > o->seq_max)) {
        set_error("%s: next sequence %ld outside --seq-range", o->state_path, st->next);
        return -1;
    }
    return 0;
}

static int fsync_dir_of(const char *path)
{
    char dir[4096];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (!slash)
        snprintf(dir, sizeof dir, ".");
    else if (slash == dir)
        dir[1] = 0;                             /* file in "/" */
    else
        *slash = 0;
    int fd = open(dir, O_RDONLY);
    if (fd < 0)
        return -1;
    fsync(fd);
    close(fd);
    return 0;
}

/* Write to a temp file, fsync, rename over: the state is never torn. */
static int state_save(const collect_opts *o, const coll_state *st)
{
    char tmp[4096];
    snprintf(tmp, sizeof tmp, "%s.tmp", o->state_path);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        set_error("%s: %s", tmp, strerror(errno));
        return -1;
    }
    fprintf(f, "# telexfer collect state: %s, sequence %ld-%ld\n",
            o->name_fmt, o->seq_min, o->seq_max);
    fprintf(f, "next %ld\n", st->next);
    if (st->last_seq >= 0)
        fprintf(f, "last %ld\n", st->last_seq);
    for (long i = 0; i < st->nrec; i++) {
        const seq_rec *r = &st->rec[i];
        if (!r->have)
            continue;
        if (r->time >= 0)
            fprintf(f, "seq %ld %lld %lld %s\n", o->seq_min + i, r->time, r->size, r->sha);
        else
            fprintf(f, "seq %ld - %lld %s\n", o->seq_min + i, r->size, r->sha);
    }
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        set_error("%s: %s", tmp, strerror(errno));
        fclose(f);
        return -1;
    }
    fclose(f);
    if (rename(tmp, o->state_path) != 0) {
        set_error("%s: %s", o->state_path, strerror(errno));
        return -1;
    }
    fsync_dir_of(o->state_path);
    return 0;
}

int collect_lock(const collect_opts *o, int *busy)
{
    char path[4096];
    *busy = 0;
    snprintf(path, sizeof path, "%s.lock", o->state_path);
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        set_error("%s: %s", path, strerror(errno));
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        *busy = errno == EWOULDBLOCK;
        set_error("%s: another collect is running", path);
        close(fd);
        return -1;
    }
    return fd;
}

/* ---- one file ----------------------------------------------------------- */

static void stamp(long long t, char *out, size_t max)
{
    time_t    tt = t >= 0 ? (time_t)t : time(NULL);
    struct tm tm;
    gmtime_r(&tt, &tm);
    strftime(out, max, "%Y%m%dT%H%M%SZ", &tm);
}

enum { GOT_NEW, GOT_OLD, GOT_ERROR };

/*
 * Download seq into dest and record it.  GOT_OLD: the content is the one
 * already collected for this sequence number (last cycle's file).
 */
static int collect_one(ftam_conn *fc, const collect_opts *o, coll_state *st,
                       long s, const char *name, const ftam_dirent *info,
                       char *local, size_t localmax, char *sha)
{
    char      tmp[4096];
    long long bytes = 0, t = file_time(info);
    char      base[512];

    /* local names never collide across wraps: name + time */
    snprintf(base, sizeof base, "%s", strrchr(name, '/') ? strrchr(name, '/') + 1 : name);
    snprintf(tmp, sizeof tmp, "%s/.%s.part", o->dest, base);
    FILE *f = fopen(tmp, "wb");
    if (!f) {
        set_error("%s: %s", tmp, strerror(errno));
        return GOT_ERROR;
    }
    int rc = ftam_get(fc, name, f, 3, &bytes);
    int werr = fflush(f) != 0 || fsync(fileno(f)) != 0;
    if (fclose(f) != 0)
        werr = 1;
    if (rc < 0 || werr) {
        if (werr && rc == 0)
            set_error("%s: %s", tmp, strerror(errno));
        unlink(tmp);
        return GOT_ERROR;
    }
    if (info->size >= 0 && bytes != info->size) {
        set_error("%s: received %lld octets, the switch reports %lld", name, bytes,
                  info->size);
        unlink(tmp);
        return GOT_ERROR;
    }
    if (sha256_file(tmp, sha) < 0) {
        set_error("%s: cannot read back for SHA-256", tmp);
        unlink(tmp);
        return GOT_ERROR;
    }
    seq_rec *r = rec_of(o, st, s);
    if (r->have && strcmp(r->sha, sha) == 0 && (t < 0 || r->time < 0 || t == r->time)) {
        unlink(tmp);
        return GOT_OLD;
    }

    char ts[32];
    stamp(t, ts, sizeof ts);
    snprintf(local, localmax, "%s/%s.%s", o->dest, base, ts);
    struct stat sb;
    for (int n = 1; stat(local, &sb) == 0; n++) {
        char have[65];
        /* same content already there: a crash after rename, before state */
        if (sha256_file(local, have) == 0 && strcmp(have, sha) == 0) {
            unlink(tmp);
            goto recorded;
        }
        snprintf(local, localmax, "%s/%s.%s.%d", o->dest, base, ts, n);
    }
    if (rename(tmp, local) != 0) {
        set_error("%s: %s", local, strerror(errno));
        unlink(tmp);
        return GOT_ERROR;
    }
    fsync_dir_of(local);
recorded:
    r->have = 1;
    r->time = t;
    r->size = bytes;
    memcpy(r->sha, sha, 65);
    st->last_seq = s;
    st->next = seq_next(o, s);
    if (state_save(o, st) < 0)
        return GOT_ERROR;
    char when[32] = "-";
    if (t >= 0)
        stamp(t, when, sizeof when);
    printf("collected seq=%ld name=%s size=%lld time=%s sha256=%s local=%s\n",
           s, name, bytes, when, sha, local);
    fflush(stdout);
    return GOT_NEW;
}

/* ---- the poll ----------------------------------------------------------------- */

typedef struct {
    int         exists;         /* 1 yes, 0 no, -1 error */
    ftam_dirent info;
    long long   time;
} probe;

static int do_probe(ftam_conn *fc, const collect_opts *o, long s, probe *p)
{
    char name[512];
    fmt_name(o->name_fmt, s, name, sizeof name);
    int rc = ftam_stat(fc, name, &p->info);
    p->exists = rc == 0 ? 1 : rc == 1 ? 0 : -1;
    p->time = rc == 0 ? file_time(&p->info) : -1;
    log_msg(LOG_DEBUG, L, "probe %s: %s", name,
            rc == 0 ? "present" : rc == 1 ? "absent" : "error");
    return p->exists < 0 ? -1 : 0;
}

/* A file at s is from the current cycle (not older than the last one
 * collected).  1 yes, 0 no, -1 unknown (no times). */
static int is_current(const coll_state *st, long long last_time, const probe *p)
{
    if (!p->exists)
        return 0;
    if (st->last_seq < 0)
        return 1;                               /* nothing collected yet */
    if (p->time < 0 || last_time < 0)
        return -1;
    return p->time >= last_time;
}

int ftam_collect(ftam_conn *fc, const collect_opts *o)
{
    coll_state st;
    int        result = COLLECT_OK, collected = 0;

    if (state_load(o, &st) < 0)
        return COLLECT_ERROR;
    if (!st.have) {
        if (o->start < 0) {
            set_error("no state in %s yet: give --start with the first sequence "
                      "number to collect", o->state_path);
            free(st.rec);
            return COLLECT_ERROR;
        }
        st.next = o->start;
    }
    long long last_time = st.last_seq >= 0 ? rec_of(o, &st, st.last_seq)->time : -1;
    long      s = st.next;

    log_msg(LOG_INFO, L, "polling from sequence %ld", s);
    for (long steps = 0; steps < st.nrec; steps++) {
        char  name[512], local[4096], sha[65];
        probe p;

        if (o->max_files && collected >= o->max_files)
            break;
        fmt_name(o->name_fmt, s, name, sizeof name);
        if (do_probe(fc, o, s, &p) < 0) {
            result = COLLECT_ERROR;
            break;
        }
        int cur = is_current(&st, last_time, &p);
        /* without the file's own time neither the generation nor the
         * "newer file follows" rule can be applied: refuse rather than
         * wait forever for a file that can never look closed */
        if (p.exists && p.time < 0 && o->closed != CLOSED_ANY) {
            set_error("%s: the switch reports no creation or modification time, so "
                      "this cycle's files cannot be told from the last one's; use "
                      "--closed any if it only shows finished files", name);
            result = COLLECT_ERROR;
            break;
        }

        if (cur != 0) {
            /* present and (possibly) current: finished yet? */
            int closed = o->closed == CLOSED_ANY;
            for (long k = 1, j = seq_next(o, s); !closed && k <= o->lookahead;
                 k++, j = seq_next(o, j)) {
                probe q;
                if (do_probe(fc, o, j, &q) < 0) {
                    result = COLLECT_ERROR;
                    goto out;
                }
                if (q.exists && q.time >= 0 && p.time >= 0 && q.time >= p.time)
                    closed = 1;
            }
            if (!closed) {
                log_msg(LOG_INFO, L, "%s is still being written", name);
                break;
            }
            int got = collect_one(fc, o, &st, s, name, &p.info, local, sizeof local, sha);
            if (got == GOT_ERROR) {
                result = COLLECT_ERROR;
                break;
            }
            if (got == GOT_OLD) {
                log_msg(LOG_INFO, L, "%s is last cycle's file (same SHA-256)", name);
                break;
            }
            collected++;
            last_time = rec_of(o, &st, s)->time;
            /* the file is safe locally and recorded: a failed
             * acknowledgement is reported, never undone */
            int ack_rc = 0;
            char to[512] = "";
            if (o->ack == ACK_DELETE) {
                ack_rc = ftam_delete(fc, name);
            } else if (o->ack == ACK_RENAME) {
                fmt_rename(o->ack_rename, name, to, sizeof to);
                ack_rc = ftam_rename(fc, name, to);
            }
            if (ack_rc < 0) {
                printf("ack-failed seq=%ld name=%s action=%s error=\"%s\"\n", s, name,
                       o->ack == ACK_DELETE ? "delete" : "rename", get_error());
                result = COLLECT_ACK_FAILED;
            }
            fflush(stdout);
            s = seq_next(o, s);
            continue;
        }

        /* absent or last cycle's: a gap, or simply nothing new yet */
        long j = seq_next(o, s), found = -1;
        for (long k = 1; k <= o->lookahead; k++, j = seq_next(o, j)) {
            probe q;
            if (do_probe(fc, o, j, &q) < 0) {
                result = COLLECT_ERROR;
                goto out;
            }
            if (is_current(&st, last_time, &q) == 1) {
                found = j;
                break;
            }
        }
        if (found < 0)
            break;                              /* nothing new */
        for (long g = s; g != found; g = seq_next(o, g)) {
            char gname[512];
            fmt_name(o->name_fmt, g, gname, sizeof gname);
            printf("gap seq=%ld name=%s\n", g, gname);
            log_msg(LOG_ERROR, L, "sequence %ld (%s) is missing: possible lost records",
                    g, gname);
        }
        fflush(stdout);
        if (result == COLLECT_OK)               /* ack failure outranks a gap */
            result = COLLECT_GAP;
        s = found;
        st.next = found;
        if (state_save(o, &st) < 0) {
            result = COLLECT_ERROR;
            break;
        }
    }
out:
    log_msg(LOG_INFO, L, "%d file(s) collected, next sequence %ld", collected, st.next);
    free(st.rec);
    return result;
}
