/*
 * util.h - growable buffers, logging, error reporting, small parsers.
 */
#ifndef FTAM_UTIL_H
#define FTAM_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* ---- growable byte buffer ---------------------------------------------- */

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} buf_t;

void buf_init(buf_t *b);
void buf_free(buf_t *b);
void buf_reset(buf_t *b);
void buf_reserve(buf_t *b, size_t extra);
void buf_put(buf_t *b, const void *p, size_t n);
void buf_put8(buf_t *b, uint8_t v);
void buf_put16(buf_t *b, uint16_t v);           /* big endian */
void buf_insert(buf_t *b, size_t pos, const void *p, size_t n);
void buf_consume(buf_t *b, size_t n);           /* drop n bytes from front */

void *xmalloc(size_t n);
void *xrealloc(void *p, size_t n);

/* ---- logging ----------------------------------------------------------- */

enum { LOG_ERROR = 0, LOG_INFO = 1, LOG_DEBUG = 2, LOG_DUMP = 3 };

extern int log_level;

void log_msg(int level, const char *layer, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
void log_hex(int level, const char *layer, const char *what,
             const uint8_t *p, size_t n);

/* ---- error reporting (last error, thread-unsafe by design) ------------- */

void        set_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
const char *get_error(void);

/* ---- parsers ----------------------------------------------------------- */

/* Hex string ("0a1B2c", optional "0x" prefix, spaces/colons ignored). */
int parse_hex(const char *s, uint8_t *out, size_t max);

/*
 * OSI selector: "0x..." or "hex:..." -> binary, otherwise the literal
 * ASCII bytes of the string.  Returns length or -1.
 */
int parse_selector(const char *s, uint8_t *out, size_t max);

#endif
