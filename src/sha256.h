/*
 * sha256.h - SHA-256 (FIPS 180-4), used to fingerprint collected files.
 */
#ifndef FTAM_SHA256_H
#define FTAM_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint64_t len;           /* bytes hashed so far */
    uint8_t  buf[64];
    size_t   fill;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *p, size_t n);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
/* Lower-case hex of the digest of a file; 0 ok, -1 on I/O error. */
int  sha256_file(const char *path, char hex[65]);

#endif
