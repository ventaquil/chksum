#ifndef CHKSUM_H
#define CHKSUM_H

#include <stdint.h>
#include <stdlib.h>

// MD5

struct MD5;

struct MD5 *chksum_hash_md5_new(void);

size_t chksum_hash_md5_update(struct MD5 *hash, const uint8_t *data, size_t length);

uint8_t *chksum_hash_md5_digest(struct MD5 *hash);

char *chksum_hash_md5_hexdigest(struct MD5 *hash);

void chksum_hash_md5_drop(struct MD5 *hash);

// SHA-1

struct SHA1;

struct SHA1 *chksum_hash_sha1_new(void);

size_t chksum_hash_sha1_update(struct SHA1 *hash, const uint8_t *data, size_t length);

uint8_t *chksum_hash_sha1_digest(struct SHA1 *hash);

char *chksum_hash_sha1_hexdigest(struct SHA1 *hash);

void chksum_hash_sha1_drop(struct SHA1 *hash);

#endif // CHKSUM_H
