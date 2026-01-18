#ifndef TEST_UNIT_COMMON_FIXTURES_H
#define TEST_UNIT_COMMON_FIXTURES_H

#include <stddef.h>

/**
 * decodes hex string into buffer
 * returns number of bytes decoded, or -1 on error
 */
int hex_decode(const char* hex, unsigned char* buf, size_t buf_len);

#endif /* TEST_UNIT_COMMON_FIXTURES_H */
