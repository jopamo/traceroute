#ifndef TEST_UNIT_COMMON_RNG_H
#define TEST_UNIT_COMMON_RNG_H

#include <stdint.h>

static uint32_t test_rng_state = 0xDEADBEEF;

static inline void test_rng_seed(uint32_t seed) {
    test_rng_state = seed;
}

static inline uint32_t test_rng_next(void) {
    // Simple Xorshift
    test_rng_state ^= test_rng_state << 13;
    test_rng_state ^= test_rng_state >> 17;
    test_rng_state ^= test_rng_state << 5;
    return test_rng_state;
}

#endif /* TEST_UNIT_COMMON_RNG_H */
