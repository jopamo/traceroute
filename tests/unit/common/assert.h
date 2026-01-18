#ifndef TEST_UNIT_COMMON_ASSERT_H
#define TEST_UNIT_COMMON_ASSERT_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define ASSERT_EQ_INT(actual, expected)                                                                           \
    do {                                                                                                          \
        int _a = (actual);                                                                                        \
        int _e = (expected);                                                                                      \
        if (_a != _e) {                                                                                           \
            fprintf(stderr, "%s:%d: ASSERT_EQ_INT failed: actual %d, expected %d\n", __FILE__, __LINE__, _a, _e); \
            exit(1);                                                                                              \
        }                                                                                                         \
    } while (0)

#define ASSERT_EQ_U64(actual, expected)                                                                               \
    do {                                                                                                              \
        unsigned long long _a = (actual);                                                                             \
        unsigned long long _e = (expected);                                                                           \
        if (_a != _e) {                                                                                               \
            fprintf(stderr, "%s:%d: ASSERT_EQ_U64 failed: actual %llu, expected %llu\n", __FILE__, __LINE__, _a, _e); \
            exit(1);                                                                                                  \
        }                                                                                                             \
    } while (0)

#define ASSERT_EQ_STR(actual, expected)                                                                              \
    do {                                                                                                             \
        const char* _a = (actual);                                                                                   \
        const char* _e = (expected);                                                                                 \
        if (strcmp(_a, _e) != 0) {                                                                                   \
            fprintf(stderr, "%s:%d: ASSERT_EQ_STR failed: actual \"%s\", expected \"%s\"\n", __FILE__, __LINE__, _a, \
                    _e);                                                                                             \
            exit(1);                                                                                                 \
        }                                                                                                            \
    } while (0)

#define ASSERT_EQ_PTR(actual, expected)                                                                           \
    do {                                                                                                          \
        const void* _a = (actual);                                                                                \
        const void* _e = (expected);                                                                              \
        if (_a != _e) {                                                                                           \
            fprintf(stderr, "%s:%d: ASSERT_EQ_PTR failed: actual %p, expected %p\n", __FILE__, __LINE__, _a, _e); \
            exit(1);                                                                                              \
        }                                                                                                         \
    } while (0)

#define ASSERT_MEMEQ(actual, expected, len)                                      \
    do {                                                                         \
        const void* _a = (actual);                                               \
        const void* _e = (expected);                                             \
        size_t _l = (len);                                                       \
        if (memcmp(_a, _e, _l) != 0) {                                           \
            fprintf(stderr, "%s:%d: ASSERT_MEMEQ failed\n", __FILE__, __LINE__); \
            exit(1);                                                             \
        }                                                                        \
    } while (0)

#define ASSERT_OK(rc)                                                                                          \
    do {                                                                                                       \
        int _rc = (rc);                                                                                        \
        if (_rc < 0) {                                                                                         \
            fprintf(stderr, "%s:%d: ASSERT_OK failed: rc %d (errno %d: %s)\n", __FILE__, __LINE__, _rc, errno, \
                    strerror(errno));                                                                          \
            exit(1);                                                                                           \
        }                                                                                                      \
    } while (0)

#define ASSERT_TRUE(cond)                                                                  \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            fprintf(stderr, "%s:%d: ASSERT_TRUE failed: %s\n", __FILE__, __LINE__, #cond); \
            exit(1);                                                                       \
        }                                                                                  \
    } while (0)

#define ASSERT_ERR(rc, expected_errno)                                                                                \
    do {                                                                                                              \
        int _rc = (rc);                                                                                               \
        int _e = (expected_errno);                                                                                    \
        if (_rc != -1 || errno != _e) {                                                                               \
            fprintf(stderr, "%s:%d: ASSERT_ERR failed: actual rc %d, errno %d (%s); expected rc -1, errno %d (%s)\n", \
                    __FILE__, __LINE__, _rc, errno, strerror(errno), _e, strerror(_e));                               \
            exit(1);                                                                                                  \
        }                                                                                                             \
    } while (0)

#define ASSERT_ERR_CODE(rc, expected_err_code)                                                                       \
    do {                                                                                                             \
        int _rc = (rc);                                                                                              \
        int _e = -(expected_err_code);                                                                               \
        if (_rc != _e) {                                                                                             \
            fprintf(stderr, "%s:%d: ASSERT_ERR_CODE failed: actual %d (%s), expected %d (%s)\n", __FILE__, __LINE__, \
                    _rc, strerror(-_rc), _e, strerror(-_e));                                                         \
            exit(1);                                                                                                 \
        }                                                                                                            \
    } while (0)

#endif /* TEST_UNIT_COMMON_ASSERT_H */
