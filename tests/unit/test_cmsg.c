#include "common/assert.h"
#include "common/fixtures.h"
#include "io/parse.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/errqueue.h>
#include <arpa/inet.h>
#include <time.h>

void test_cmsg_parse_sock_extended_err_basic(void) {
    char control[256];
    struct msghdr msg = {0};
    msg.msg_control = control;
    msg.msg_controllen = CMSG_SPACE(sizeof(struct sock_extended_err) + sizeof(struct sockaddr_in));
    memset(control, 0, sizeof(control));

    struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_IP;
    cm->cmsg_type = IP_RECVERR;
    cm->cmsg_len = CMSG_LEN(sizeof(struct sock_extended_err) + sizeof(struct sockaddr_in));

    struct sock_extended_err* ee = (struct sock_extended_err*)CMSG_DATA(cm);
    ee->ee_origin = SO_EE_ORIGIN_ICMP;
    ee->ee_type = ICMP_TIME_EXCEEDED;

    struct sockaddr_in* sin = (struct sockaddr_in*)SO_EE_OFFENDER(ee);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inet_addr("1.2.3.4");

    CMSGInfo out;
    ASSERT_OK(parse_cmsgs(&msg, &out));
    ASSERT_EQ_PTR(out.ee, ee);
    ASSERT_EQ_INT(out.ee->ee_type, ICMP_TIME_EXCEEDED);
    ASSERT_EQ_INT(out.offender->sa_family, AF_INET);
}

void test_cmsg_parse_reject_truncated_cmsg(void) {
    char control[256];
    struct msghdr msg = {0};
    msg.msg_control = control;
    msg.msg_controllen = CMSG_SPACE(sizeof(struct sock_extended_err));
    memset(control, 0, sizeof(control));

    struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_IP;
    cm->cmsg_type = IP_RECVERR;
    cm->cmsg_len = CMSG_LEN(sizeof(struct sock_extended_err) - 1);  // Truncated

    CMSGInfo out;
    ASSERT_ERR_CODE(parse_cmsgs(&msg, &out), EBADMSG);
}

void test_cmsg_parse_handles_multiple_cmsgs_order_independent(void) {
    char control[512];
    struct msghdr msg = {0};
    msg.msg_control = control;
    msg.msg_controllen = CMSG_SPACE(sizeof(struct timespec)) + CMSG_SPACE(sizeof(struct sock_extended_err));
    memset(control, 0, sizeof(control));

    struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_TIMESTAMPNS;
    cm->cmsg_len = CMSG_LEN(sizeof(struct timespec));
    struct timespec* ts = (struct timespec*)CMSG_DATA(cm);
    ts->tv_sec = 123;
    ts->tv_nsec = 456;

    cm = CMSG_NXTHDR(&msg, cm);
    cm->cmsg_level = SOL_IP;
    cm->cmsg_type = IP_RECVERR;
    cm->cmsg_len = CMSG_LEN(sizeof(struct sock_extended_err));
    struct sock_extended_err* ee = (struct sock_extended_err*)CMSG_DATA(cm);
    ee->ee_origin = SO_EE_ORIGIN_ICMP;

    CMSGInfo out;
    ASSERT_OK(parse_cmsgs(&msg, &out));
    ASSERT_EQ_PTR(out.ee, ee);
    ASSERT_EQ_U64((uint64_t)out.timestamp, 123);
}

void test_cmsg_parse_scm_timestampns(void) {
    char control[256];
    struct msghdr msg = {0};
    msg.msg_control = control;
    msg.msg_controllen = CMSG_SPACE(sizeof(struct timespec));
    memset(control, 0, sizeof(control));

    struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_TIMESTAMPNS;
    cm->cmsg_len = CMSG_LEN(sizeof(struct timespec));
    struct timespec* ts = (struct timespec*)CMSG_DATA(cm);
    ts->tv_sec = 1000;
    ts->tv_nsec = 500000000;

    CMSGInfo out;
    ASSERT_OK(parse_cmsgs(&msg, &out));
    // Due to double precision, comparison might be slightly off but 0.5 should be exact
    if (out.timestamp < 1000.49 || out.timestamp > 1000.51) {
        fprintf(stderr, "Timestamp mismatch: %f\n", out.timestamp);
        exit(1);
    }
}

void register_test_cmsg(void) {
    test_cmsg_parse_sock_extended_err_basic();
    test_cmsg_parse_reject_truncated_cmsg();
    test_cmsg_parse_handles_multiple_cmsgs_order_independent();
    test_cmsg_parse_scm_timestampns();
}
