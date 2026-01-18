#include "common/assert.h"
#include "common/mocks.h"
#include "traceroute.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

/* Use common mocks */

/* Mock probe for testing */
static probe mock_pb;

void test_extension_mpls(void) {
    memset(&mock_pb, 0, sizeof(mock_pb));
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));

    /* ICMP Extension Header */
    buf[0] = 0x20;  // Version 2
    buf[1] = 0x00;
    buf[2] = 0x00;  // Checksum (0 means ignored if we don't calculate it)
    buf[3] = 0x00;

    /* MPLS Object */
    buf[4] = 0x00;
    buf[5] = 12;  // Length (4 header + 8 data = 2 labels)
    buf[6] = 1;   // Class 1 (MPLS)
    buf[7] = 1;   // C-Type 1

    /* Label 1: L=100, E=7, S=1, T=1 */
    uint32_t l1 = htonl((100 << 12) | (7 << 9) | (1 << 8) | 1);
    memcpy(&buf[8], &l1, 4);

    /* Label 2: L=200, E=0, S=0, T=255 */
    uint32_t l2 = htonl((200 << 12) | (0 << 9) | (0 << 8) | 255);
    memcpy(&buf[12], &l2, 4);

    handle_extensions(&mock_pb, (char*)buf, 16, 0);

    ASSERT_EQ_STR(mock_pb.ext, "MPLS:L=100,E=7,S=1,T=1/L=200,E=0,S=0,T=255");
    free(mock_pb.ext);
}

void test_extension_interface_info_index(void) {
    memset(&mock_pb, 0, sizeof(mock_pb));
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));

    buf[0] = 0x20;
    buf[4] = 0x00;
    buf[5] = 12;    // Length
    buf[6] = 2;     // Class 2 (Interface Info)
    buf[7] = 0x08;  // C-Type: Index only (Role=0, Index=1)

    uint32_t idx = htonl(123);
    memcpy(&buf[8], &idx, 4);

    handle_extensions(&mock_pb, (char*)buf, 16, 0);
    ASSERT_EQ_STR(mock_pb.ext, "INC:123");
    free(mock_pb.ext);
}

void test_extension_unknown(void) {
    memset(&mock_pb, 0, sizeof(mock_pb));
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));

    buf[0] = 0x20;
    buf[4] = 0x00;
    buf[5] = 12;   // Length
    buf[6] = 100;  // Unknown class
    buf[7] = 1;

    uint32_t val = htonl(0xdeadbeef);
    memcpy(&buf[8], &val, 4);

    handle_extensions(&mock_pb, (char*)buf, 16, 0);
    ASSERT_EQ_STR(mock_pb.ext, "100/1:deadbeef,00000000");
    free(mock_pb.ext);
}

void test_extension_malformed_short(void) {
    memset(&mock_pb, 0, sizeof(mock_pb));
    unsigned char buf[4];
    buf[0] = 0x20;

    handle_extensions(&mock_pb, (char*)buf, 4, 0);
    ASSERT_EQ_PTR(mock_pb.ext, NULL);
}

void test_extension_malformed_wrong_version(void) {
    memset(&mock_pb, 0, sizeof(mock_pb));
    unsigned char buf[8];
    buf[0] = 0x10;  // Version 1

    handle_extensions(&mock_pb, (char*)buf, 8, 0);
    ASSERT_EQ_PTR(mock_pb.ext, NULL);
}

void register_test_extension(void) {
    test_extension_mpls();
    test_extension_interface_info_index();
    test_extension_unknown();
    test_extension_malformed_short();
    test_extension_malformed_wrong_version();
}