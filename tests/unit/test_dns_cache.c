#include "common/assert.h"
#include "core/dns_cache.h"
#include <netinet/in.h>
#include <arpa/inet.h>

static void make_addr(sockaddr_any* sa, const char* ip) {
    sa->sin.sin_family = AF_INET;
    sa->sin.sin_addr.s_addr = inet_addr(ip);
}

void test_dns_cache_insert_hit(void) {
    DNSCache* c = dns_cache_create(10);
    sockaddr_any sa;
    make_addr(&sa, "1.1.1.1");

    dns_cache_insert(c, &sa, "one.one.one.one", 100, 3600);

    const char* name = dns_cache_lookup(c, &sa, 150);
    ASSERT_EQ_STR(name, "one.one.one.one");

    dns_cache_destroy(c);
}

void test_dns_cache_negative_cache_hit(void) {
    // Negative cache is just caching an empty string or special marker
    // Here we test simply that we can cache arbitrary strings
    DNSCache* c = dns_cache_create(10);
    sockaddr_any sa;
    make_addr(&sa, "1.2.3.4");

    dns_cache_insert(c, &sa, "<NXDOMAIN>", 100, 60);

    const char* name = dns_cache_lookup(c, &sa, 110);
    ASSERT_EQ_STR(name, "<NXDOMAIN>");

    dns_cache_destroy(c);
}

void test_dns_cache_ttl_expiry(void) {
    DNSCache* c = dns_cache_create(10);
    sockaddr_any sa;
    make_addr(&sa, "10.0.0.1");

    dns_cache_insert(c, &sa, "router", 100, 10);  // Expire at 110

    ASSERT_EQ_STR(dns_cache_lookup(c, &sa, 105), "router");
    ASSERT_EQ_PTR(dns_cache_lookup(c, &sa, 111), NULL);

    dns_cache_destroy(c);
}

void test_dns_cache_lru_eviction(void) {
    DNSCache* c = dns_cache_create(2);
    sockaddr_any sa1, sa2, sa3;
    make_addr(&sa1, "1.1.1.1");
    make_addr(&sa2, "2.2.2.2");
    make_addr(&sa3, "3.3.3.3");

    dns_cache_insert(c, &sa1, "one", 100, 3600);
    dns_cache_insert(c, &sa2, "two", 100, 3600);

    // Access sa1 to make it MRU
    dns_cache_lookup(c, &sa1, 101);

    // Insert sa3, should evict sa2 (LRU)
    dns_cache_insert(c, &sa3, "three", 102, 3600);

    ASSERT_EQ_STR(dns_cache_lookup(c, &sa1, 103), "one");
    ASSERT_EQ_PTR(dns_cache_lookup(c, &sa2, 103), NULL);
    ASSERT_EQ_STR(dns_cache_lookup(c, &sa3, 103), "three");

    dns_cache_destroy(c);
}

void test_dns_cache_idna_or_invalid_names_handled(void) {
    DNSCache* c = dns_cache_create(10);
    sockaddr_any sa;
    make_addr(&sa, "8.8.8.8");

    // Just ensure it copies safely and terminates
    char long_name[300];
    memset(long_name, 'a', 299);
    long_name[299] = '\0';

    dns_cache_insert(c, &sa, long_name, 100, 60);

    const char* ret = dns_cache_lookup(c, &sa, 101);
    ASSERT_EQ_U64(strlen(ret), 255);  // Max len - 1

    dns_cache_destroy(c);
}

void register_test_dns_cache(void) {
    test_dns_cache_insert_hit();
    test_dns_cache_negative_cache_hit();
    test_dns_cache_ttl_expiry();
    test_dns_cache_lru_eviction();
    test_dns_cache_idna_or_invalid_names_handled();
}
