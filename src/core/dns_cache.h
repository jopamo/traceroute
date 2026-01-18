#ifndef TRACEROUTE_CORE_DNS_CACHE_H
#define TRACEROUTE_CORE_DNS_CACHE_H

#include "types.h"
#include <stddef.h>

#define DNS_MAX_NAME_LEN 256

typedef struct {
    sockaddr_any addr;
    char name[DNS_MAX_NAME_LEN];
    uint64_t expiry;
    uint64_t last_used;
    int is_valid;
} DNSCacheEntry;

typedef struct {
    DNSCacheEntry* entries;
    size_t capacity;
    size_t count;
    uint64_t current_tick;
} DNSCache;

DNSCache* dns_cache_create(size_t capacity);
void dns_cache_destroy(DNSCache* cache);

/**
 * Inserts or updates a mapping.
 * ttl_sec: how long this entry is valid (0 for permanent/default)
 */
void dns_cache_insert(DNSCache* cache, const sockaddr_any* addr, const char* name, uint64_t now, uint64_t ttl_sec);

/**
 * Looks up a name for an address.
 * Returns pointer to name if found and not expired, NULL otherwise.
 */
const char* dns_cache_lookup(DNSCache* cache, const sockaddr_any* addr, uint64_t now);

#endif /* TRACEROUTE_CORE_DNS_CACHE_H */
