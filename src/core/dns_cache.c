#include "dns_cache.h"
#include <stdlib.h>
#include <string.h>

// Helper to compare addresses
static int addr_equal(const sockaddr_any* a, const sockaddr_any* b) {
    if (a->sa.sa_family != b->sa.sa_family)
        return 0;

    if (a->sa.sa_family == AF_INET) {
        return a->sin.sin_addr.s_addr == b->sin.sin_addr.s_addr;
    }
    else if (a->sa.sa_family == AF_INET6) {
        return memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr, sizeof(a->sin6.sin6_addr)) == 0;
    }
    return 0;
}

DNSCache* dns_cache_create(size_t capacity) {
    DNSCache* c = calloc(1, sizeof(DNSCache));
    if (!c)
        return NULL;

    c->capacity = capacity;
    c->entries = calloc(capacity, sizeof(DNSCacheEntry));
    if (!c->entries) {
        free(c);
        return NULL;
    }

    return c;
}

void dns_cache_destroy(DNSCache* cache) {
    if (!cache)
        return;
    if (cache->entries)
        free(cache->entries);
    free(cache);
}

void dns_cache_insert(DNSCache* cache, const sockaddr_any* addr, const char* name, uint64_t now, uint64_t ttl_sec) {
    if (!cache || !addr || !name)
        return;

    cache->current_tick++;

    // Check if exists
    for (size_t i = 0; i < cache->count; i++) {
        if (addr_equal(&cache->entries[i].addr, addr)) {
            strncpy(cache->entries[i].name, name, DNS_MAX_NAME_LEN - 1);
            cache->entries[i].name[DNS_MAX_NAME_LEN - 1] = '\0';
            cache->entries[i].expiry = now + ttl_sec;
            cache->entries[i].last_used = cache->current_tick;
            cache->entries[i].is_valid = 1;
            return;
        }
    }

    size_t idx;
    if (cache->count < cache->capacity) {
        idx = cache->count++;
    }
    else {
        // Evict LRU
        uint64_t min_tick = -1;  // Max uint64
        idx = 0;
        for (size_t i = 0; i < cache->capacity; i++) {
            if (cache->entries[i].last_used < min_tick) {
                min_tick = cache->entries[i].last_used;
                idx = i;
            }
        }
    }

    cache->entries[idx].addr = *addr;
    strncpy(cache->entries[idx].name, name, DNS_MAX_NAME_LEN - 1);
    cache->entries[idx].name[DNS_MAX_NAME_LEN - 1] = '\0';
    cache->entries[idx].expiry = now + ttl_sec;
    cache->entries[idx].last_used = cache->current_tick;
    cache->entries[idx].is_valid = 1;
}

const char* dns_cache_lookup(DNSCache* cache, const sockaddr_any* addr, uint64_t now) {
    if (!cache || !addr)
        return NULL;

    cache->current_tick++;

    for (size_t i = 0; i < cache->count; i++) {
        if (cache->entries[i].is_valid && addr_equal(&cache->entries[i].addr, addr)) {
            if (cache->entries[i].expiry > 0 && now > cache->entries[i].expiry) {
                cache->entries[i].is_valid = 0;  // Expired
                return NULL;
            }
            cache->entries[i].last_used = cache->current_tick;
            return cache->entries[i].name;
        }
    }

    return NULL;
}
