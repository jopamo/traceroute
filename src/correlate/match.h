#ifndef TRACEROUTE_CORRELATE_MATCH_H
#define TRACEROUTE_CORRELATE_MATCH_H

#include "../core/types.h"
#include "../io/net.h"

/**
 * Extracts probe identity from a received packet buffer (usually from ICMP error payload).
 *
 * @param buf The packet buffer (starts with IP header of the quoted packet)
 * @param len The length of the buffer
 * @param id  Pointer to ProbeIdentity to fill
 * @return 1 on success, 0 if not enough data or unrecognized protocol
 */
int correlate_extract_id(const void* buf, size_t len, ProbeIdentity* id);

/**
 * Matches a received PacketResult against a sent Probe.
 *
 * @param res The received packet result (already populated with original_req via extract_id)
 * @param probe The sent probe to check against
 * @return 1 if they match, 0 otherwise
 */
int correlate_match(const PacketResult* res, const Probe* probe);

#endif  // TRACEROUTE_CORRELATE_MATCH_H
