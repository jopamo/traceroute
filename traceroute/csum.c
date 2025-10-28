/*
    Copyright (c)  2006, 2007		Dmitry Butskoy
                                        <dmitry@butskoy.name>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>  // For htons()

uint16_t in_csum(const void* ptr, size_t len) {
    const uint16_t* p = (const uint16_t*)ptr;
    size_t nw = len / 2;   // Number of 16-bit words
    unsigned int sum = 0;  // Accumulator for the checksum
    uint16_t res;

    // Process 16-bit words
    while (nw--) {
        sum += *p++;
    }

    // Handle the last byte if length is odd
    if (len & 0x1) {
        sum += htons(*((unsigned char*)p) << 8);
    }

    // Fold 32-bit sum to 16 bits (add overflow from the higher 16 bits)
    sum = (sum & 0xFFFF) + (sum >> 16);  // Fold the upper 16-bits into the lower 16-bits
    sum += (sum >> 16);                  // Add any remaining overflow

    // Invert the sum and return
    res = ~sum;
    return res ? res : ~0;  // Return 0xFFFF if checksum is 0 (special case)
}
