#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../src/correlate/match.h"

// Fuzz target for correlate_extract_id
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ProbeIdentity id;

    // We just want to make sure it doesn't crash on arbitrary input
    correlate_extract_id(data, size, &id);

    return 0;
}
