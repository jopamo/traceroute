/*
    Copyright (c)  2006, 2007		Dmitry Butskoy
                                        <dmitry@butskoy.name>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdlib.h>
#include <unistd.h>
#include <sys/times.h>
#include <sys/random.h>  // For better randomness if supported

#include "traceroute.h"

static void __init_random_seq(void) __attribute__((constructor));
static void __init_random_seq(void) {
    // For better randomness, using getrandom() if available
    unsigned int seed = 0;

    // Try using getrandom() for a better random seed on Linux
    if (getrandom(&seed, sizeof(seed), GRND_NONBLOCK) == -1) {
        // Fallback to time and PID if getrandom() is unavailable
        seed = times(NULL) + getpid();
    }

    srand(seed);
}

unsigned int random_seq(void) {
    // Using random() instead of rand() for better randomness
    return (random() << 16) ^ (random() << 8) ^ random() ^ (random() >> 8);
}
