/*
    Copyright (c)  2006, 2007		Dmitry Butskoy
                                        <dmitry@butskoy.name>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "traceroute.h"

/*  Just returns current time as double, with most possible precision...  */

double get_time(void) {
    struct timespec ts;
    double d;

    clock_gettime(CLOCK_REALTIME, &ts);

    d = ((double)ts.tv_nsec) / 1000000000. + (unsigned long)ts.tv_sec;

    return d;
}
