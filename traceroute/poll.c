/*
    Copyright (c)  2006, 2007		Dmitry Butskoy
                                        <dmitry@butskoy.name>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <math.h>

#include "traceroute.h"

static struct pollfd* pfd = NULL;
static unsigned int num_polls = 0;
static unsigned int max_polls = 0;  // Track the allocated size to optimize reallocations

void add_poll(int fd, int events) {
    unsigned int i;

    // Look for the first empty spot
    for (i = 0; i < num_polls && pfd[i].fd > 0; i++)
        ;

    if (i == num_polls) {
        // Double the allocated size if more space is needed
        if (num_polls == max_polls) {
            max_polls = max_polls ? max_polls * 2 : 4;  // Start with a reasonable initial size
            pfd = realloc(pfd, max_polls * sizeof(*pfd));
            if (!pfd)
                error("realloc");
        }
        num_polls++;
    }

    pfd[i].fd = fd;
    pfd[i].events = events;
}

void del_poll(int fd) {
    unsigned int i;

    // Look for the file descriptor to remove
    for (i = 0; i < num_polls && pfd[i].fd != fd; i++)
        ;

    if (i < num_polls) {
        pfd[i].fd = -1;  // Mark it as invalid
    }
}

static unsigned int cleanup_polls(void) {
    unsigned int i, j;

    // Compact the array to remove holes (invalid file descriptors)
    for (i = 0; i < num_polls && pfd[i].fd > 0; i++)
        ;

    if (i < num_polls) {  // A hole has been found
        for (j = i + 1; j < num_polls; j++) {
            if (pfd[j].fd > 0) {
                pfd[i++] = pfd[j];
                pfd[j].fd = -1;
            }
        }
    }

    return i;
}

void do_poll(double timeout, void (*callback)(int fd, int revents)) {
    unsigned int nfds, i;
    int n;

    nfds = cleanup_polls();  // Get the number of active file descriptors

    if (!nfds)
        return;

    // Poll the file descriptors with the specified timeout
    n = poll(pfd, nfds, ceil(timeout * 1000));
    if (n < 0) {
        if (errno == EINTR)
            return;
        error("poll");
    }

    // Call the callback for each file descriptor that has events
    for (i = 0; n && i < nfds; i++) {
        if (pfd[i].revents) {
            callback(pfd[i].fd, pfd[i].revents);
            n--;
        }
    }
}

void cleanup() {
    free(pfd);
    pfd = NULL;
    num_polls = 0;
    max_polls = 0;
}
