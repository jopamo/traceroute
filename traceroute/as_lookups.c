/*
    Copyright (c)  2006, 2007		Dmitry Butskoy
                                        <dmitry@butskoy.name>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "traceroute.h"

#define DEF_RADB_SERVER "whois.radb.net"
#define DEF_RADB_SERVICE "nicname"
#define MAX_BUF_SIZE 512
#define MAX_RA_BUF_SIZE 1024

#define ROUTE_PREFIX "route:"
#define ROUTE6_PREFIX "route6:"
#define ORIGIN_PREFIX "origin:"
#define IFACE_NAME_LEN 64

static sockaddr_any ra_addr = {0};
static char ra_buf[MAX_RA_BUF_SIZE] = {0};

const char* get_as_path(const char* query) {
    int sk, n;
    char buf[MAX_BUF_SIZE];
    FILE* fp;
    int prefix = 0, best_prefix = 0;
    char *rb, *re = &ra_buf[MAX_RA_BUF_SIZE - 1];

    if (!ra_addr.sa.sa_family) {
        const char *server, *service;
        struct addrinfo* res;
        int ret;

        server = getenv("RA_SERVER") ? getenv("RA_SERVER") : DEF_RADB_SERVER;
        service = getenv("RA_SERVICE") ? getenv("RA_SERVICE") : DEF_RADB_SERVICE;

        ret = getaddrinfo(server, service, NULL, &res);
        if (ret) {
            fprintf(stderr, "%s/%s: %s\n", server, service, gai_strerror(ret));
            exit(2);
        }

        memcpy(&ra_addr, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
    }

    // Create socket
    sk = socket(ra_addr.sa.sa_family, SOCK_STREAM, 0);
    if (sk < 0) {
        perror("socket");
        return "!!";
    }

    // Connect to the remote server
    if (connect(sk, &ra_addr.sa, sizeof(ra_addr)) < 0) {
        perror("connect");
        close(sk);
        return "!!";
    }

    // Send query
    n = snprintf(buf, sizeof(buf), "%s\r\n", query);
    if (n >= sizeof(buf)) {
        fprintf(stderr, "Query buffer overflow\n");
        close(sk);
        return "!!";
    }

    if (write(sk, buf, n) < n) {
        perror("write");
        close(sk);
        return "!!";
    }

    fp = fdopen(sk, "r");
    if (!fp) {
        perror("fdopen");
        close(sk);
        return "!!";
    }

    // Initialize buffer and read data
    strcpy(ra_buf, "*");
    rb = ra_buf;

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strncmp(buf, ROUTE_PREFIX, strlen(ROUTE_PREFIX)) == 0 || strncmp(buf, ROUTE6_PREFIX, strlen(ROUTE6_PREFIX)) == 0) {
            char* p = strchr(buf, '/');
            if (p) {
                prefix = strtoul(++p, NULL, 10);
            }
            else {
                prefix = 0;
            }
        }
        else if (strncmp(buf, ORIGIN_PREFIX, strlen(ORIGIN_PREFIX)) == 0) {
            char* p = buf + strlen(ORIGIN_PREFIX);
            while (isspace(*p))
                p++;

            char* as = p;
            while (*p && !isspace(*p))
                p++;
            *p = '\0';

            // If prefix is better or equal, store the result
            if (prefix > best_prefix) {
                best_prefix = prefix;
                rb = ra_buf;
                while (rb < re && (*rb++ = *as++))
                    ;
            }
            else if (prefix == best_prefix) {
                // Handle multiple equal prefix origins
                char* q = strstr(ra_buf, as);
                if (!q || (*(q += strlen(as)) != '\0' && *q != '/')) {
                    if (rb > ra_buf)
                        rb[-1] = '/';
                    while (rb < re && (*rb++ = *as++))
                        ;
                }
            }
        }
    }

    fclose(fp);
    close(sk);

    return ra_buf;
}
