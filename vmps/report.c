#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "report.h"

static struct sockaddr_in stats_sock;
static char opt_statsserver[] = "127.0.0.1:8989";
static char opt_querykey[] = "index.html?op=pub&type=event&event=";

/*
 * Open our connection to the stats server
 */
static int open_statsserver(void)
{
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct timeval tv;
        int flags;

        /*
         * Wow, never realized what a stunning pain-in-the-ass it is to
         * put a timeout on a connect operation!
         */
        flags = fcntl(sock, F_GETFL, 0);
        if (fcntl(sock, F_SETFL, flags|O_NONBLOCK)) {
            close(sock);
            return -2;
        }
        if (connect(sock, (struct sockaddr *)&stats_sock, sizeof stats_sock)) {
            fd_set fds;
            int err = errno;
            socklen_t len;

            if (err != EINPROGRESS) {
                close(sock);
                return -3;
            }

            FD_ZERO(&fds);
            FD_SET(sock, &fds);
            tv.tv_sec = 0;
            tv.tv_usec = 500000;
            if (select(sock+1, NULL, &fds, NULL, &tv) != 1) {
                close(sock);
                return -4;
            }
            err = 0;
            len = sizeof err;
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) ||
                    err != 0) {
                fprintf(stderr, "Connect to stats server returned %d\n", err);
                close(sock);
                return -5;
            }
        }
        if (fcntl(sock, F_SETFL, flags)) {
            close(sock);
            return -6;
        }

        /*
         * Okay, that was a hoot, now we STILL need to set the socket
         * non-blocking for write!
         */
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv)) {
            close(sock);
            return -7;
        }
    }

    return sock;
}

int init_stats(void)
{
    char *ip, *port;
    int fd;

    if (opt_statsserver == NULL)
        return 0;

    ip = opt_statsserver;
    port = index(ip, ':');
    if (port == NULL || ip == port || port[1] == '\0') {
        fprintf(stderr, "could not parse statsserver '%s'\n",
                opt_statsserver);
        return 1;
    }
    *port++ = '\0';
    if (!inet_aton(ip, &stats_sock.sin_addr)) {
        fprintf(stderr, "statsserver addr must be an IP address\n");
        return 1;
    }
    stats_sock.sin_port = htons(atoi(port));
    stats_sock.sin_family = AF_INET;

    /* make sure we can talk to the server */
    fd = open_statsserver();
    if (fd < 0) {
        fprintf(stderr, "could not talk to statsserver at %s (%d)\n",
                opt_statsserver, fd);
        return 1;
    }
    close(fd);

    printf("Stats server at %s:%d\n",
            inet_ntoa(stats_sock.sin_addr), ntohs(stats_sock.sin_port));
    return 0;
}

int report_event(const char *msg)
{
    char statbuf[256];
    int sock, rv = 0;

    snprintf(statbuf, sizeof statbuf,
        "GET /%s%s HTTP/1.1\n"
        "Host: a3\n\n", opt_querykey, msg);
    //printf("querystr: %s\n", statbuf);

    sock = open_statsserver();
    if (sock >= 0)
    {
        if (write(sock, statbuf, strlen(statbuf)+1) < 0) 
        {
            fprintf(stderr, "Write to socket failed (%d)\n", errno);
            rv = 1;
        }
        close(sock);
    }
    else
    {
        rv = 1;
    }

    return rv;
}
