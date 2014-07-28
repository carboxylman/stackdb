/*
 * A3 host controller support.
 *
 * Routines to communicate via HTTP with host controller to report
 * detected anomalies. Derived from the A3 modifications to the UNFS3
 * user mode NFS server.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/time.h>
#include <syslog.h>
#include <arpa/inet.h>
#include "a3lib.h"

static int a3_hc_open(void);
static int a3_hc_send(char *buf, int len);
static int a3_hc_sendevent(int enforce, char *msg);
static int a3_hc_sendkv(char *key, int val);
static void logmsg(int prio, const char *fmt, ...);
static char *url_encode(char *str);

static int usesyslog;
static int localreports;
static struct sockaddr_in a3_hc_sock;
static char *role, *server;

int
a3_hc_init(char *domid, char *server, int syslog)
{
    char *ip, *port;
    int fd;

    usesyslog = syslog;
    if (usesyslog)
	openlog("a3asm", LOG_CONS|LOG_PID, LOG_DAEMON);
    else
	setvbuf(stdout, NULL, _IOLBF, 0);

    if (strcmp(domid, "a3-ncz") == 0)
	role = "ncz";
    else if (strcmp(domid, "a3-app") == 0)
	role = "app";
    else {
	logmsg(LOG_INFO, "do not recognize domain '%s'", domid);
	return 1;
    }

    if (strcmp(server, "SYSLOG") == 0) {
	localreports = 1;
	logmsg(LOG_INFO, "Sending reports to local logfile instead of HC");
	return 0;
    }

    ip = server;
    port = index(ip, ':');
    if (port == NULL || ip == port || port[1] == '\0') {
	logmsg(LOG_INFO, "could not parse server '%s'", server);
	return 1;
    }
    *port++ = '\0';
    if (!inet_aton(ip, &a3_hc_sock.sin_addr)) {
	logmsg(LOG_INFO, "server addr must be an IP address");
	return 1;
    }
    a3_hc_sock.sin_port = htons(atoi(port));
    a3_hc_sock.sin_family = AF_INET;

    /* make sure we can talk to the server */
    fd = a3_hc_open();
    if (fd < 0) {
	logmsg(LOG_INFO, "could not talk to server at %s (%d)",
	       server, fd);
	return 1;
    }
    close(fd);

    logmsg(LOG_INFO, "Host controller at %s:%d",
	   inet_ntoa(a3_hc_sock.sin_addr), ntohs(a3_hc_sock.sin_port));
    return 0;
}

/*
 * Report stats to the controller
 */
void
a3_hc_report_stats(struct a3_hc_stats *sb)
{
    if (server == NULL)
	return;

#if 0
    logmsg(LOG_INFO, "%s report: %d/%d/%d: %u/%u/%u/%u/%u",
	   cli, (int)p->tops, (int)p->rbytes, (int)p->wbytes,
	   p->ops[0], p->ops[1], p->ops[2], p->ops[3], p->ops[4]);
#endif

#if 0
    if (a3_hc_sendkv("NFS ops/sec", (int)p->tops) ||
	a3_hc_sendkv("NFS read-Kbytes/sec",
			   (int)(p->rbytes/1000.0)) ||
	a3_hc_sendkv("NFS write-Kbytes/sec",
			   (int)(p->wbytes/1000.0)))
	logmsg(LOG_INFO, "Stat reporting failed");
#endif
}

/*
 * Signal a detected anomaly.
 */
int
a3_hc_signal_anomaly(char *atype)
{
    char anom[256];

    /* XXX to match the java GUI's expectations */
    char *etag = strcmp(role, "ncz") == 0 ? "FAP" : "WS";

    snprintf(anom, sizeof anom, "%s: %s", etag, atype);
    return a3_hc_sendevent(0, anom);
}

/*
 * Signal a recovery attempt.
 */
int
a3_hc_signal_recovery_attempt(char *func, int argc, char **argv)
{
    char recov[256];
    int i;
    unsigned int len = 0;

    /* XXX to match the java GUI's expectations */
    char *etag = strcmp(role, "ncz") == 0 ? "FAP" : "WS";

    snprintf(&recov[len], sizeof recov - len - 1,
	     "%s: FN=%s", etag, func);
    len = strlen(recov);
    for (i = 0; i < argc && len < sizeof recov - 1; i++) {
	snprintf(&recov[len], sizeof recov - len - 1,
		 " A%d=%s", i, argv[i]);
	len = strlen(recov);
    }
    memset(&recov[len], '\0', sizeof recov - len);
    return a3_hc_sendevent(1, recov);
}

/*
 * Signal a recovery completion
 */
int
a3_hc_signal_recovery_complete(char *func, int status)
{
    char recov[256];

    /* XXX to match the java GUI's expectations */
    char *etag = strcmp(role, "ncz") == 0 ? "FAP" : "WS";

    snprintf(recov, sizeof recov,
	     "%s: FN=%s, STAT=%d", etag, func, status);
    return a3_hc_sendevent(1, recov);
}

/*
 * Open our connection to the host controller.
 */
static int
a3_hc_open(void)
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
	if (connect(sock, (struct sockaddr *)&a3_hc_sock, sizeof a3_hc_sock)) {
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
		logmsg(LOG_INFO, "Connect to stats server returned %d", err);
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

static int
a3_hc_send(char *buf, int len)
{
    int sock;
    int rv = 0;

    if (localreports) {
	logmsg(LOG_INFO, "a3_hc: %s", buf);
	return 0;
    }

    sock = a3_hc_open();
    if (sock >= 0) {
	if (write(sock, buf, len) < 0) {
	    logmsg(LOG_INFO, "Write to socket failed (%d)", errno);
	    rv = 1;
	}
	/*
	 * XXX the polite thing to do would be to wait for the response
	 * from the web server...nah!
	 */
	close(sock);
    } else
	rv = 1;

    return rv;
}

#define GETTS(tsp) { \
    struct timeval _tv; gettimeofday(&_tv, NULL); \
    *(tsp) = (uint64_t)_tv.tv_sec * 1000 + _tv.tv_usec / 1000; \
}

/*
 * Send an event message to the stats server. URL arguments:
 *   origin=ASM
 *   vmid=<ncz|app>      (based on what VM being run against)
 *   ts=<timestamp>      (based on current time)
 *   op=pub
 *   type=event
 *   eventtype=<OBS|ENF> (based on enforce)
 *   event=<string>      (URL-encoded msg)
 */
static int
a3_hc_sendevent(int enforce, char *msg)
{
    char *sendbuf;
    int sendlen, rv = 0;
    char *etype, *estr;
    uint64_t ts;

    GETTS(&ts);
    etype = enforce ? "ENF" : "OBS";
    if (localreports)
	estr = strdup(msg);
    else
	estr = url_encode(msg);

    sendlen = strlen(estr) + 256;
    sendbuf = malloc(sendlen);
    if (sendbuf == NULL) {
	free(estr);
	return 1;
    }

    snprintf(sendbuf, sendlen, "GET /index.html?"
	     "origin=ASM&op=pub&type=event&eventtype=%s&vmid=%s%s&ts=%llu&"
	     "event=%s HTTP/1.1\nHost: a3\n\n",
	     etype, "", role, (unsigned long long)ts, estr);
    free(estr);

    rv = a3_hc_send(sendbuf, strlen(sendbuf) + 1);
    free(sendbuf);

    return rv;
}

/*
 * Send a stats message to the stats server. URL arguments:
 *   origin=ASM
 *   vmid=<ncz|app>     (based on polid)
 *   ts=<timestamp>     (based on current time)
 *   op=pub
 *   type=dstat
 *   eventtype=OBS
 *   key=<string>       (URL-encoded key)
 *   val=<int>		(val)
 */
static int
a3_hc_sendkv(char *key, int val)
{
    char *sendbuf;
    int sendlen, rv = 0;
    char *etype, *estr;
    uint64_t ts;

    GETTS(&ts);
    etype = "OBS";
    if (localreports)
	estr = strdup(key);
    else
	estr = url_encode(key);

    sendlen = strlen(estr) + 256;
    sendbuf = malloc(sendlen);
    if (sendbuf == NULL) {
	free(estr);
	return 1;
    }

    snprintf(sendbuf, sendlen, "GET /index.html?"
	     "origin=ASM&op=pub&type=dstat&eventtype=%s&vmid=%s%s&ts=%llu&"
	     "key=%s&value=%d HTTP/1.1\nHost: a3\n\n",
	     etype, "", role, (unsigned long long)ts, estr, val);
    free(estr);

    rv = a3_hc_send(sendbuf, strlen(sendbuf) + 1);
    free(sendbuf);

    return rv;
}

static void
logmsg(int prio, const char *fmt, ...)
{
    va_list ap;
    char mesg[1024];

    va_start(ap, fmt);
    if (usesyslog) {
	vsnprintf(mesg, 1024, fmt, ap);
	syslog(prio, mesg, 1024);
    } else {
	vprintf(fmt, ap);
	putchar('\n');
    }
    va_end(ap);
}

/*
 * For URL encoding.
 * Caller must free returned string.
 */
static char *
url_encode(char *str)
{
    char *pstr = str;
    char *buf = malloc(strlen(str) * 3 + 1);
    char *pbuf = buf;

    while (*pstr) {
	if (isalnum(*pstr) ||
	    *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
	    *pbuf++ = *pstr;
	else if (*pstr == ' ')
	    *pbuf++ = '+';
	else {
	    *pbuf++ = '%';
	    *pbuf++ = "0123456789abcdef"[(*pstr >> 4) & 15];
	    *pbuf++ = "0123456789abcdef"[*pstr & 15];
	}
	pstr++;
    }
    *pbuf = '\0';

    return buf;
}
