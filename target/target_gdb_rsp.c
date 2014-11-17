/*
 * Copyright (c) 2014 The University of Utah
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "config.h"

#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#if !defined(UNIX_PATH_MAX)
#define UNIX_PATH_MAX (size_t)sizeof(((struct sockaddr_un *) 0)->sun_path)
#endif
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <argp.h>

#include "common.h"
#include "arch.h"
#include "arch_x86.h"
#include "arch_x86_64.h"
#include "evloop.h"
#include "target_api.h"
#include "target.h"
#include "target_arch_x86.h"
#include "target_gdb.h"
#include "target_gdb_rsp.h"

#include <glib.h>

extern int h_errno;

/*
 * Local prototypes.
 */
static inline int __h2ul(char *str,unsigned int len,unsigned long *out);
static inline int __hs2ul_lsb(char *str,unsigned int len,unsigned long *out);
static inline int __h2ul_be(char *str,unsigned int len,unsigned long *out);
static inline int __hs2d(char *str,unsigned int len,char *buf);
static inline int __d2hs(char *buf,unsigned int len,char *str);
static int gdb_rsp_send_raw(struct target *target,
			    char *data,unsigned int len);
static gdb_rsp_handler_ret_t
gdb_rsp_simple_ack_handler(struct target *target,char *data,unsigned int len,
			   void *handler_data);
static gdb_rsp_handler_ret_t
gdb_rsp_features_handler(struct target *target,char *data,unsigned int len,
			 void *handler_data);
static gdb_rsp_handler_ret_t
gdb_rsp_vcont_check_handler(struct target *target,char *data,unsigned int len,
			    void *handler_data);
static gdb_rsp_handler_ret_t
gdb_rsp_stop_handler(struct target *target,char *data,unsigned int len,
		     void *handler_data);

int gdb_rsp_query_stub(struct target *target);

/**
 ** A partial implement of the GDB RSP.  Doesn't bother with some things
 ** that only GDB servers need, like the ability to send notifications.
 **/

int gdb_rsp_connect(struct target *target) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    struct gdb_spec *spec = (struct gdb_spec *)target->spec->backend_spec;
    struct stat sbuf;
    struct sockaddr_un sun,sun_client;
    char *tmpdir;
    char *cpath;
    int cpath_len;
    int len;
    struct hostent *he;
    void *dst;
    int addrtype;
    int dlen;
    struct sockaddr_in sin,sinc;
    struct sockaddr_in6 sin6,sin6c;
    gdb_rsp_handler_ret_t hret = GDB_RSP_HANDLER_ERR;
    int sret = 0;

    if (gstate->fd > -1) {
	verror("already connected via fd %d!\n",gstate->fd);
	errno = EALREADY;
	return -1;
    }

    if (spec->hostname || spec->port > -1) {
	if (!spec->hostname)
	    spec->hostname = strdup("localhost");
	if (spec->port < 0)
	    spec->port = 1234;

	he = gethostbyname(spec->hostname);
	if (!he) {
	    verror("gethostbyname(%s): %s (%d)!",spec->hostname,
		   hstrerror(h_errno),h_errno);
	    goto in_err;
	}

	addrtype = he->h_addrtype;
	if (addrtype == AF_INET) {
	    memcpy(&sin.sin_addr,he->h_addr,he->h_length);
	    dlen = sizeof(sin);
	    sin.sin_port = htons(spec->port);
	    sin.sin_family = addrtype;
	}
	else if (addrtype == AF_INET6) {
	    memcpy(&sin6.sin6_addr,he->h_addr,he->h_length);
	    dlen = sizeof(sin6);
	    sin6.sin6_port = htons(spec->port);
	    sin6.sin6_family = addrtype;
	}
	else {
	    verror("unknown addrtype %d for hostname %s!\n",
		   addrtype,spec->hostname);
	    goto in_err;
	}

	/*
	if (inet_pton(addrtype,he->h_addr,dst) != 1) {
	    verror("could not convert addr %s to network!\n",he->h_addr);
	    goto in_err;
	}
	*/

	if (spec->do_udp)
	    gstate->fd = socket(addrtype,SOCK_DGRAM,0);
	else
	    gstate->fd = socket(addrtype,SOCK_STREAM,0);
	if (gstate->fd < 0) {
	    verror("socket(): %s\n",strerror(errno));
	    goto in_err;
	}

	if (addrtype == AF_INET) {
	    dst = &sin;
	    dlen = sizeof(sin);
	    if (spec->do_udp) {
		sinc.sin_family = addrtype;
		sinc.sin_addr.s_addr = INADDR_ANY;
		sinc.sin_port = 0;
		if (bind(gstate->fd,&sinc,sizeof(sinc))) {
		    verror("could not bind udp socket: %s (%d)!\n",
			   strerror(errno),errno);
		    goto in_err;
		}
	    }
	}
	else {
	    dst = &sin6;
	    dlen = sizeof(sin6);
	    if (spec->do_udp) {
		sin6c.sin6_family = addrtype;
		sin6c.sin6_addr = in6addr_any;
		sin6c.sin6_port = 0;
		if (bind(gstate->fd,&sin6c,sizeof(sin6c))) {
		    verror("could not bind udp socket: %s (%d)!\n",
			   strerror(errno),errno);
		    goto in_err;
		}
	    }
	}

	if (connect(gstate->fd,(struct sockaddr *)dst,dlen) < 0) {
	    verror("connect(%s): %s\n",he->h_addr,strerror(errno));
	    goto in_err;
	}

	if (!spec->do_udp) {
	    const int one = 1;
	    setsockopt(gstate->fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(&one));
	}

	vdebug(5,LA_TARGET,LF_GDB,
	       "connected to %s socket %s:%d (fd %d)\n",
	       (spec->do_udp) ? "udp" : "tcp",he->h_name,spec->port,gstate->fd);

	goto connected;

    in_err:
	if (gstate->fd > -1) {
	    close(gstate->fd);
	    gstate->fd = -1;
	}
	return -1;

    }
    else if (spec->sockfile) {
	memset(&sun,0,sizeof(sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path,UNIX_PATH_MAX,"%s",spec->sockfile);

	/*
	 * Just try TMPDIR or /tmp or .
	 */
	if ((tmpdir = getenv("TMPDIR"))
	    && stat(tmpdir,&sbuf) == 0 && access(tmpdir,W_OK) == 0) {
	    cpath_len =
		strlen(tmpdir) + 1 + strlen("target_gdb_sock.") + 11 + 1;
	    cpath = malloc(cpath_len);
	    snprintf(cpath,cpath_len,"%s/target_gdb_sock.%d",tmpdir,getpid());
	}
	else if (stat("/tmp",&sbuf) == 0 
		 && S_ISDIR(sbuf.st_mode) && access("/tmp",W_OK) == 0) {
	    cpath_len =
		strlen("/tmp") + 1 + strlen("target_gdb_sock.") + 11 + 1;
	    cpath = malloc(cpath_len);
	    snprintf(cpath,cpath_len,"/tmp/target_gdb_sock.%d",getpid());
	}
	else if (stat("/var/tmp",&sbuf) == 0 
	    && S_ISDIR(sbuf.st_mode) && access("/var/run",W_OK) == 0) {
	    cpath_len =
		strlen("/var/run") + 1 + strlen("target_gdb_sock.") + 11 + 1;
	    cpath = malloc(cpath_len);
	    snprintf(cpath,cpath_len,"/var/run/target_gdb_sock.%d",getpid());
	}
	else {
	    cpath_len = strlen(".") + 1 + strlen("target_gdb_sock.") + 11 + 1;
	    cpath = malloc(cpath_len);
	    snprintf(cpath,cpath_len,"./target_gdb_sock.%d",getpid());
	}

	memset(&sun_client,0,sizeof(sun_client));
	sun_client.sun_family = AF_UNIX;
	snprintf(sun_client.sun_path,UNIX_PATH_MAX,"%s",cpath);

	gstate->sockfile = strdup(cpath);

	gstate->fd = socket(AF_UNIX,SOCK_STREAM,0);
	if (gstate->fd < 0) {
	    verror("socket(): %s\n",strerror(errno));
	    goto sun_err;
	}
	len = offsetof(struct sockaddr_un,sun_path)
	    + strlen(sun_client.sun_path);
	if (bind(gstate->fd,&sun_client,len) < 0) {
	    verror("bind(%s): %s\n",sun_client.sun_path,strerror(errno));
	    goto sun_err;
	}
	if (fchmod(gstate->fd,S_IRUSR | S_IWUSR) < 0) {
	    verror("chmod(%s): %s\n",sun_client.sun_path,strerror(errno));
	    goto sun_err;
	}
	
	len = offsetof(struct sockaddr_un,sun_path) + strlen(sun.sun_path);
	if (connect(gstate->fd,&sun,len) < 0) {
	    verror("connect(%s): %s\n",sun.sun_path,strerror(errno));
	    goto sun_err;
	}

	vdebug(5,LA_TARGET,LF_GDB,
	       "connected to unix socket %s (fd %d)\n",
	       gstate->sockfile,gstate->fd);

	goto connected;

    sun_err:
	if (gstate->fd > -1) {
	    close(gstate->fd);
	    gstate->fd = -1;
	}
	if (gstate->sockfile) {
	    unlink(gstate->sockfile);
	    free(gstate->sockfile);
	    gstate->sockfile = NULL;
	}
	return -1;
    }
    else if (spec->devfile || spec->do_stdio) {
	verror("unsupported transport!\n");
	errno = ENOTSUP;
	return -1;
    }
    else {
	verror("unspecified transport!\n");
	errno = EINVAL;
	return -1;
    }

 connected:

    /*
     * Put the read fd into nonblocking.  We don't want reads to stall
     * us; we'd be ok with synchronous writes; but since for most
     * transports, read/write will go over the same bidirectional socket,
     * we'll make them both nonblocking and handle it.  Well, actually,
     * we're going to force synchronous writes... because we don't
     * really have a mechanism in the target library to queue commands
     * and callback to caller.  Don't have that at all.
     */

    /*
     * Setup the recv buf.
     */
    gstate->ibuf = malloc(4096);
    gstate->ibuf_alen = 4096;
    gstate->ibuf_len = 0;

    /*
     * Send a quick ack to get things started.
     */
    if (gdb_rsp_ack(target)) {
	verror("failed to send an initial ack!\n");
	goto err_setup;
    }

    /*
     * Tell the stub about our features, and get the stub's features.
     */
    if (gdb_rsp_query_stub(target)) {
	verror("failed to query stub features!\n");
	goto err_setup;
    }

    /*
     * Set some defaults for subsequent operations...
     */
    if (gdb_rsp_send_packet(target,"Hg0",0,gdb_rsp_simple_ack_handler,&sret)) {
	verror("failed to set Hg0 defaults!\n");
	return -1;
    }

    if (gdb_rsp_recv_until_handled(target,gdb_rsp_simple_ack_handler,&hret)) {
	verror("failed to recv Hg0 defaults response; aborting!\n");
	return -1;
    }
    else if (hret != GDB_RSP_HANDLER_DONE) {
	verror("simple ack handler returned not done: %d; aborting!\n",hret);
	return -1;
    }
    else if (sret) {
	verror("failed to set Hg0 defaults: error %d!\n",sret);
	return -1;
    }

    if (gdb_rsp_send_packet(target,"Hc-1",0,gdb_rsp_simple_ack_handler,&sret)) {
	verror("failed to set Hc-1 defaults!\n");
	return -1;
    }

    if (gdb_rsp_recv_until_handled(target,gdb_rsp_simple_ack_handler,&hret)) {
	verror("failed to recv Hc-1 response; aborting!\n");
	return -1;
    }
    else if (hret != GDB_RSP_HANDLER_DONE) {
	verror("simple ack handler returned not done: %d; aborting!\n",hret);
	return -1;
    }
    else if (sret) {
	verror("failed to set Hc-1 defaults: error %d!\n",sret);
	return -1;
    }

    vdebug(9,LA_TARGET,LF_GDB,"setup default thread for c/g ops\n");

    /*
     * This is sadly necessary to do before installing breakpoints on
     * the QEMU gdb stub; if you don't read regs first, breakpoints will
     * claim to work but won't.
     */
    gdb_rsp_read_regs(target,NULL);

    return 0;

 err_setup:
    gdb_rsp_close(target,0);
    return -1;
}

#define GDB_CHECKCONN(errcode)	\
    do {			\
        if (gstate->fd < 0) {	\
	    verror("not connected to gdb server!\n");	\
	    errno = ENOTCONN;				\
	    return (errcode);				\
	}						\
    } while(0)

int gdb_rsp_close(struct target *target,int stay_paused) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;

    GDB_CHECKCONN(0);

    if (stay_paused && gstate->vcont) {
	if (gdb_rsp_send_packet(target,"vCont;t",0,NULL,NULL)) {
	    verror("failed to detach, STOPPED, via vCont;t!\n");
	    return -1;
	}
    }
    else if (gdb_rsp_send_packet(target,"D",0,NULL,NULL)) {
	verror("failed to detach via D !\n");
	return -1;
    }
    else {
	vdebug(9,LA_TARGET,LF_GDB,"detached via D\n");
    }

    /*
     * Don't bother waiting for an ACK nor a simple ACK packet.
     */

    if (gstate->ibuf) {
	free(gstate->ibuf);
	gstate->ibuf = NULL;
    }
    if (gstate->wfd > -1) {
	close(gstate->wfd);
	gstate->wfd = -1;
    }
    if (gstate->fd > -1) {
	close(gstate->fd);
	gstate->fd = -1;
    }
    if (gstate->sockfile) {
	unlink(gstate->sockfile);
	free(gstate->sockfile);
	gstate->sockfile = NULL;
    }

    return 0;
}

static int gdb_rsp_send_raw(struct target *target,
			    char *data,unsigned int len) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    unsigned int remaining;
    int rc;
    int fd;

    GDB_CHECKCONN(-1);

    if (gstate->writing) {
	verror("gdb already sending packet; BUG!\n");
	errno = EALREADY;
	return -1;
    }

    gstate->writing = 1;

    if (gstate->wfd > -1)
	fd = gstate->wfd;
    else
	fd = gstate->fd;

    if (fd < 0) {
	verror("connection not up!\n");
	target_set_status(target,TSTATUS_UNKNOWN);
	return -1;
    }

    remaining = len;
    while (remaining) {
	rc = write(fd,data + (len - remaining),remaining);

	if (rc < 0) {
	    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
		continue;
	    else if (errno == EPIPE) {
		/*
		 * XXX: try to reconnect?  how to close gracefully?
		 */
		verror("connection unexpectedly terminated!\n");
		target_set_status(target,TSTATUS_UNKNOWN);
		goto errout;
	    }
	    else {
		verror("write to fd %d failed after %d of %d bytes: %s (%d)!\n",
		       fd,(len - remaining),len,strerror(errno),errno);
		goto errout;
	    }
	}
	else
	    remaining -= rc;
    }

    vdebug(9,LA_TARGET,LF_GDB,"wrote %d bytes to fd %d\n",len,fd);

    gstate->writing = 0;
    return 0;

 errout:
    gstate->writing = 0;
    return -1;
}

static char GDB_INT_BYTE[1] = { 0x03, };
static char GDB_ACK_BYTE[1] = { '+', };
static char GDB_NAK_BYTE[1] = { '-', };

int gdb_rsp_interrupt(struct target *target) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    gdb_rsp_handler_ret_t hret;
    int rc;

    GDB_CHECKCONN(-1);

    if (gstate->writing) {
	vdebug(6,LA_TARGET,LF_GDB,
	       "gdb already sending packet; scheduling interrupt!\n");
	gstate->need_interrupt = 1;
	return 0;
    }

    rc = gdb_rsp_send_raw(target,GDB_INT_BYTE,sizeof(GDB_INT_BYTE));
    if (rc) {
	verror("could not send interrupt request!\n");
	return -1;
    }

    /*
     * If there's a handler, we need to wait for it to handle stuff!
     *
     * XXX: hm, maybe we should only do this if the handler is the stop
     * handler... not sure.
     */
    if (gstate->handler == gdb_rsp_stop_handler) {
	if (gdb_rsp_recv_until_handled(target,gdb_rsp_stop_handler,&hret)) {
	    verror("failed to recv stop response; aborting!\n");
	    return -1;
	}
	else if (hret != GDB_RSP_HANDLER_DONE) {
	    verror("stop handler error returned not done: %d; aborting!\n",hret);
	    return -1;
	}
    }

    return 0;
}

/*
int gdb_rsp_interrupt_synch(struct target *target) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;

    GDB_CHECKCONN(-1);

    if (gstate->writing) {
	vdebug(6,LA_TARGET,LF_GDB,
	       "gdb already sending packet; scheduling interrupt!\n");
	gstate->need_interrupt = 1;
	return 0;
    }

    while (1) {
	rc = gdb_rsp_send_raw(target,GDB_INT_BYTE,sizeof(GDB_INT_BYTE));
	if (
}
*/

int gdb_rsp_ack(struct target *target) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;

    if (!gstate->need_ack)
	return 0;

    GDB_CHECKCONN(-1);

    if (gstate->writing) {
	verror("gdb already sending packet; BUG!\n");
	return -1;
    }

    return gdb_rsp_send_raw(target,GDB_ACK_BYTE,sizeof(GDB_ACK_BYTE));
}

int gdb_rsp_nak(struct target *target) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;

    GDB_CHECKCONN(-1);

    if (gstate->writing) {
	verror("gdb already sending packet; BUG!\n");
	return -1;
    }

    return gdb_rsp_send_raw(target,GDB_NAK_BYTE,sizeof(GDB_NAK_BYTE));
}

/*
 * The binary data representation uses 7d (ASCII ‘}’) as an escape
 * character. Any escaped byte is transmitted as the escape character
 * followed by the original character XORed with 0x20. For example, the
 * byte 0x7d would be transmitted as the two bytes 0x7d 0x5d. The bytes
 * 0x23 (ASCII ‘#’), 0x24 (ASCII ‘$’), and 0x7d (ASCII ‘}’) must always
 * be escaped.
 */
static int gdb_rsp_encode(struct target *target,char ptype,
			  char *ibuf,unsigned int ilen,
			  char **obuf,unsigned int *olen) {
    unsigned long int sum = 0;
    unsigned int alen = ilen + 32;
    unsigned int i,j;
    char *lbuf;

    lbuf = malloc(alen);
    j = 0;
    lbuf[j] = ptype;
    ++j;

    for (i = 0; i < ilen; ++i,++j) {
	if ((j + 1) >= alen) {
	    alen += 32;
	    lbuf = realloc(lbuf,alen);
	}

	if (ibuf[i] == 0x7d || ibuf[i] == '#' || ibuf[i] == '$') {
	    lbuf[j] = 0x7d;
	    sum = (sum + lbuf[j]) % 256;
	    ++j;
	    lbuf[j] = lbuf[i] ^ 0x20;
	    sum = (sum + lbuf[j]) % 256;
	}
	else {
	    lbuf[j] = ibuf[i];
	    sum = (sum + lbuf[j]) % 256;
	}
    }

    if ((j + 4) >= alen)
	lbuf = realloc(lbuf,j + 4);
    else if ((j + 4) < alen)
	lbuf = realloc(lbuf,j + 4);

    lbuf[j++] = '#';
    snprintf(lbuf + j,3,"%02hhx",(uint8_t)sum);

    *obuf = lbuf;
    *olen = j + 2;

    return 0;
}

int gdb_rsp_send_packet(struct target *target,
			char *data,unsigned int len,
			gdb_rsp_handler_t handler,void *handler_data) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;

    GDB_CHECKCONN(-1);

    if (gstate->writing) {
	verror("gdb already writing; BUG!\n");
	return -1;
    }

    if (len == 0)
	len = strlen(data);

    if (gdb_rsp_encode(target,'$',data,len,
		       &gstate->obuf,&gstate->obuf_len)) {
	verror("failed to encode data of len %d!\n",len);
	goto errout;
    }

    vdebug(9,LA_TARGET,LF_GDB,"encoded %d bytes into '%c' packet of %d bytes\n",
	   len,'$',gstate->obuf_len);

    if (gdb_rsp_send_raw(target,gstate->obuf,gstate->obuf_len)) {
	verror("could not send %d encoded bytes (%d non-encoded)!\n",
	       gstate->obuf_len,len);
	goto errout;
    }

    vdebug(9,LA_TARGET,LF_GDB,"wrote %d encoded bytes (%s)\n",
	   gstate->obuf_len,gstate->obuf);

    if (!gstate->need_ack) {
	free(gstate->obuf);
	gstate->obuf = NULL;
	gstate->obuf_len = 0;
    }

    gstate->handler = handler;
    gstate->handler_data = handler_data;
    gstate->handler_ret = GDB_RSP_HANDLER_ERR;

    return 0;

 errout:
    gstate->writing = 0;
    return -1;
}

int gdb_rsp_send_notification(struct target *target,
				     char *data,unsigned int len) {
    verror("client should not send notifications!");
    errno = ENOTSUP;
    return -1;
}

/*
 * Return value of 1 means incomplete packet; 0 means we decoded a
 * packet (and packet type will be in ptype, and decoded data will be in
 * *obuf and length in *olen, if ptype is GDB_PACKET or GDB_NOTIFICATION); 
 * -1 means there was a decoding error!  We *always* set ibuf_used!
 */
static int gdb_rsp_decode(struct target *target,char *ibuf,unsigned int ilen,
			  gdb_ptype_t *ptype,unsigned int *ilen_used,
			  char **obuf,unsigned int *olen) {
    unsigned long int sum = 0;
    unsigned int start;
    unsigned int end;
    unsigned long decsum;
    unsigned int alen;
    uint8_t rlen;
    int inesc = 0;
    unsigned int i,j,k;
    char prevchar;

    if (ptype)
	*ptype = GDB_UNKNOWN;

    /*
     * First, skip any non-packet leading junk.
     */
    i = 0;
    while (i < ilen) {
	switch (*(ibuf+i)) {
	/* Interrupt -- client should not see it. */
	case 0x03:
	    if (ptype)
		*ptype = GDB_INTERRUPT;
	    vdebug(9,LA_TARGET,LF_GDB,"interrupt packet\n");
	    if (ilen_used)
		*ilen_used = i + 1;
	    return 0;
	/* Simple ACK/NAK */
	case '+':
	    if (ptype)
		*ptype = GDB_ACK;
	    vdebug(9,LA_TARGET,LF_GDB,"ACK packet\n");
	    if (ilen_used)
		*ilen_used = i + 1;
	    return 0;
	case '-':
	    if (ptype)
		*ptype = GDB_NAK;
	    vdebug(9,LA_TARGET,LF_GDB,"NAK packet\n");
	    if (ilen_used)
		*ilen_used = i + 1;
	    return 0;
	/* Full packet or notification packet. */
	case '$':
	    if (ptype)
		*ptype = GDB_PACKET;
	    vdebug(9,LA_TARGET,LF_GDB,"normal packet\n");
	    break;
	case '%':
	    if (ptype)
		*ptype = GDB_NOTIFICATION;
	    vdebug(9,LA_TARGET,LF_GDB,"notification packet\n");
	    break;
	/* Garbage. */
	default:
	    vdebug(16,LA_TARGET,LF_GDB,"unrecognized leading char %c (%hhx)\n",
		   *(ibuf+i),*(ibuf+i));
	    ++i;
	    continue;
	}

	/* Ok, we found something. */
	break;
    }

    /*
     * If the data was all garbage, error.
     */
    if (i >= ilen) {
	if (ilen_used)
	    *ilen_used = i + 1;
	errno = EBADMSG;
	return -1;
    }

    /*
     * Otherwise, we have a full packet ($) or notification (%); look
     * for a complete packet and checksum.
     */
    start = i;
    /* Skip the $ or %. */
    ++i;
    /* Compute the checksum on the data. */
    for (; i < ilen && ibuf[i] != '#'; ++i)
	sum = (sum + ibuf[i]) % 256;
    if (i >= ilen) {
	if (ilen_used)
	    /* Let it skip any garbage when it comes back again. */
	    *ilen_used = start;
	vdebug(9,LA_TARGET,LF_GDB,
	       "incomplete packet len %d (%d garbage)\n",ilen,start);
	return 1;
    }
    else if ((i + 2) >= ilen) {
	if (ilen_used)
	    /* Let it skip any garbage when it comes back again. */
	    *ilen_used = start;
	vdebug(9,LA_TARGET,LF_GDB,
	       "incomplete packet '%s' len %d (%d garbage; missing %d checksum bytes)\n",
	       ibuf + start,ilen,start,(i + 3 - ilen));
	return 1;
    }
    else {
	if (__h2ul(ibuf + i + 1,2,&decsum)) {
	    verror("error computing checksum!\n");
	    if (ilen_used)
		*ilen_used = i + 1; /* don't include checksum bytes! */
	    return -1;
	}
	else if (decsum != sum) {
	    verror("bad checksum: expected 0x%lx, got 0x%lx (%d data bytes)\n",
		   sum,decsum,i - start - 1);
	    if (ilen_used)
		*ilen_used = i + 1 + 2; /* do include checksum bytes! */
	    return -1;
	}
	else {
	    vdebug(9,LA_TARGET,LF_GDB,
		   "good checksum: expected 0x%lx, got 0x%lx (%d data bytes)\n",
		   sum,decsum,i - start - 1);
	    if (ilen_used)
		*ilen_used = i + 1 + 2;
	    /* Continue decoding... */
	}
    }

    /* Move past $ or % */
    start += 1;
    /* End points to # */
    end = i;

    /*
     * Decode the data; alloc *obuf; set *olen.
     */
    if (obuf && olen) {
	if ((end - start) == 0) {
	    *obuf = malloc(1);
	    **obuf = '\0';
	    *olen = 0;
	    vdebug(9,LA_TARGET,LF_GDB,"empty data in packet\n");
	    return 0;
	}

	alen = ((end - start) / 4096) * 4096;
	if ((end - start) != 4096)
	    alen += 4096;
	*obuf = malloc(alen);
	*olen = 0;

	for (i = start,j = 0; i < end; ++i,++j) {
	    /* Make sure *obuf is big enough... */
	    if (j >= alen) {
		alen += 4096;
		*obuf = realloc(*obuf,alen);
	    }

	    if (inesc) {
		(*obuf)[j] = ibuf[i + 1] ^ 0x20;
		++i;
		inesc = 0;
	    }
	    else if (ibuf[i] == 0x7d)
		inesc = 1;
	    else if (ibuf[i] == 0x2a) {
		/* Make sure *obuf is big enough for the run sequence */
		rlen = ibuf[i + 1] - 29;

		if ((j + rlen) >= alen) {
		    alen += 4096;
		    *obuf = realloc(*obuf,alen);
		}

		for (k = 0; k < rlen; ++k)
		    (*obuf)[j + 1 + k] = prevchar;

		j += rlen;
	    }
	    else {
		prevchar = (*obuf)[j] = ibuf[i];
	    }
	}

	/* Realloc to j + 1 (to leave space for a '\0' */
	*obuf = realloc(*obuf,j + 1);
	(*obuf)[j] = '\0';
	/* But the length does not count the '\0'! */
	*olen = j;
    }

    return 0;
}

static gdb_rsp_handler_ret_t
gdb_rsp_default_handler(struct target *target,char *data,unsigned int len,
			void *handler_data) {
    vdebug(5,LA_TARGET,LF_GDB,"cannot handle '%s' (len %u)\n",data,len);

    return GDB_RSP_HANDLER_NOTMINE;
}

int gdb_rsp_recv(struct target *target,int blocking,int only_one,
		 gdb_ptype_t *o_ptype) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    int rc;
    gdb_ptype_t ptype = GDB_UNKNOWN;
    char *obuf = NULL;
    char *new_ibuf;
    unsigned int new_alen;
    unsigned int olen = 0;
    unsigned int ilen_used = 0;
    int retval;

    GDB_CHECKCONN(-1);

    /*
     * If we had sent a packet, we might get a response to that packet;
     * we might get a nak; we might receive a new notification; we might
     * receive the next part of a notification, or its final OK; 
     */

    /*
     * Read everything we can; then see if we have a packet, a
     * notification, a simple ack (OK, Enn), an ack/nak, or an interrupt
     * (which we shouldn't get cause we're a client, but whatever).  If
     * we don't have a full packet, return 0 so that the caller tries
     * again when there is more input; we'll continue reading then...
     */
 decode:
    do {
	ptype = GDB_UNKNOWN;
	obuf = NULL;
	olen = 0;
	new_ibuf = NULL;
	new_alen = 0;
	ilen_used = 0;

	if (gstate->ibuf && gstate->ibuf_len > 0) {
	    /* Try to decode a full msg! */
	    rc = gdb_rsp_decode(target,gstate->ibuf,gstate->ibuf_len,
				&ptype,&ilen_used,&obuf,&olen);
	    if (rc == 1) {
		vdebug(8,LA_TARGET,LF_GDB,
		       "incomplete packet; not skipping %u processed bytes\n",
		       ilen_used);
	    }
	    else if (rc == -1) {
		verror("decoding error; skipping %u processed bytes!\n",
		       ilen_used);

		/* Send an immediate NAK. */
		gdb_rsp_nak(target);

		goto errout;
	    }
	    else {
		vdebug(8,LA_TARGET,LF_GDB,
		       "decoded %u-byte message (%s) of type %d (skip %u);"
		       " processing\n",olen,obuf,ptype,ilen_used);
		break;
	    }
	}

	if (gstate->ibuf_alen == gstate->ibuf_len) {
	    gstate->ibuf = realloc(gstate->ibuf,gstate->ibuf_alen + 4096);
	    gstate->ibuf_alen += 4096;
	}

	rc = recv(gstate->fd,gstate->ibuf + gstate->ibuf_len,
		  gstate->ibuf_alen - gstate->ibuf_len,
		  (blocking) ? 0 : MSG_DONTWAIT);
	if (rc == 0) {
	    vwarn("server disconnected unexpectedly!\n");
	    close(gstate->fd);
	    gstate->fd = -1;
	    return -1;
	}
	else if (rc < 0) {
	    if (errno == EAGAIN || errno == EWOULDBLOCK)
		return 0;
	    else if (errno == EINTR) {
		return 0;
	    }
	    else {
		verror("recv: %s (%d)\n",strerror(errno),errno);
		/* XXX: should we clear the ibuf buffer? */
		return -1;
	    }
	}
	else {
	    gstate->ibuf_len += rc;
	}
    } while (1);

    if (ptype == GDB_UNKNOWN) {
	verror("BUG! unknown message type!\n");
	goto errout;
    }
    else if (ptype == GDB_ACK) {
	vdebug(9,LA_TARGET,LF_GDB,
	       "ACK for %d bytes sent; clearing\n",gstate->obuf_len);
	if (gstate->obuf) {
	    free(gstate->obuf);
	    gstate->obuf = NULL;
	}
	gstate->obuf_len = 0;
    }
    else if (ptype == GDB_NAK) {
	vwarnopt(9,LA_TARGET,LF_GDB,
		 "NAK for %d bytes sent; retrying\n",gstate->obuf_len);

	if (gdb_rsp_send_raw(target,gstate->obuf,gstate->obuf_len)) {
	    verror("could not send %d encoded bytes that already failed!\n",
		   gstate->obuf_len);
	    goto errout;
	}

	vdebug(9,LA_TARGET,LF_GDB,
	       "retransmitted %d encoded bytes\n",gstate->obuf_len);

	if (!gstate->need_ack) {
	    free(gstate->obuf);
	    gstate->obuf = NULL;
	    gstate->obuf_len = 0;
	}
    }
    else if (ptype == GDB_NOTIFICATION) {
	// XXX finish
	verror("BUG! cannot handle notifications yet!\n");
	goto errout;
    }
    else if (ptype == GDB_PACKET) {
	/* Send an immediate ack */
	gdb_rsp_ack(target);

	if (gstate->handler) {
	    rc = gstate->handler(target,obuf,olen,gstate->handler_data);
	    if (rc == GDB_RSP_HANDLER_ERR) {
		verror("handler failed on packet '%s' (len %u); removing handler"
		       " and trying default handler!\n",
		       obuf,olen);
		gstate->handler = NULL;
		gstate->handler_ret = rc;
		goto default_handler;
	    }
	    else if (rc == GDB_RSP_HANDLER_DONE) {
		vdebug(8,LA_TARGET,LF_GDB,"handler handled '%s' (len %u)\n",
		       obuf,olen);
		gstate->handler = NULL;
		gstate->handler_ret = rc;
	    }
	    else if (rc == GDB_RSP_HANDLER_MORE) {
		vdebug(8,LA_TARGET,LF_GDB,
		       "handler handled '%s' (len %u) but expects more packets\n",
		       obuf,olen);
		gstate->handler_ret = rc;
	    }
	    else if (rc == GDB_RSP_HANDLER_NOTMINE) {
		vdebug(8,LA_TARGET,LF_GDB,
		       "handler does not own '%s' (len %u);"
		       " trying default handler\n",obuf,olen);
		gstate->handler_ret = rc;
		goto default_handler;
	    }
	    else {
		vwarn("bad return code %d from handler; trying default"
		      " handler!\n",rc);
		gstate->handler_ret = GDB_RSP_HANDLER_ERR;
		goto default_handler;
	    }
	}
	else {
	default_handler:
	    rc = gdb_rsp_default_handler(target,obuf,olen,NULL);
	    if (rc == GDB_RSP_HANDLER_ERR) {
		verror("default handler failed on packet '%s' (len %u)!\n",
		       obuf,olen);
		goto errout;
	    }
	    else if (rc == GDB_RSP_HANDLER_DONE) {
		vdebug(8,LA_TARGET,LF_GDB,
		       "default handler handled '%s' (len %u)\n",obuf,olen);
		gstate->handler = NULL;
	    }
	    else if (rc == GDB_RSP_HANDLER_MORE) {
		vdebug(8,LA_TARGET,LF_GDB,
		       "default handler handled '%s' (len %u) but expects more"
		       " packets\n",obuf,olen);
	    }
	    else if (rc == GDB_RSP_HANDLER_NOTMINE) {
		vdebug(8,LA_TARGET,LF_GDB,
		       "default handler does not own '%s' (len %u);"
		       " skipping this message!\n",obuf,olen);
	    }
	}
    }
    else {
	verror("invalid packet type %d!\n",ptype);
	errno = EBADMSG;
	goto errout;
    }

    /* Return successfully. */
    retval = 0;

 out:
    if (ilen_used >= gstate->ibuf_len) {
	if (gstate->ibuf_alen != 4096) {
	    gstate->ibuf = realloc(gstate->ibuf,4096);
	    gstate->ibuf_alen = 4096;

	    vdebug(12,LA_TARGET,LF_GDB,
		   "used all %u bytes; reset input buf to 4096\n",ilen_used);
	}
	else {
	    vdebug(12,LA_TARGET,LF_GDB,"used all %u bytes\n",ilen_used);
	}

	gstate->ibuf_len = 0;
    }
    else if (ilen_used > 0) {
	new_alen = (gstate->ibuf_len - ilen_used) / 4096;
	if ((gstate->ibuf_len - ilen_used) != 4096)
	    new_alen += 4096;
	new_ibuf = malloc(new_alen);
	memcpy(new_ibuf,gstate->ibuf + ilen_used,gstate->ibuf_len - ilen_used);
	free(gstate->ibuf);
	gstate->ibuf = new_ibuf;
	gstate->ibuf_alen = new_alen;
	gstate->ibuf_len -= ilen_used;

	vdebug(12,LA_TARGET,LF_GDB,
	       "shrunk input buf to %u by %u bytes; current used %u\n",
	       new_alen,ilen_used,gstate->ibuf_len);
    }

    if (obuf) {
	free(obuf);
	obuf = NULL;
    }

    if (o_ptype)
	*o_ptype = ptype;

    /*
     * If we processed some input, but there is still more, keep processing!
     */
    if (!only_one && retval == 0 && gstate->ibuf_len > 0 && ilen_used > 0) {
	vdebug(12,LA_TARGET,LF_GDB,"continuing to process %u remaining bytes!\n",
	       gstate->ibuf_len);
	fflush(stderr);
	goto decode;
    }
    else
	return retval;

 errout:
    retval = -1;
    goto out;
}

int gdb_rsp_recv_until_handled(struct target *target,
			       gdb_rsp_handler_t handler,
			       gdb_rsp_handler_ret_t *handler_ret) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    int rc;

    while (gstate->handler == handler) {
	rc = gdb_rsp_recv(target,1,0,NULL);
	if (rc) {
	    verror("failed to recv response; aborting!\n");
	    return -1;
	}
    }

    if (handler_ret)
	*handler_ret = gstate->handler_ret;

    return 0;
}

int gdb_rsp_recv_until_acked(struct target *target) {
    int rc;
    gdb_ptype_t ptype;

    while (1) {
	rc = gdb_rsp_recv(target,1,1,&ptype);
	if (rc) {
	    verror("failed to recv response; aborting!\n");
	    return -1;
	}
	else if (ptype != GDB_ACK) {
	    vdebug(12,LA_TARGET,LF_GDB,"received ptype %d, not ACK!\n",ptype);
	}
	else {
	    break;
	}
    }

    return 0;
}

/**
 ** Handlers.
 **/

static gdb_rsp_handler_ret_t
gdb_rsp_simple_ack_handler(struct target *target,char *data,unsigned int len,
			   void *handler_data) {
    char *next;
    int *ret = (int *)handler_data;

    if (len == 0) {
	if (ret)
	    *ret = -1;
	vwarnopt(9,LA_TARGET,LF_GDB,"empty reply -- not supported?\n");
	return GDB_RSP_HANDLER_DONE;
    }

    next = data;
    if (strncmp(next,"OK",2) == 0) {
	if (ret)
	    *ret = 0;
	return GDB_RSP_HANDLER_DONE;
    }
    else if (*next == 'E') {
	if (ret)
	    *ret = atoi(next+1);
	return GDB_RSP_HANDLER_DONE;
    }
    else {
	vwarnopt(12,LA_TARGET,LF_GDB,"unexpected simple ack '%s'\n",data);
	return GDB_RSP_HANDLER_NOTMINE;
    }
}

static gdb_rsp_handler_ret_t
gdb_rsp_features_handler(struct target *target,char *data,unsigned int len,
			 void *handler_data) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    char *end = data + len;
    char *cur;
    char *next;
    char *value;
    unsigned int i;

    if (len == 0) {
	vdebug(9,LA_TARGET,LF_GDB,"no features (empty reply)\n");
	return GDB_RSP_HANDLER_DONE;
    }

    next = data;
    while (next < end) {
	/* Get rid of any spaces... */
	i = 0;
	while (next < end) {
	    if (*next == ' ')
		++next;
	    else
		break;
	}
	cur = next;
	/* Find the next separator */
	while (next < end) {
	    if (*next == ';') {
		*next = '\0';
		++next;
		break;
	    }
	    else
		++next;
	}
	/* Get rid of any spaces... */
	i = 2;
	while ((next - i) >= cur && *(next - i) == ' ') {
	    *(next - i) = '\0';
	    ++i;
	}
	/* Parse the token. */
	value = cur;
	while (*value) {
	    if (*value == '=') {
		*value = '\0';
		++value;
		break;
	    }
	    else if (*value == '+') {
		*value = '\0';
		value = "+";
		break;
	    }
	    else if (*value == '-') {
		*value = '\0';
		value = "-";
		break;
	    }
	    else if (*value == '?') {
		*value = '\0';
		value = "?";
		break;
	    }
	    else
		++value;
	}
	/* Record the feature. */
	g_hash_table_insert(gstate->stubfeatures,strdup(cur),strdup(value));
	vdebug(5,LA_TARGET,LF_GDB,"stub feature '%s' -> '%s'\n",cur,value);
    }

    /* Not expecting anything more. */
    return GDB_RSP_HANDLER_DONE;
}

static gdb_rsp_handler_ret_t
gdb_rsp_vcont_check_handler(struct target *target,char *data,unsigned int len,
			    void *handler_data) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    char *end = data + len;
    char *next;

    if (len == 0) {
	vdebug(9,LA_TARGET,LF_GDB,"vCont not supported (empty reply)\n");
	return GDB_RSP_HANDLER_DONE;
    }

    next = data;

    while (next < end && *next == ' ')
	++next;

    if (strncmp(next,"vCont",5) != 0) {
	vdebug(9,LA_TARGET,LF_GDB,
	       "response '%s' (len %d) not for us!\n",data,len);
	return GDB_RSP_HANDLER_NOTMINE;
    }
    else {
	gstate->vcont = 1;
	next += 5;
    }

    vdebug(5,LA_TARGET,LF_GDB,"checking for vCont actions\n");

    next = data;
    while (next < end) {
	switch (*next) {
	case 'c':
	    gstate->vcont_c = 1;
	    vdebug(5,LA_TARGET,LF_GDB,"vCont 'c'\n");
	    break;
	case 'C':
	    gstate->vcont_C = 1;
	    vdebug(5,LA_TARGET,LF_GDB,"vCont 'C'\n");
	    break;
	case 's':
	    gstate->vcont_s = 1;
	    vdebug(5,LA_TARGET,LF_GDB,"vCont 's'\n");
	    break;
	case 'S':
	    gstate->vcont_S = 1;
	    vdebug(5,LA_TARGET,LF_GDB,"vCont 'S'\n");
	    break;
	case 't':
	    gstate->vcont_t = 1;
	    vdebug(5,LA_TARGET,LF_GDB,"vCont 't'\n");
	    break;
	case 'r':
	    gstate->vcont_r = 1;
	    vdebug(5,LA_TARGET,LF_GDB,"vCont 'r'\n");
	    break;
	default:
	    break;
	}

	++next;
    }

    /* Not expecting anything more. */
    return GDB_RSP_HANDLER_DONE;
}

/*
 * From the docs:
 *
 * Several packets and replies include a thread-id field to identify a
 * thread. Normally these are positive numbers with a target-specific
 * interpretation, formatted as big-endian hex strings. A thread-id can
 * also be a literal ‘-1’ to indicate all threads, or ‘0’ to pick any
 * thread.
 *
 * In addition, the remote protocol supports a multiprocess feature in
 * which the thread-id syntax is extended to optionally include both
 * process and thread ID fields, as ‘ppid.tid’. The pid (process) and
 * tid (thread) components each have the format described above: a
 * positive number with target-specific interpretation formatted as a
 * big-endian hex string, literal ‘-1’ to indicate all processes or
 * threads (respectively), or ‘0’ to indicate an arbitrary process or
 * thread. Specifying just a process, as ‘ppid’, is equivalent to
 * ‘ppid.-1’. It is an error to specify all processes but a specific
 * thread, such as ‘p-1.tid’. Note that the ‘p’ prefix is not used for
 * those packets and replies explicitly documented to include a process
 * ID, rather than a thread-id.
 *
 * The multiprocess thread-id syntax extensions are only used if both
 * GDB and the stub report support for the ‘multiprocess’ feature using
 * ‘qSupported’.
 */

static gdb_rsp_handler_ret_t
gdb_rsp_stop_handler(struct target *target,char *data,unsigned int len,
		     void *handler_data) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    char *end = data + len;
    char *next;
    char command;
    struct gdb_rsp_stop_status *ss = &gstate->last_stop_status;
    char *colon,*semicolon,*dot;
    unsigned int xlen;

    next = data;

    while (next < end && *next == ' ') ++next;

    command = *next;
    ++next;
    switch (command) {
    case 'S':
	vdebug(9,LA_TARGET,LF_GDB,"stop response 'S'\n");
	ss->reason = GDB_RSP_STOP_SIGNAL;
	while (next < end && (*next == ' ' || *next == ';')) ++next;
	ss->signal = 0;
	__h2ul(next,((end - next) > 2) ? 2 : (end - next),&ss->signal);
	next += 2;
	break;
    case 'T':
	vdebug(9,LA_TARGET,LF_GDB,"stop response 'T'\n");
	ss->reason = GDB_RSP_STOP_SIGNAL;
	while (next < end && (*next == ' ' || *next == ';')) ++next;
	ss->signal = 0;
	xlen = ((end - next) > 2) ? 2 : (end - next);
	__h2ul(next,xlen,&ss->signal);
	next += xlen;
	while (next < end && (*next == ' ' || *next == ';')) ++next;
	while (next < end) {
	    /*
	     * Parse n1:r1;n2:r2;... string.
	     */
	    colon = index(next,':');
	    if (!colon)
		break;
	    semicolon = index(next,';');
	    if (!semicolon)
		semicolon = end;

	    *colon = '\0';
	    ++colon; /* The current rN value */
	    *semicolon = '\0';

	    if (strncmp(next,"thread",6) == 0) {
		dot = index(colon,'.');
		if (*colon == 'p' && dot) {
		    ++colon;
		    *dot = '\0';
		    ss->has_pid = 1;
		    ss->has_tid = 1;
		    if (strcmp(colon,"-1") == 0)
			ss->pid = -1;
		    else if (*colon == '0' && *(colon + 1) == '\0')
			ss->pid = 0;
		    else {
			__h2ul_be(colon,(dot - colon),(unsigned long *)&ss->pid);
		    }
		    if (strncmp(dot + 1,"-1",2) == 0)
			ss->tid = -1;
		    else if (*(dot + 1) == '0')
			ss->tid = 0;
		    else {
			__h2ul_be(colon,(semicolon - (dot + 1)),
				  (unsigned long *)&ss->tid);
		    }
		}
		else {
		    ss->has_tid = 1;
		    if (strcmp(colon,"-1") == 0)
			ss->tid = -1;
		    else if (*colon == '0' && *(colon + 1) == '\0')
			ss->tid = 0;
		    else {
			__h2ul_be(colon,(dot - colon),(unsigned long *)&ss->tid);
		    }
		}
	    }
	    else if (strncmp(next,"core",4) == 0) {
		ss->has_core = 1;
		ss->core = 0;
		__h2ul(colon,semicolon - colon,&ss->core);
	    }
	    else if (strncmp(next,"watch",5) == 0) {
		ss->reason = GDB_RSP_STOP_WATCH;
		ss->addr = 0;
		__h2ul(colon,semicolon - colon,&ss->addr);
	    }
	    else if (strncmp(next,"rwatch",6) == 0) {
		ss->reason = GDB_RSP_STOP_RWATCH;
		ss->addr = 0;
		__h2ul(colon,semicolon - colon,&ss->addr);
	    }
	    else if (strncmp(next,"awatch",6) == 0) {
		ss->reason = GDB_RSP_STOP_AWATCH;
		ss->addr = 0;
		__h2ul(colon,semicolon - colon,&ss->addr);
	    }
	    else if (strncmp(next,"library",7) == 0) {
		ss->reason = GDB_RSP_STOP_LIBRARY;
	    }
	    else if (strncmp(next,"replaylog",9) == 0) {
		ss->reason = GDB_RSP_STOP_LIBRARY;
	    }
	    else if (isdigit(*next) || (*next >= 'a' && *next <= 'f')
		     || (*next >= 'f' && *next <= 'F')) {
		vdebug(9,LA_TARGET,LF_GDB,
		       "skipping register value %s:%s\n",next,colon);
	    }
	    else {
		vdebug(9,LA_TARGET,LF_GDB,
		       "skipping unknown reason:value %s:%s\n",next,colon);
	    }

	    ++semicolon; /* next value for "next" */
	    next = semicolon;
	}
	break;
    case 'W':
	vdebug(9,LA_TARGET,LF_GDB,"stop response 'W'\n");
	ss->reason = GDB_RSP_STOP_EXITED;
	while (next < end && (*next == ' ' || *next == ';')) ++next;
	ss->signal = 0;
	xlen = ((end - next) > 2) ? 2 : (end - next);
	__h2ul(next,xlen,&ss->signal);
	next += xlen;
	while (next < end && (*next == ' ' || *next == ';')) ++next;
	if (strncmp(next,"process:",8) == 0) {
	    next += 8;
	    ss->has_pid = 1;
	    ss->pid = 0;
	    __h2ul_be(next,end - next,(unsigned long *)&ss->pid);
	}
	break;
    case 'X':
	vdebug(9,LA_TARGET,LF_GDB,"stop response 'X'\n");
	ss->reason = GDB_RSP_STOP_TERMINATED;
	while (next < end && (*next == ' ' || *next == ';')) ++next;
	ss->signal = 0;
	xlen = ((end - next) > 2) ? 2 : (end - next);
	__h2ul(next,xlen,&ss->signal);
	next += xlen;
	while (next < end && (*next == ' ' || *next == ';')) ++next;
	if (strncmp(next,"process:",8) == 0) {
	    next += 8;
	    ss->has_pid = 1;
	    ss->pid = 0;
	    __h2ul_be(next,end - next,(unsigned long *)&ss->pid);
	}
	break;
    case 'O':
	vdebug(9,LA_TARGET,LF_GDB,"stop response 'O'\n");
	vwarn("unsupported console output stop \"status\"\n");
	break;
    case 'F':
	vdebug(9,LA_TARGET,LF_GDB,"stop response 'F'\n");
	vwarn("unsupported file i/o extension; ignoring\n");
	break;
    default:
	vwarnopt(9,LA_TARGET,LF_GDB,
		 "response '%s' (len %d) not for us!\n",data,len);
	return GDB_RSP_HANDLER_NOTMINE;
    }

    switch (ss->reason) {
    case GDB_RSP_STOP_UNKNOWN:
    case GDB_RSP_STOP_NONE:
	target_set_status(target,TSTATUS_UNKNOWN);
	break;
    case GDB_RSP_STOP_SIGNAL:
    case GDB_RSP_STOP_WATCH:
    case GDB_RSP_STOP_RWATCH:
    case GDB_RSP_STOP_AWATCH:
    case GDB_RSP_STOP_LIBRARY:
    case GDB_RSP_STOP_REPLAYLOG:
	target_set_status(target,TSTATUS_PAUSED);
	break;
    case GDB_RSP_STOP_EXITED:
	target_set_status(target,TSTATUS_DONE);
	break;
    case GDB_RSP_STOP_TERMINATED:
	target_set_status(target,TSTATUS_DONE);
	break;
    default:
	target_set_status(target,TSTATUS_ERROR);
	break;
    }

    gstate->rsp_status_valid = 1;

    /* Not expecting anything more. */
    return GDB_RSP_HANDLER_DONE;
}

/*
 * QEMU's stub is a bit funny!
 *
 * XXX: we only do the GP regs, IP, flags, and selectors.  Who cares
 * about mmx and FP regs... not system programmers!
 */
static unsigned int qemu_reg_count_64 = 24;
static unsigned int qemu_offset_to_reg_64[24] = {
    0,3,2,1,4,5,6,7,8,9,10,11,12,13,14,15,16,51,52,53,50,54,55,
};
static int qemu_arch_reg_to_reg_64[ARCH_X86_64_REG_COUNT] = {
    0,3,2,1,4,5,6,7,8,9,10,11,12,13,14,15,16,
    -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,
    -1,17,18,19,20,21,22,
    -1,-1,
    -1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,
    -1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,
    -1,-1,-1,-1,-1,-1,-1,-1,
    -1,
};
static unsigned int qemu_reg_sizes_64[24] = {
    8,8,8,8,8,8,8,8,8,8,8, 8, 8, 8, 8, 8, 8, 4, 4, 4, 4, 4, 4,
};
static unsigned int qemu_reg_count_32 = 16;
static unsigned int qemu_offset_to_reg_32[16] = {
    0,3,2,1,4,5,6,7,8,9, 41,42,43,40,44,45,
};
static int qemu_arch_reg_to_reg_32[ARCH_X86_REG_COUNT] = {
    0,3,2,1,4,5,6,7,8,9,
    -1,
    -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,
    41,42,43,40,44,45,
    -1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,
    -1,
};
static unsigned int qemu_reg_sizes_32[16] = {
    4,4,4,4,4,4,4,4,4,4, 4, 4, 4, 4, 4, 4,
};

static gdb_rsp_handler_ret_t
gdb_rsp_regs_handler(struct target *target,char *data,unsigned int len,
		     void *handler_data) {
    struct gdb_spec *gspec = (struct gdb_spec *)target->spec->backend_spec;
    char *end = data + len;
    char *next;
    struct regcache *regcache = (struct regcache *)handler_data;
    unsigned int i;
    REGVAL regval = 0;
    unsigned int *offset_to_reg = NULL;
    unsigned int *reg_sizes = NULL;
    unsigned int reg_count = 0;

    if (gspec->is_qemu) {
	if (target->arch->type == ARCH_X86_64) {
	    offset_to_reg = qemu_offset_to_reg_64;
	    reg_sizes = qemu_reg_sizes_64;
	    reg_count = qemu_reg_count_64;
	}
	else {
	    offset_to_reg = qemu_offset_to_reg_32;
	    reg_sizes = qemu_reg_sizes_32;
	    reg_count = qemu_reg_count_32;
	}
    }

    if (regcache) {
	next = data;
	i = 0;
	while (next < end) {
	    regval = 0;

	    /*
	     * If we have a special register mapping hack, use it;
	     * otherwise just go in order by target wordsize.  This
	     * default will almost certainly always be wrong, but we
	     * have to do something...
	     */
	    if (reg_count > 0) {
		if (i >= reg_count)
		    break;
		__hs2ul_lsb(next,reg_sizes[i] * 2,&regval);
		regcache_init_reg(regcache,offset_to_reg[i],regval);
		next += reg_sizes[i] * 2;
	    }
	    else {
		__hs2ul_lsb(next,sizeof(regval)*2,&regval);
		regcache_init_reg(regcache,i,regval);
		next += sizeof(regval) * 2;
	    }

	    ++i;
	}
    }

    /* Not expecting anything more. */
    return GDB_RSP_HANDLER_DONE;
}

static gdb_rsp_handler_ret_t
gdb_rsp_read_mem_handler(struct target *target,char *data,unsigned int len,
			 void *handler_data) {
    struct gdb_rsp_read_mem_data *d = \
	(struct gdb_rsp_read_mem_data *)handler_data;
    unsigned int dlen = len;

    if (*data == 'E') {
	if (d)
	    d->error = atoi(data+1);
	return GDB_RSP_HANDLER_ERR;
    }

    if (!d->buf) {
	d->length = len / 2 + (len % 2);
	d->buf = malloc(d->length + 1);
	d->buf[d->length] = '\0';
    }
    else if (d->length < (len / 2 + (len % 2))) {
	vwarnopt(12,LA_TARGET,LF_GDB,
		 "not enough space in supplied buffer for decoded response;"
		 " filling what we can!\n");
	dlen = d->length * 2;
	/*
	errno = ENOMEM;
	return GDB_RSP_HANDLER_ERR;
	*/
    }

    __hs2d(data,dlen,d->buf);

    /* Not expecting anything more. */
    return GDB_RSP_HANDLER_DONE;
}

/**
 ** Commands or command wrappers.
 **/

/*
 * RSP commands from the client to the server are textual strings,
 * optionally followed by arguments. Each command is sent in its own
 * packet. The packets fall into four groups:
 *
 *   Packets requiring no acknowledgment. These commands are: f, i, I, k,
 *     R, t and vFlashDone.
 *
 *   Packets requiring a simple acknowledgment packet. The
 *     acknowledgment is either OK, Enn (where nn is an error number) or
 *     for some commands an empty packet (meaning "unsupported"). These
 *     commands are: !, A, D, G, H, M, P, Qxxxx, T, vFlashErase,
 *     vFlashWrite, X, z and Z.
 *
 *   Packets that return result data or an error code.. These commands
 *     are: ?, c, C, g, m, p, qxxxx, s, S and most vxxxx.
 *
 *   Deprecated packets which should no longer be used. These commands
 *     are b, B, d and r.  
 */

target_status_t gdb_rsp_load_status(struct target *target) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    gdb_rsp_handler_ret_t hret;

    if (gstate->rsp_status_valid)
	return target->status;

    if (gdb_rsp_send_packet(target,"?",0,gdb_rsp_stop_handler,NULL)) {
	verror("failed to check status via ? !\n");
	return -1;
    }
    else {
	vdebug(9,LA_TARGET,LF_GDB,"queried status via ?\n");
    }

    if (gdb_rsp_recv_until_handled(target,gdb_rsp_stop_handler,&hret)) {
	verror("failed to recv stop response; aborting!\n");
	return -1;
    }
    else if (hret != GDB_RSP_HANDLER_DONE) {
	verror("stop handler error returned not done: %d; aborting!\n",hret);
	return -1;
    }

    return target->status;
}

int gdb_rsp_pause(struct target *target) {
    /*
     * XXX: interrupts are not ACK'd, but they seem to be the only way
     * to pause a target.  Probably we should query with ? to get a stop
     * reply status...
     */
    if (gdb_rsp_interrupt(target)) {
	return -1;
    }

    return 0;
}

int gdb_rsp_resume(struct target *target) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    //gdb_rsp_handler_ret_t hret;
    //    struct gdb_rsp_stop_status ss;

    //memset(&ss,0,sizeof(ss));

    if (gstate->vcont && gstate->vcont_c) {
	if (gdb_rsp_send_packet(target,"vCont;c",0,gdb_rsp_stop_handler,
				&gstate->last_stop_status)) {
	    verror("failed to resume via vCont;c!\n");
	    return -1;
	}
	else {
	    vdebug(9,LA_TARGET,LF_GDB,"resumed via vCont;c\n");
	}
    }
    else {
	if (gdb_rsp_send_packet(target,"c",0,gdb_rsp_stop_handler,
				&gstate->last_stop_status)) {
	    verror("failed to resume via c!\n");
	    return -1;
	}
	else {
	    vdebug(9,LA_TARGET,LF_GDB,"resumed via c\n");
	}
    }

    /*
     * XXX: shoot, we can't wait for the vCont response to be handled!
     * We only want to wait for an ACK.
     */
    if (gdb_rsp_recv_until_acked(target)) {
	verror("failed to recv ACK; aborting!\n");
	return -1;
    }

    /*
    if (gdb_rsp_recv_until_handled(target,gdb_rsp_stop_handler,&hret)) {
	verror("failed to recv stop response; aborting!\n");
	return -1;
    }
    else if (hret != GDB_RSP_HANDLER_DONE) {
	verror("stop handler error returned not done: %d; aborting!\n",hret);
	return -1;
    }

    gstate->last_stop_status = ss;
    */

    return 0;
}

int gdb_rsp_step(struct target *target) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;

    if (gstate->vcont && gstate->vcont_s) {
	if (gdb_rsp_send_packet(target,"vCont;s",0,gdb_rsp_stop_handler,
				&gstate->last_stop_status)) {
	    verror("failed to resume via vCont;s!\n");
	    return -1;
	}
	else {
	    vdebug(9,LA_TARGET,LF_GDB,"resumed via vCont;s\n");
	}
    }
    else {
	if (gdb_rsp_send_packet(target,"s",0,gdb_rsp_stop_handler,
				&gstate->last_stop_status)) {
	    verror("failed to resume via s!\n");
	    return -1;
	}
	else {
	    vdebug(9,LA_TARGET,LF_GDB,"resumed via s\n");
	}
    }

    if (gdb_rsp_recv_until_acked(target)) {
	verror("failed to recv ACK; aborting!\n");
	return -1;
    }

    return 0;
}

int gdb_rsp_query_stub(struct target *target) {
    gdb_rsp_handler_ret_t hret = GDB_RSP_HANDLER_ERR;

    if (gdb_rsp_send_packet(target,
			    "qSupported:multiprocess+;qRelocInsn-;xmlRegisters-",
			    0,gdb_rsp_features_handler,NULL)) {
	verror("could not send features via qSupported!\n");
	return -1;
    }

    if (gdb_rsp_recv_until_handled(target,gdb_rsp_features_handler,&hret)) {
	verror("failed to recv qSupported response; aborting!\n");
	return -1;
    }
    else if (hret != GDB_RSP_HANDLER_DONE) {
	verror("features handler error returned not done: %d; aborting!\n",hret);
	return -1;
    }

    if (gdb_rsp_send_packet(target,"vCont?",0,gdb_rsp_vcont_check_handler,NULL)) {
	verror("could not check vCont features via vCont?!\n");
	return -1;
    }

    if (gdb_rsp_recv_until_handled(target,gdb_rsp_vcont_check_handler,&hret)) {
	verror("failed to recv vCont? response; aborting!\n");
	return -1;
    }
    else if (hret != GDB_RSP_HANDLER_DONE) {
	verror("vCont? handler error returned not done: %d; aborting!\n",hret);
	return -1;
    }

    return 0;
}

int gdb_rsp_read_regs(struct target *target,struct regcache *regcache) {
    gdb_rsp_handler_ret_t hret = GDB_RSP_HANDLER_ERR;

    if (gdb_rsp_send_packet(target,"g",0,gdb_rsp_regs_handler,regcache)) {
	verror("could not read regs!\n");
	return -1;
    }

    if (gdb_rsp_recv_until_handled(target,gdb_rsp_regs_handler,&hret)) {
	verror("failed to recv read regs response; aborting!\n");
	return -1;
    }
    else if (hret != GDB_RSP_HANDLER_DONE) {
	verror("regs handler error returned not done: %d; aborting!\n",hret);
	return -1;
    }

    return 0;
}

int gdb_rsp_write_regs(struct target *target,struct regcache *regcache) {
    struct gdb_spec *gspec = (struct gdb_spec *)target->spec->backend_spec;
    gdb_rsp_handler_ret_t hret = GDB_RSP_HANDLER_ERR;
    REGVAL regval = 0;
    char *buf;
    unsigned int len;
    int sret = 0;
    int rc;
    char *next;
    unsigned int i;
    unsigned int *offset_to_reg = NULL;
    unsigned int *reg_sizes = NULL;
    unsigned int reg_count = 0;

    if (gspec->is_qemu) {
	if (target->arch->type == ARCH_X86_64) {
	    offset_to_reg = qemu_offset_to_reg_64;
	    reg_sizes = qemu_reg_sizes_64;
	    reg_count = qemu_reg_count_64;
	}
	else {
	    offset_to_reg = qemu_offset_to_reg_32;
	    reg_sizes = qemu_reg_sizes_32;
	    reg_count = qemu_reg_count_32;
	}
    }
    else
	reg_count = regcache->arch->regcount;

    /*
     * This should be enough, but we have realloc() support in case
     * there are big registers.  Of course, we don't support those yet :).
     */
    len = reg_count * target->arch->wordsize * 2 + 2;
    buf = malloc(len);

    buf[0] = 'G';
    next = buf + 1;
    for (i = 0; i < reg_count; ++i) {
	regval = 0;

	/*
	 * If we have a special register mapping hack, use it;
	 * otherwise just go in order by target wordsize.  This
	 * default will almost certainly always be wrong, but we
	 * have to do something...
	 */
	if (offset_to_reg) {
	    if (((next + reg_sizes[i] * 2) - buf) >= (len - 1)) {
		len += 128;
		buf = realloc(buf,len);
	    }
	    regcache_read_reg(regcache,offset_to_reg[i],&regval);
	    __d2hs((char *)&regval,reg_sizes[i],next);
	    next += reg_sizes[i] * 2;
	}
	else {
	    if (((next + target->arch->wordsize * 2) - buf) >= (len - 1)) {
		len += 128;
		buf = realloc(buf,len);
	    }
	    regcache_read_reg(regcache,i,&regval);
	    __d2hs((char *)&regval,target->arch->wordsize,next);
	    next += target->arch->wordsize * 2;
	}
    }

    *next = '\0';

    rc = gdb_rsp_send_packet(target,buf,0,gdb_rsp_simple_ack_handler,&sret);
    if (rc) {
	verror("could not write registers!\n");
	goto errout;
    }

    rc = gdb_rsp_recv_until_handled(target,gdb_rsp_simple_ack_handler,&hret);
    if (rc) {
	verror("failed to recv response!\n");
	goto errout;
    }
    else if (hret != GDB_RSP_HANDLER_DONE) {
	verror("simple ack handler returned not done: %d\n",hret);
	goto errout;
    }
    else if (sret) {
	verror("failed: error %d\n",sret);
	goto errout;
    }

    vdebug(8,LA_TARGET,LF_GDB,"wrote all GP regs\n");
    return 0;

 errout:
    vwarnopt(8,LA_TARGET,LF_GDB,"failed to write GP regs\n");
    return -1;
}

/*
 * XXX: since we don't necessarily save all the registers from the 'g'
 * read GP regs command, we cannot just use 'G' to write them back.  So
 * we write each dirty one back invididually... :).
 *
 * Ok, but the QEMU stub doesn't accept 'p' or 'P' unless the client and
 * stub both support the GDB target xml description stuff... which we
 * don't, and QEMU by itself doesn't seem to either.
 */
int gdb_rsp_write_reg_one_by_one(struct target *target,struct regcache *regcache) {
    struct gdb_spec *gspec = (struct gdb_spec *)target->spec->backend_spec;
    gdb_rsp_handler_ret_t hret = GDB_RSP_HANDLER_ERR;
    int *areg_to_qreg = NULL;
    REGVAL regval = 0;
    /* 129 can support regval sizes up to 64 bytes for __d2hs below. */
    char rsval[129];
    char buf[160];
    int sret = 0;
    int retval = 0;
    int count = 0;
    unsigned int *reg_sizes = NULL;
    int i,qreg;
    unsigned int qsize;
    int rc;

    if (gspec->is_qemu) {
	if (target->arch->type == ARCH_X86_64) {
	    areg_to_qreg = qemu_arch_reg_to_reg_64;
	    reg_sizes = qemu_reg_sizes_64;
	}
	else {
	    areg_to_qreg = qemu_arch_reg_to_reg_32;
	    reg_sizes = qemu_reg_sizes_32;
	}
    }

    for (i = 0; i < target->arch->regcount; ++i) {
	if (regcache_read_reg_ifdirty(regcache,i,&regval))
	    continue;

	if (areg_to_qreg) {
	    qreg = areg_to_qreg[i];
	    if (qreg < 0)
		continue;
	    qsize = reg_sizes[qreg];
	}
	else {
	    /*
	     * XXX: this is almost certain to be wrong!  We need the
	     * arch-specific register number mapping and size.
	     */
	    qreg = i;
	    qsize = target->arch->wordsize;
	}

	__d2hs((char *)&regval,qsize,rsval);
	rsval[qsize * 2] = '\0';
	rc = snprintf(buf,sizeof(buf),"P%x=%s",qreg,rsval);

	rc = gdb_rsp_send_packet(target,buf,0,gdb_rsp_simple_ack_handler,&sret);
	if (rc) {
	    verror("could not write areg %d qreg %d!\n",i,qreg);
	    --retval;
	    continue;
	}

	rc = gdb_rsp_recv_until_handled(target,gdb_rsp_simple_ack_handler,&hret);
	if (rc) {
	    verror("failed to recv response (areg %d qreg %d)!\n",i,qreg);
	    --retval;
	}
	else if (hret != GDB_RSP_HANDLER_DONE) {
	    verror("simple ack handler returned not done: %d (areg %d qreg %d)!\n",
		   hret,i,qreg);
	    --retval;
	}
	else if (sret) {
	    verror("failed: error %d! (areg %d qreg %d)\n",sret,i,qreg);
	    --retval;
	}
	else
	    ++count;
    }

    vdebug(8,LA_TARGET,LF_GDB,"wrote %d dirty regs\n",count);
    if (retval) {
	vwarnopt(8,LA_TARGET,LF_GDB,"failed to write %d dirty regs\n",-retval);
    }

    return retval;
}

int gdb_rsp_read_mem(struct target *target,ADDR addr,
		     unsigned long length,unsigned char *buf) {
    gdb_rsp_handler_ret_t hret = GDB_RSP_HANDLER_ERR;
    char cmd[128];
    struct gdb_rsp_read_mem_data d;

    memset(&d,0,sizeof(d));
    d.buf = (char *)buf;
    d.length = length;

    snprintf(cmd,sizeof(cmd),"m%"PRIxADDR",%lx",addr,length);

    if (gdb_rsp_send_packet(target,cmd,0,gdb_rsp_read_mem_handler,&d)) {
	verror("could not send read mem request '%s'!\n",cmd);
	return -1;
    }

    if (gdb_rsp_recv_until_handled(target,gdb_rsp_read_mem_handler,&hret)) {
	verror("failed to recv read mem response; aborting!\n");
	return -1;
    }
    else if (hret != GDB_RSP_HANDLER_DONE) {
	verror("read mem handler returned not done: %d; aborting!\n",hret);
	return -1;
    }
    else if (d.error) {
	verror("failed to read mem: error %d!\n",d.error);
	return -1;
    }

    return 0;
}

int gdb_rsp_write_mem(struct target *target,ADDR addr,
		      unsigned long length,unsigned char *buf) {
    gdb_rsp_handler_ret_t hret = GDB_RSP_HANDLER_ERR;
    char *cmd;
    unsigned long len;
    int sret = 0;

    len = 16 + 1 + 16 + length * 2 + 1;
    cmd = malloc(len);
    cmd[len] = '\0';

    sret = snprintf(cmd,len,"M%"PRIxADDR",%lu:",addr,length);
    __d2hs((char *)buf,length,cmd + len);

    if (gdb_rsp_send_packet(target,cmd,0,gdb_rsp_simple_ack_handler,&sret)) {
	verror("could not send request '%s'!\n",cmd);
	return -1;
    }

    if (gdb_rsp_recv_until_handled(target,gdb_rsp_simple_ack_handler,&hret)) {
	verror("failed to recv response; aborting!\n");
	return -1;
    }
    else if (hret != GDB_RSP_HANDLER_DONE) {
	verror("simple ack handler returned not done: %d; aborting!\n",hret);
	return -1;
    }
    else if (sret) {
	verror("failed: error %d!\n",sret);
	return -1;
    }

    return 0;
}

int gdb_rsp_insert_break(struct target *target,ADDR addr,
			 gdb_rsp_break_t bt,int kind) {
    gdb_rsp_handler_ret_t hret = GDB_RSP_HANDLER_ERR;
    char buf[128];
    int sret = 0;

    snprintf(buf,sizeof(buf),"Z%d,%"PRIxADDR",%d",bt,addr,kind);

    if (gdb_rsp_send_packet(target,buf,0,gdb_rsp_simple_ack_handler,&sret)) {
	verror("could not send breakpoint insert request '%s'!\n",buf);
	return -1;
    }

    if (gdb_rsp_recv_until_handled(target,gdb_rsp_simple_ack_handler,&hret)) {
	verror("failed to recv breakpoint insert response; aborting!\n");
	return -1;
    }
    else if (hret != GDB_RSP_HANDLER_DONE) {
	verror("simple ack handler returned not done: %d; aborting!\n",hret);
	return -1;
    }
    else if (sret) {
	verror("failed to insert breakpoint: error %d!\n",sret);
	return -1;
    }

    return 0;
}

int gdb_rsp_remove_break(struct target *target,ADDR addr,
			 gdb_rsp_break_t bt,int kind) {
    gdb_rsp_handler_ret_t hret = GDB_RSP_HANDLER_ERR;
    char buf[128];
    int sret = 0;

    snprintf(buf,sizeof(buf),"z%d,%"PRIxADDR",%d",bt,addr,kind);

    if (gdb_rsp_send_packet(target,buf,0,gdb_rsp_simple_ack_handler,&sret)) {
	verror("could not send breakpoint remove request '%s'!\n",buf);
	return -1;
    }

    if (gdb_rsp_recv_until_handled(target,gdb_rsp_simple_ack_handler,&hret)) {
	verror("failed to recv breakpoint remove response; aborting!\n");
	return -1;
    }
    else if (hret != GDB_RSP_HANDLER_DONE) {
	verror("simple ack handler returned not done: %d; aborting!\n",hret);
	return -1;
    }
    else if (sret) {
	verror("failed to remove breakpoint: error %d!\n",sret);
	return -1;
    }

    return 0;
}

/**
 ** Utility stuff...
 **/

static inline int __h2ul(char *str,unsigned int len,unsigned long *out) {
    unsigned long factor = 0;
    unsigned int x;
    unsigned long sum = 0;

    if (len > sizeof(*out) * 2) {
	errno = ENOMEM;
	return -1;
    }

    while (len) {
	--len;
	x = *(str + len);
	if (x >= '0' && x <= '9')
	    x -= '0';
	else if (x >= 'A' && x <= 'F')
	    x = (x - 'A') + 10;
	else if (x >= 'a' && x <= 'f')
	    x = (x - 'a') + 10;
	else {
	    vwarnopt(15,LA_TARGET,LF_GDB,"bad hex char 0x%hhx/%c!\n",x,(char)x);
	    errno = EINVAL;
	    return -1;
	}

	if (factor == 0) {
	    sum = x;
	    factor = 16;
	}
	else {
	    sum += x * factor;
	    factor *= 16;
	}
    }

    if (out)
	*out = sum;

    return 0;
}

static inline int __hs2ul_lsb(char *str,unsigned int len,unsigned long *out) {
    unsigned long factor = 0;
    unsigned int x,y;
    unsigned long sum = 0;
    unsigned int i;

    if (len > sizeof(*out) * 2) {
	errno = ENOMEM;
	return -1;
    }

    i = 0;
    while (i < len) {
	x = *(str + i);
	y = *(str + i + 1);

	if (x >= '0' && x <= '9') x -= '0';
	else if (x >= 'A' && x <= 'F') x = (x - 'A') + 10;
	else if (x >= 'a' && x <= 'f') x = (x - 'a') + 10;
	else {
	    vwarnopt(15,LA_TARGET,LF_GDB,"bad hex char 0x%hhx!\n",x);
	    errno = EINVAL;
	    return -1;
	}

	if (y >= '0' && y <= '9') y -= '0';
	else if (y >= 'A' && y <= 'F') y = (y - 'A') + 10;
	else if (y >= 'a' && y <= 'f') y = (y - 'a') + 10;
	else {
	    vwarnopt(15,LA_TARGET,LF_GDB,"bad hex char 0x%hhx!\n",y);
	    errno = EINVAL;
	    return -1;
	}

	if (factor == 0) {
	    sum = y;
	    factor = 16;
	}
	else {
	    sum += y * factor;
	    factor *= 16;
	}

	sum += x * factor;
	factor *= 16;

	i += 2;
    }

    if (out)
	*out = sum;

    return 0;
}

static inline int __h2ul_be(char *str,unsigned int len,unsigned long *out) {
    unsigned long factor = 0;
    unsigned int x;
    unsigned long sum = 0;
    unsigned int i;

    if (len > sizeof(*out) * 2) {
	errno = ENOMEM;
	return -1;
    }

    i = 0;
    while (i < len) {
	x = *(str + i);
	if (x >= '0' && x <= '9')
	    x -= '0';
	else if (x >= 'A' && x <= 'F')
	    x = (x - 'A') + 10;
	else if (x >= 'a' && x <= 'f')
	    x = (x - 'a') + 10;
	else {
	    vwarnopt(15,LA_TARGET,LF_GDB,"bad hex char 0x%hhx!\n",x);
	    errno = EINVAL;
	    return -1;
	}

	if (factor == 0) {
	    sum = x;
	    factor = 16;
	}
	else {
	    sum += x * factor;
	    factor *= 16;
	}

	++i;
    }

    if (out)
	*out = sum;

    return 0;
}

static inline int __hs2d(char *str,unsigned int len,char *buf) {
    unsigned int x,y;
    unsigned int i;

    i = 0;
    while (i < len) {
	x = *(str + i);
	y = *(str + i + 1);

	if (x >= '0' && x <= '9') x -= '0';
	else if (x >= 'A' && x <= 'F') x = (x - 'A') + 10;
	else if (x >= 'a' && x <= 'f') x = (x - 'a') + 10;
	else {
	    vwarnopt(15,LA_TARGET,LF_GDB,"bad hex char 0x%hhx!\n",x);
	    errno = EINVAL;
	    return -1;
	}

	if (y >= '0' && y <= '9') y -= '0';
	else if (y >= 'A' && y <= 'F') y = (y - 'A') + 10;
	else if (y >= 'a' && y <= 'f') y = (y - 'a') + 10;
	else {
	    vwarnopt(15,LA_TARGET,LF_GDB,"bad hex char 0x%hhx!\n",y);
	    errno = EINVAL;
	    return -1;
	}

	buf[i/2] = y + 16*x;

	i += 2;
    }

    return 0;
}

static inline int __d2hs(char *buf,unsigned int len,char *str) {
    unsigned int i;
    uint8_t hi,lo;

    i = 0;
    while (i < len) {
	lo = buf[i] & 0xf;
	hi = (buf[i] >> 4) & 0xf;

	if (lo <= 9) str[i*2+1] = '0' + lo;
	else str[i*2+1] = 'a' + (lo - 10);

	if (hi <= 9) str[i*2] = '0' + hi;
	else str[i*2] = 'a' + (hi - 10);

	++i;
    }

    return 0;
}
