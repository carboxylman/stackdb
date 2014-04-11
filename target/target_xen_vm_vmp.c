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

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#if !defined(UNIX_PATH_MAX)
#define UNIX_PATH_MAX (size_t)sizeof(((struct sockaddr_un *) 0)->sun_path)
#endif
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#include <xenctrl.h>
#include <xen/xen.h>

#include <glib.h>

#include "common.h"
#include "target.h"
#include "target_xen_vm.h"
#include "target_xen_vm_vmp.h"

extern char *optarg;
extern int optind, opterr, optopt;

static int nodaemon = 0;
static GHashTable *clients = NULL;
static int sfd = -1;
char *path = NULL;

#ifdef XENCTRL_HAS_XC_INTERFACE
static xc_interface *xc_handle = NULL;
static xc_interface *xce_handle = NULL;
#define XC_IF_INVALID (NULL)
#else
static int xc_handle = -1;
static int xce_handle = -1;
#define XC_IF_INVALID (-1)
#endif

#if !defined(XC_EVTCHN_PORT_T)
#error "XC_EVTCHN_PORT_T undefined!"
#endif
static XC_EVTCHN_PORT_T dbg_port = -1;

int xce_fd = -1;

void cleanup() {
    GHashTableIter iter;
    gpointer kp,vp;

    if (path && path[0] != '\0') {
	unlink(path);
	path = NULL;
    }
    if (clients) {
	g_hash_table_iter_init(&iter,clients);
	while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	    close((int)(uintptr_t)kp);
	    //free((void *)vp);
	}
	g_hash_table_destroy(clients);
	clients = NULL;
    }
    if (sfd > -1) {
	close(sfd);
	sfd = -1;
    }

    xen_vm_virq_detach(xce_handle,&dbg_port);
    dbg_port = -1;
    xen_vm_xc_detach(&xc_handle,&xce_handle);
    xce_handle = XC_IF_INVALID;
    xc_handle = XC_IF_INVALID;
}

void sigh(int signo) {
    cleanup();
    if (signo == SIGHUP || signo == SIGINT || SIGQUIT)
	exit(0);
    else
	exit(-100);
}

int main(int argc,char **argv) {
    int opt,rc;
    struct stat sbuf;
    struct sockaddr_un sun,sun_client;
    socklen_t clen;
    fd_set rfds,wfds,efds;
    GHashTableIter iter;
    gpointer kp,vp;
    int max_fd,fd;
    struct target_xen_vm_vmp_client_request req;
    struct target_xen_vm_vmp_client_response resp = { 0 };
    int len;
    int port;
    long int flags;

    while ((opt = getopt(argc,argv,"hd::w::l:p:")) > -1) {
	switch (opt) {
	case 'd':
	    nodaemon = 1;
	    if (optarg)
		vmi_set_log_level(atoi(optarg));
	    else
		vmi_inc_log_level();
	    break;
	case 'w':
	    nodaemon = 1;
	    if (optarg)
		vmi_set_warn_level(atoi(optarg));
	    else
		vmi_inc_warn_level();
	    break;
	case 'l':
	    vmi_set_log_area_flaglist(optarg,",");
	    break;
	case 'p':
	    path = optarg;
	    break;
	case 'h':
	case '?':
	default:
	    verror("Usage: %s [-h] [-d [<level>]] [-w [<level>]]"
		   " [-l logflag1,logflag2,...]\n",argv[0]);
	    exit(-1);
	}
    }

    if (!nodaemon) {
	if (daemon(0,0)) {
	    verror("daemon(): %s\n",strerror(errno));
	    exit(-1);
	}
    }

    signal(SIGHUP,sigh);
    signal(SIGINT,sigh);
    signal(SIGQUIT,sigh);
    signal(SIGABRT,sigh);
    signal(SIGSEGV,sigh);
    //signal(SIGPIPE,sigh);

    signal(SIGALRM,SIG_IGN);
    signal(SIGUSR1,SIG_IGN);
    signal(SIGUSR2,SIG_IGN);

    clients = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    if (!path) {
	/*
	 * Just try /var/run or TMPDIR or /tmp or .
	 */
	if (stat("/var/run",&sbuf) == 0 
	    && S_ISDIR(sbuf.st_mode) && access("/var/run",W_OK) == 0)
	    path = "/var/run/" TARGET_XV_VMP_SOCKET_FILENAME;
	else if ((path = getenv("TMPDIR"))
		 && stat(path,&sbuf) == 0 && access(path,W_OK) == 0) {
	    path = malloc(strlen(path) + strlen(TARGET_XV_VMP_SOCKET_FILENAME) + 2);
	    sprintf(path,"%s/%s",path,TARGET_XV_VMP_SOCKET_FILENAME);
	}
	else if (stat("/tmp",&sbuf) == 0 
		 && S_ISDIR(sbuf.st_mode) && access("/tmp",W_OK) == 0)
	    path = "/tmp/" TARGET_XV_VMP_SOCKET_FILENAME;
	else
	    path = "./" TARGET_XV_VMP_SOCKET_FILENAME;
    }

    memset(&sun,0,sizeof(sun));
    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path,UNIX_PATH_MAX,"%s",path);

    sfd = socket(AF_UNIX,SOCK_STREAM,0);
    if (sfd < 0) {
	verror("socket(): %s\n",strerror(errno));
	goto err;
    }
    len = offsetof(struct sockaddr_un,sun_path) + strlen(sun.sun_path);
    if (bind(sfd,&sun,len) < 0) {
	verror("bind(): %s\n",strerror(errno));
	goto err;
    }
    if (fchmod(sfd,S_IRUSR | S_IWUSR) < 0) {
	verror("chmod(%s): %s\n",sun.sun_path,strerror(errno));
	goto err;
    }
    if (listen(sfd,8)) {
	verror("listen(): %s\n",strerror(errno));
	goto err;
    }

    if (xen_vm_xc_attach(&xc_handle,&xce_handle)) {
	verror("could not attach to XC interfaces!\n");
	goto err;
    }

    if (xen_vm_virq_attach(xce_handle,&dbg_port)) {
	verror("could not attach to VIRQ_DEBUGGER evtchn!\n");
	goto err;
    }

    xce_fd = xc_evtchn_fd(xce_handle);

    vdebug(1,LA_TARGET,LF_XV,"Attached to Xen; listening for clients on %s...\n",
	   path);

    /*
     * Main loop.
     */
    while (1) {
	/*
	 * Reset all the FD info for select().
	 */
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&efds);

	max_fd = sfd;
	FD_SET(sfd,&rfds);

	if (xce_fd > max_fd)
	    max_fd = xce_fd;
	FD_SET(xce_fd,&rfds);

	g_hash_table_iter_init(&iter,clients);
	while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	    fd = (int)(uintptr_t)kp;
	    if (fd > max_fd)
		max_fd = fd;
	    FD_SET(fd,&rfds);
	}

        /*
	 * Wait for 
	 */
        rc = select(max_fd + 1,&rfds,&wfds,&efds,NULL);
	if (rc < 0) {
	    if (errno == EINTR)
		continue;
	    else {
		verror("select(): %s, exiting!\n",strerror(errno));
		goto err;
	    }
	}
	else if (rc == 0)
	    continue;

	/*
	 * Check the read/except FDs first; remove any as clients if
	 * they've dropped.
	 */
	g_hash_table_iter_init(&iter,clients);
	while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	    fd = (int)(uintptr_t)kp;
	    if (FD_ISSET(fd,&rfds) || FD_ISSET(fd,&efds)) {
		rc = read(fd,&req,sizeof(req));
		if (rc == 0) {
		    /* Remove this client. */
		    vdebug(1,LA_TARGET,LF_XV,
			   "Removing client %d (closed connection)\n",fd);
		    close(fd);
		    g_hash_table_iter_remove(&iter);
		}
		else if (rc == -1) {
		    if (errno == EINTR)
			continue;
		    else {
			/* Remove! */
			vdebug(1,LA_TARGET,LF_XV,
			       "Removing client %d (read error: %s)\n",
			       fd,strerror(errno));
			close(fd);
			g_hash_table_iter_remove(&iter);
		    }
		}
		else if (rc != sizeof(req)) {
		    /* Remove */
		    vdebug(1,LA_TARGET,LF_XV,
			   "Removing client %d (bad request length: %d)\n",fd,rc);
		    close(fd);
		    g_hash_table_iter_remove(&iter);
		}
		else {
		    ;
		}
	    }
	}

	/*
	 * Check for new clients.
	 */
	if (FD_ISSET(sfd,&rfds)) {
	    clen = sizeof(sun_client);
	    fd = accept(sfd,&sun_client,&clen);
	    if (fd > 0) {
		clen -= offsetof(struct sockaddr_un,sun_path);
		if (clen >= UNIX_PATH_MAX) {
		    vwarn("bad sockaddr_un.sun_path length from accept()!\n");
		    clen = UNIX_PATH_MAX - 1;
		}

		if (clen < offsetof(struct sockaddr_un,sun_path)
		    || clen >= sizeof(sun_client.sun_path)) {
		    vwarn("ignoring new client with unbound unix socket!\n");
		    close(fd);
		}
		else {
		    sun_client.sun_path[clen] = '\0';
		    stat(sun_client.sun_path,&sbuf);
		    vdebug(1,LA_TARGET,LF_XV,
			   "accepting new client %d (pid %d, uid %d, path %s)\n",
			   fd,sbuf.st_rdev,sbuf.st_uid,sun_client.sun_path);
		    g_hash_table_insert(clients,(void *)(uintptr_t)fd,NULL);

		    flags = fcntl(fd,F_GETFL);
		    fcntl(fd,F_SETFL,flags | O_NONBLOCK);
		}
	    }
	    else {
		verror("accept(): %s, ignoring\n",strerror(errno));
	    }
	}

	/*
	 * Check the VIRQ event channel; forward to all for now.
	 *
	 * XXX: later, maybe, do the demultiplexing here and only
	 * forward to clients monitoring the VM in question.
	 */
	if (FD_ISSET(xce_fd,&rfds)) {
	    /* we've got something from eventchn. let's see what it is! */
	    port = xc_evtchn_pending(xce_handle);

	    /* unmask the event channel BEFORE doing anything else */
	    if (xc_evtchn_unmask(xce_handle,port) == -1) {
		vwarn("failed to unmask event channel\n");
	    }

	    if (port != dbg_port)
		continue;

	    g_hash_table_iter_init(&iter,clients);
	    while (g_hash_table_iter_next(&iter,&kp,&vp)) {
		fd = (int)(uintptr_t)kp;
		int tries = 3;
	    again:
		if (tries == 0) {
		    vwarn("Removing client %d (write error: %s)\n",
			  fd,strerror(errno));
		    close(fd);
		    g_hash_table_iter_remove(&iter);
		    continue;
		}

		rc = write(fd,&resp,sizeof(resp));

		if (rc < 0) {
		    if (errno == EINTR) {
			--tries;
			goto again;
		    }
		    else {
			vdebug(1,LA_TARGET,LF_XV,
			       "Removing client %d (write error: %s)\n",
			       fd,strerror(errno));
			close(fd);
			g_hash_table_iter_remove(&iter);
		    }
		}
		else if (rc != sizeof(resp)) {
		    vdebug(1,LA_TARGET,LF_XV,
			   "Removing client %d (incomplete write: %d)\n",
			   fd,rc);
		    close(fd);
		    g_hash_table_iter_remove(&iter);
		}
		else {
		    vdebug(5,LA_TARGET,LF_XV,
			   "Wrote %d bytes to client %d\n",rc,fd);
		}
	    }
	}
    }

 err:
    cleanup();
    exit(-1);
}
