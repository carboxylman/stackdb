/*
 * Copyright (c) 2012, 2013 The University of Utah
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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>
#include <pthread.h>
#include <inttypes.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "log.h"
#include "alist.h"
#include "waitpipe.h"
#include "evloop.h"

#include "monitor.h"

static pthread_mutex_t monitor_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * We don't need monitor IDs yet -- the address of the monitored object
 * suffices! 
 */
static GHashTable *monitor_obj_tab = NULL;
static GHashTable *monitor_thread_tab = NULL;

static int monitor_objtype_idx = 1;
static GHashTable *objtype_tab = NULL;

struct monitor *monitor_lookup(void *obj) {
    struct monitor *m;

    if (!monitor_obj_tab) {
	pthread_mutex_lock(&monitor_mutex);
	monitor_obj_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
	pthread_mutex_unlock(&monitor_mutex);
	return NULL;
    }
    else {
	pthread_mutex_lock(&monitor_mutex);
	m = (struct monitor *)g_hash_table_lookup(monitor_obj_tab,obj);
	pthread_mutex_unlock(&monitor_mutex);
        return m;
    }
}

struct monitor *monitor_lookup_and_lock(void *obj) {
    struct monitor *m;

    if (!monitor_obj_tab) {
	pthread_mutex_lock(&monitor_mutex);
	monitor_obj_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
	pthread_mutex_unlock(&monitor_mutex);
	return NULL;
    }
    else {
	pthread_mutex_lock(&monitor_mutex);
	m = (struct monitor *)g_hash_table_lookup(monitor_obj_tab,obj);
	if (m)
	    pthread_mutex_lock(&m->mutex);
	pthread_mutex_unlock(&monitor_mutex);
        return m;
    }
}

static void monitor_insert(struct monitor *monitor) {
    pthread_mutex_lock(&monitor_mutex);

    if (!monitor_obj_tab) {
	monitor_obj_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
	monitor_thread_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    }

    g_hash_table_insert(monitor_obj_tab,monitor->obj,monitor);
    g_hash_table_insert(monitor_thread_tab,
			(gpointer)(uintptr_t)monitor->mtid,monitor);

    pthread_mutex_unlock(&monitor_mutex);
}

static void monitor_remove(struct monitor *monitor) {
    pthread_mutex_lock(&monitor_mutex);

    if (!monitor_obj_tab) {
	monitor_obj_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
	monitor_thread_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    }

    g_hash_table_remove(monitor_obj_tab,monitor->obj);
    g_hash_table_remove(monitor_thread_tab,(gpointer)(uintptr_t)monitor->mtid);

    pthread_mutex_unlock(&monitor_mutex);
}

int monitor_register_objtype(int objtype,struct monitor_objtype_ops *ops) {
    pthread_mutex_lock(&monitor_mutex);

    if (!objtype_tab) 
	objtype_tab = g_hash_table_new(g_direct_hash,g_direct_equal);

    if (objtype != -1 
	&& g_hash_table_lookup(objtype_tab,(gpointer)(uintptr_t)objtype)) {
	verror("monitor objtype %d already exists!\n",objtype);
	errno = EBUSY;
	pthread_mutex_unlock(&monitor_mutex);
	return -1;
    }

    if (objtype == -1)
	objtype = monitor_objtype_idx++;

    g_hash_table_insert(objtype_tab,(gpointer)(uintptr_t)objtype,ops);

    pthread_mutex_unlock(&monitor_mutex);

    return objtype;
}

int __monitor_recv_evh(int fd,int fdtype,void *state) {
    struct monitor *monitor = (struct monitor *)state;
    struct monitor_msg *msg;

    /* XXX: don't bother checking if @fd == @monitor->monitor_reply_fd */
    msg = monitor_recv(monitor);

    if (msg) {
	vdebug(9,LOG_OTHER,"defhandler: monitor recv %d:%d %d '%s'\n",
	       msg->id,msg->seqno,msg->len,msg->msg);

	if (monitor->objtype_ops && monitor->objtype_ops->recv_msg) 
	    monitor->objtype_ops->recv_msg(monitor,msg);
    }

    if (msg)
	monitor_msg_free(msg);

    return EVLOOP_HRET_SUCCESS;
}

int __monitor_child_recv_evh(int fd,int fdtype,void *state) {
    struct monitor *monitor = (struct monitor *)state;
    struct monitor_msg *msg;

    /* XXX: don't bother checking if @fd == @monitor->monitor_reply_fd */
    msg = monitor_child_recv(monitor);

    if (msg) {
	vdebug(9,LOG_OTHER,"defhandler: recv %d:%d %d '%s'\n",
	       msg->id,msg->seqno,msg->len,msg->msg);

	if (monitor->objtype_ops && monitor->objtype_ops->child_recv_msg) 
	    monitor->objtype_ops->child_recv_msg(monitor,msg);
    }

    if (msg)
	monitor_msg_free(msg);

    return EVLOOP_HRET_SUCCESS;
}

struct monitor *monitor_create_custom(monitor_type_t type,monitor_flags_t flags,
				      int objtype,void *obj) {
    struct monitor *monitor;
    int req_pipe[2] = { -1,-1 };
    int rep_pipe[2] = { -1,-1 };

    if (type != MONITOR_TYPE_THREAD && type != MONITOR_TYPE_PROCESS) {
	verror("unknown monitor type %d\n",type);
	errno = EINVAL;
	return NULL;
    }
    else if (type == MONITOR_TYPE_PROCESS) 
	/*
	 * Need to ensure init waitpipe().  We don't need an extra sighandler.
	 */
	waitpipe_init_default();

    monitor = calloc(1,sizeof(*monitor));

    monitor->type = type;
    monitor->flags = flags;
    monitor->mtid = pthread_self();
    monitor->objtype = objtype;
    monitor->obj = obj;
    if (objtype_tab)
	monitor->objtype_ops = (struct monitor_objtype_ops *) \
	    g_hash_table_lookup(objtype_tab,(gpointer)(uintptr_t)objtype);
    pthread_mutex_init(&monitor->mutex,NULL);

    monitor->msg_obj_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    pthread_mutex_init(&monitor->msg_obj_tab_mutex,NULL);

    // XXX: add a monitor error handler too? :(
    monitor->evloop = evloop_create(NULL);

    if (monitor->objtype_ops && monitor->objtype_ops->evloop_attach) {
	if (monitor->objtype_ops->evloop_attach(monitor->evloop,obj) < 0) {
	    verror("could not attach evloop to obj!\n");
	    goto errout;
	}
    }

    if (pipe(req_pipe)) {
	verror("pipe: %s\n",strerror(errno));
	goto errout;
    }
    monitor->monitor_send_fd = req_pipe[1];
    fcntl(monitor->monitor_send_fd,F_SETFD,FD_CLOEXEC);
    monitor->child_recv_fd = req_pipe[0];

    monitor->p.pid = -1;

    if (flags & MONITOR_FLAG_BIDI) {
	if (pipe(rep_pipe)) {
	    verror("pipe: %s\n",strerror(errno));
	    goto errout;
	}
	monitor->child_send_fd = rep_pipe[1];
	monitor->monitor_recv_fd = rep_pipe[0];
	fcntl(monitor->monitor_recv_fd,F_SETFD,FD_CLOEXEC);
    }
    else {
	monitor->child_send_fd = -1;
	monitor->monitor_recv_fd = -1;
    }
	
    /*
     * Set up @monitor->evloop with our default handler if this is a
     * thread-based monitor, because the client and monitor are in the
     * same thread :).  For processes, we do nothing.
     */
    if (type == MONITOR_TYPE_THREAD && monitor->child_recv_fd > -1) {
	if (monitor->objtype_ops && monitor->objtype_ops->child_recv_evh)
	    evloop_set_fd(monitor->evloop,
			  monitor->child_recv_fd,EVLOOP_FDTYPE_R,
			  monitor->objtype_ops->child_recv_evh,monitor);
	else
	    evloop_set_fd(monitor->evloop,
			  monitor->child_recv_fd,EVLOOP_FDTYPE_R,
			  __monitor_child_recv_evh,monitor);

    }
	
    /*
     * Set up @monitor->evloop with our default handler if this is a
     * bidirectional monitor.
     */
    if (monitor->monitor_recv_fd > -1) {
	if (monitor->objtype_ops && monitor->objtype_ops->recv_evh)
	    evloop_set_fd(monitor->evloop,
			  monitor->monitor_recv_fd,EVLOOP_FDTYPE_R,
			  monitor->objtype_ops->recv_evh,monitor);
	else 
	    evloop_set_fd(monitor->evloop,
			  monitor->monitor_recv_fd,EVLOOP_FDTYPE_R,
			  __monitor_recv_evh,monitor);
    }

    /* These are initialized by calling monitor_setup_io if necessary. */
    monitor->p.stdin_m_fd = -1;
    monitor->p.stdin_c_fd = -1;
    monitor->p.stdout_m_fd = -1;
    monitor->p.stdout_c_fd = -1;
    monitor->p.stdout_log_fd = -1;
    monitor->p.stderr_m_fd = -1;
    monitor->p.stderr_c_fd = -1;
    monitor->p.stderr_log_fd = -1;

    monitor_insert(monitor);

    return monitor;

 errout:
    if (monitor->msg_obj_tab)
	g_hash_table_destroy(monitor->msg_obj_tab);
    if (monitor->evloop)
	evloop_free(monitor->evloop);
    if (req_pipe[0] > -1)
	close(req_pipe[0]);
    if (req_pipe[1] > -1)
	close(req_pipe[1]);
    if (rep_pipe[0] > -1)
	close(rep_pipe[0]);
    if (rep_pipe[1] > -1)
	close(rep_pipe[1]);
    free(monitor);

    return NULL;
}

struct monitor *monitor_create(monitor_type_t type,monitor_flags_t flags,
			       int objtype,void *obj) {
    struct monitor *monitor;

    if (!g_hash_table_lookup(objtype_tab,(gpointer)(uintptr_t)objtype)) {
	verror("unknown monitored object type %d\n",objtype);
	errno = EINVAL;
	return NULL;
    }

    monitor = monitor_create_custom(type,flags,objtype,obj);
    if (!monitor)
	return NULL;

    return monitor;
}

int monitor_can_attach(void) {
    if (getenv(MONITOR_CHILD_RECV_FD_ENVVAR))
	return 1;
    return 0;
}

int monitor_can_attach_bidi(void) {
    if (getenv(MONITOR_CHILD_RECV_FD_ENVVAR)
	&& getenv(MONITOR_CHILD_SEND_FD_ENVVAR))
	return 1;
    return 0;
}

struct monitor *monitor_attach(monitor_type_t type,monitor_flags_t flags,
			       int objtype,void *obj) {
    struct monitor *monitor;

    if (type != MONITOR_TYPE_PROCESS) {
	verror("can only attach to process-based monitors! (%d)\n",type);
	errno = EINVAL;
	return NULL;
    }

    if (!g_hash_table_lookup(objtype_tab,(gpointer)(uintptr_t)objtype)) {
	verror("unknown monitored object type %d\n",objtype);
	errno = EINVAL;
	return NULL;
    }

    /*
     * We could check the env vars, and fail if we can't get them, but
     * we don't in this case.  We want to allow "headless" monitor
     * childs through.
     */

    monitor = calloc(1,sizeof(*monitor));

    monitor->type = type;
    monitor->flags = flags;
    monitor->mtid = pthread_self();
    monitor->objtype = objtype;
    monitor->obj = obj;
    if (objtype_tab)
	monitor->objtype_ops = (struct monitor_objtype_ops *) \
	    g_hash_table_lookup(objtype_tab,(gpointer)(uintptr_t)objtype);
    pthread_mutex_init(&monitor->mutex,NULL);

    monitor->msg_obj_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    pthread_mutex_init(&monitor->msg_obj_tab_mutex,NULL);

    if (getenv(MONITOR_CHILD_RECV_FD_ENVVAR)) {
	monitor->child_recv_fd = atoi(getenv(MONITOR_CHILD_RECV_FD_ENVVAR));
	/* Don't want any children to inherit this... */
	fcntl(monitor->child_recv_fd,F_SETFD,FD_CLOEXEC);
    }
    else
	monitor->child_recv_fd = -1;

    if (flags & MONITOR_FLAG_BIDI && getenv(MONITOR_CHILD_SEND_FD_ENVVAR)) {
	monitor->child_send_fd = atoi(getenv(MONITOR_CHILD_SEND_FD_ENVVAR));
	/* Don't want any children to inherit this... */
	fcntl(monitor->child_send_fd,F_SETFD,FD_CLOEXEC);
    }
    else
	monitor->child_send_fd = -1;

    monitor->evloop = evloop_create(NULL);

    /* Only process-based monitor children can call this, so we do not
     * listen on anything else.
     */
    if (monitor->child_recv_fd > -1) {
	if (monitor->objtype_ops && monitor->objtype_ops->child_recv_evh)
	    evloop_set_fd(monitor->evloop,
			  monitor->child_recv_fd,EVLOOP_FDTYPE_R,
			  monitor->objtype_ops->child_recv_evh,monitor);
	else
	    evloop_set_fd(monitor->evloop,
			  monitor->child_recv_fd,EVLOOP_FDTYPE_R,
			  __monitor_child_recv_evh,monitor);
    }

    monitor->p.stdin_m_fd = -1;
    monitor->p.stdin_c_fd = -1;
    monitor->p.stdout_m_fd = -1;
    monitor->p.stdout_c_fd = -1;
    monitor->p.stdout_log_fd = -1;
    monitor->p.stderr_m_fd = -1;
    monitor->p.stderr_c_fd = -1;
    monitor->p.stderr_log_fd = -1;

    monitor_insert(monitor);

    return monitor;
}

int __monitor_send_stdin_evh(int fd,int fdtype,void *state) {
    struct monitor *monitor = (struct monitor *)state;
    int retval;

    if (monitor->p.stdin_left <= 0) {
	vwarn("called again even with no input remaining!\n");
	return EVLOOP_HRET_REMOVEALLTYPES;
    }

 again:
    retval = write(monitor->p.stdin_m_fd,
		   monitor->p.stdin_buf + \
		       (monitor->p.stdin_bufsiz - monitor->p.stdin_left),
		   monitor->p.stdin_left);
    if (retval < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK) 
	    return EVLOOP_HRET_SUCCESS;
	else if (errno == EINTR) 
	    goto again;
	else if (errno == EPIPE) {
	    vwarn("child closed read stdin unexpectedly?\n");
	    /* XXX: do something more informative? */
	    return EVLOOP_HRET_BADERROR;
	}
	else {
	    verror("error(wrote %d of %d bytes stdin): write: %s\n",
		   monitor->p.stdin_bufsiz - monitor->p.stdin_left,
		   monitor->p.stdin_bufsiz,strerror(errno));
	    return EVLOOP_HRET_REMOVEALLTYPES;
	}
    }
    else {
	monitor->p.stdin_left -= retval;
	vdebug(8,LOG_OTHER,"wrote %d of %d bytes stdin\n",
	       monitor->p.stdin_bufsiz - monitor->p.stdin_left,
	       monitor->p.stdin_bufsiz);

	if (monitor->p.stdin_left <= 0) {
	    vdebug(8,LOG_OTHER,"finished writing %d bytes stdin\n",
		   monitor->p.stdin_bufsiz);

	    monitor->p.stdin_left = monitor->p.stdin_bufsiz = -1;

	    free(monitor->p.stdin_buf);
	    monitor->p.stdin_buf = NULL;
	    close(monitor->p.stdin_m_fd);
	    monitor->p.stdin_m_fd = -1;

	    return EVLOOP_HRET_REMOVEALLTYPES;
	}
    }

    return EVLOOP_HRET_SUCCESS;
}

int monitor_setup_stdin(struct monitor *monitor,
			char *stdin_buf,int stdin_buflen) {
    int pipefds[2] = { -1,-1 };

    if (monitor->type != MONITOR_TYPE_PROCESS) {
	errno = EINVAL;
	verror("invalid monitor type %d\n",monitor->type);
	return -1;
    }

    if (pipe(pipefds)) {
	verror("pipe: %s\n",strerror(errno));
	return -1;
    }
    monitor->p.stdin_m_fd = pipefds[1];
    fcntl(monitor->p.stdin_m_fd,F_SETFD,FD_CLOEXEC);
    /*
     * Also open this one nonblocking because we don't want the monitor
     * thread to block while sending input to the child.
     */
    fcntl(pipefds[1],F_SETFL,fcntl(pipefds[1],F_GETFL) | O_NONBLOCK);
    monitor->p.stdin_c_fd = pipefds[0];

    monitor->p.stdin_buf = stdin_buf;
    monitor->p.stdin_left = stdin_buflen;
    monitor->p.stdin_bufsiz = stdin_buflen;

    /* Make sure to send our stdin to the child. */
    evloop_set_fd(monitor->evloop,monitor->p.stdin_m_fd,EVLOOP_FDTYPE_W,
		  __monitor_send_stdin_evh,monitor);

    return 0;
}

int monitor_setup_stdout(struct monitor *monitor,
			 int maxbufsiz,char *stdout_logfile,
			 int (*stdout_callback)(int fd,char *buf,int len)) {
    int pipefds[2] = { -1,-1 };

    if (monitor->type != MONITOR_TYPE_PROCESS) {
	errno = EINVAL;
	verror("invalid monitor type %d\n",monitor->type);
	return -1;
    }

    if (stdout_logfile) {
	monitor->p.stdout_log_fd = \
	    open(stdout_logfile,O_WRONLY | O_CREAT | O_APPEND,
		 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (monitor->p.stdout_log_fd < 0) {
	    verror("could not open stdout logfile %s!\n",stdout_logfile);
	    return -1;
	}
    }

    if (pipe(pipefds)) {
	verror("pipe: %s\n",strerror(errno));
	if (monitor->p.stdout_log_fd != -1)
	    close(monitor->p.stdout_log_fd);
	return -1;
    }
    monitor->p.stdout_c_fd = pipefds[1];
    monitor->p.stdout_m_fd = pipefds[0];
    fcntl(monitor->p.stdout_m_fd,F_SETFD,FD_CLOEXEC);
    /*
     * Also open this one nonblocking because we don't want the monitor
     * thread to block while reading output from the child.
     */
    fcntl(monitor->p.stdout_m_fd,F_SETFL,
	  fcntl(monitor->p.stdout_m_fd,F_GETFL) | O_NONBLOCK);

    /*
    if (maxbufsiz > 0) 
	monitor->p.stdout_buf = cbuf_alloc(maxbufsiz,-1);
    */

    monitor->p.stdout_callback = stdout_callback;

    return 0;
}

int monitor_setup_stderr(struct monitor *monitor,
			 int maxbufsiz,char *stderr_logfile,
			 int (*stderr_callback)(int fd,char *buf,int len)) {
    int pipefds[2] = { -1,-1 };

    if (monitor->type != MONITOR_TYPE_PROCESS) {
	errno = EINVAL;
	verror("invalid monitor type %d\n",monitor->type);
	return -1;
    }

    if (stderr_logfile) {
	monitor->p.stderr_log_fd = \
	    open(stderr_logfile,O_WRONLY | O_CREAT | O_APPEND,
		 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (monitor->p.stderr_log_fd < 0) {
	    verror("could not open stderr logfile %s!\n",stderr_logfile);
	    return -1;
	}
    }

    if (pipe(pipefds)) {
	verror("pipe: %s\n",strerror(errno));
	if (monitor->p.stderr_log_fd != -1)
	    close(monitor->p.stderr_log_fd);
	return -1;
    }
    monitor->p.stderr_c_fd = pipefds[1];
    monitor->p.stderr_m_fd = pipefds[0];
    fcntl(monitor->p.stderr_m_fd,F_SETFD,FD_CLOEXEC);
    /*
     * Also open this one nonblocking because we don't want the monitor
     * thread to block while reading output from the child.
     */
    fcntl(monitor->p.stderr_m_fd,F_SETFL,
	  fcntl(monitor->p.stderr_m_fd,F_GETFL) | O_NONBLOCK);

    /*
    if (maxbufsiz > 0) 
	monitor->p.stderr_buf = cbuf_alloc(maxbufsiz,-1);
    */

    monitor->p.stderr_callback = stderr_callback;

    return 0;
}

static int __monitor_pid_evh(int fd,int fdtype,void *state) {
    struct monitor *monitor = (struct monitor *)state;
    int pid = monitor->p.pid;
    int status;

    /* The waitpipe tells us that the pid died; wait for it and save its
     * status.
     */

    vdebug(9,LOG_OTHER,"pid %d finished\n",pid);
    waitpid(pid,&status,0);
    vdebug(9,LOG_OTHER,"pid %d finished status %d\n",pid,WEXITSTATUS(status));

    /* nuke the pipe */
    waitpipe_remove(pid);

    /* save status */
    monitor->p.status = status;

    /* remove ALL the fds from the event loop */
    return EVLOOP_HRET_DONE_SUCCESS;
}

int __safe_write(int fd,char *buf,int count) {
    int rc = 0;
    int retval;

    while (rc < count) {
        retval = write(fd,buf + rc,count - rc);
	if (retval < 0) {
	    if (errno == EINTR)
		continue;
	    else if (errno == EAGAIN || errno == EWOULDBLOCK) {
		return rc;
	    }
	    else {
	        verror("read(%d): %s\n",fd,strerror(errno));
		return retval;
	    }
	}
	else 
	    rc += retval;
    }

    return rc;
}

static int __monitor_stdio_evh(int fd,int fdtype,void *state) {
    struct monitor *monitor = (struct monitor *)state;
    int logfd;
    int (*callback)(int fd,char *buf,int len);
    char buf[64];
    int rc = 0;
    int retval;

    if (fd == monitor->p.stdout_m_fd) {
	logfd = monitor->p.stdout_log_fd;
	callback = monitor->p.stdout_callback;
    }
    else if (fd == monitor->p.stderr_m_fd) {
	logfd = monitor->p.stderr_log_fd;
	callback = monitor->p.stderr_callback;
    }
    else {
	vwarn("unknown stdio fd %d!\n",fd);
	return EVLOOP_HRET_SUCCESS;
    }

    while (rc < (int)sizeof(buf)) {
        retval = read(fd,buf + rc,sizeof(buf) - rc);
	if (retval < 0) {
	    if (errno == EINTR)
		continue;
	    else if (errno == EAGAIN || errno == EWOULDBLOCK) {
		/* Stop here; fire callback if we need */
		if (callback && rc) 
		    callback(fd,buf,rc);
		__safe_write(logfd,buf,rc);
		return EVLOOP_HRET_SUCCESS;
	    }
	    else {
	        verror("read(%d): %s\n",logfd,strerror(errno));
		return EVLOOP_HRET_BADERROR;
	    }
	}
	else if (retval == 0) {
	    if (rc && callback)
		callback(fd,buf,rc);
	    __safe_write(logfd,buf,rc);
	    return EVLOOP_HRET_SUCCESS;
	}
	else {
	    rc += retval;
	    if (retval == sizeof(buf)) {
		if (callback)
		    callback(fd,buf,rc);
		__safe_write(logfd,buf,rc);
		rc = 0;
	    }
	}
    }


    return EVLOOP_HRET_SUCCESS;
}

extern char **environ;

int monitor_spawn(struct monitor *monitor,char *filename,
		  char *const argv[],char *const envp[],char *dir) {
    int pid;
    char envvarbuf[64];
    int fd;
    int envlen;
    char **envp_actual;
    char cwd[PATH_MAX];
    int i;

    if (monitor->type != MONITOR_TYPE_PROCESS) {
	verror("cannot handle a non-MONITOR_TYPE_PROCESS!\n");
	errno = EINVAL;
	return -1;
    }

    if (dir) {
	if (!getcwd(cwd,PATH_MAX)) {
	    verror("getcwd: %s\n",strerror(errno));
	    return -1;
	}
	if (chdir(dir)) {
	    verror("chdir(%s): %s!\n",dir,strerror(errno));
	    return -1;
	}
    }

    pid = fork();

    if (pid < 0) {
	verror("fork: %s\n",strerror(errno));
	return pid;
    }
    else if (!pid) {
	/* Setup env vars.  If they are not passing in a new env, we
	 * can just use putenv() with the old one in the child.
	 * Otherwise, we have to manually extend the env they passed.
	 */
	if (!envp) {
	    /* Tell the child it is monitored, and tell it its FDs. */
	    if (monitor->child_recv_fd > -1) {
		snprintf(envvarbuf,sizeof(envvarbuf),"%s=%d",
			 MONITOR_CHILD_RECV_FD_ENVVAR,monitor->child_recv_fd);
		putenv(envvarbuf);
	    }
	    if (monitor->child_send_fd > -1) {
		snprintf(envvarbuf,sizeof(envvarbuf),"%s=%d",
			 MONITOR_CHILD_SEND_FD_ENVVAR,monitor->child_send_fd);
		putenv(envvarbuf);
	    }

	    envp_actual = environ;
	}
	else {
	    envlen = 0;
	    i = 0;
	    while (envp[i]) 
		++envlen;

	    envp_actual = calloc(envlen + 3,sizeof(char *));

	    i = 0;
	    while (i < envlen) {
		envp_actual[i] = envp[i];
		++i;
	    }

	    /* Tell the child it is monitored, and tell it its FDs. */
	    if (monitor->child_recv_fd > -1) {
		snprintf(envvarbuf,sizeof(envvarbuf),"%s=%d",
			 MONITOR_CHILD_RECV_FD_ENVVAR,monitor->child_recv_fd);
		envp_actual[i] = strdup(envvarbuf);
		++i;
		envp_actual[i] = NULL;
	    }
	    if (monitor->child_send_fd > -1) {
		snprintf(envvarbuf,sizeof(envvarbuf),"%s=%d",
			 MONITOR_CHILD_SEND_FD_ENVVAR,monitor->child_send_fd);
		envp_actual[i] = strdup(envvarbuf);
		++i;
		envp_actual[i] = NULL;
	    }
	}

	/*
	 * Setup stdio streams.
	 */
	if (monitor->p.stdin_c_fd > -1) {
	    if (dup2(monitor->p.stdin_c_fd,STDIN_FILENO)) {
		verror("dup2(%d,stdin): %s; closing stdin!\n",
		       monitor->p.stdin_c_fd,strerror(errno));
		close(STDIN_FILENO);
	    }
	}

	if (monitor->p.stdout_c_fd > -1) {
	    if (dup2(monitor->p.stdout_c_fd,STDOUT_FILENO) < 0) {
		verror("dup2(%d,stdout): %s; ignoring!\n",
		       monitor->p.stdout_c_fd,strerror(errno));
	    }
	}

	if (monitor->p.stderr_c_fd > -1) {
	    if (dup2(monitor->p.stderr_c_fd,STDERR_FILENO) < 0) {
		verror("dup2(%d,stderr): %s; ignoring!\n",
		       monitor->p.stderr_c_fd,strerror(errno));
	    }
	}

	/*
	 * XXX: cleanup any monitor-only state!
	 */

	if (execve(filename,argv,envp_actual)) {
	    verror("execve(%s): %s!\n",filename,strerror(errno));
	    return -1;
	}
    }
    else {
	monitor->p.pid = pid;

	/* Change dir back if we need. */
	if (dir && chdir(cwd)) {
	    verror("chdir(%s): %s!\n",cwd,strerror(errno));
	    // XXX: do not exit; this should not happen; trust it won't.
	}

	/*
	 * Add our default handler for stderr/stdout if necessary.
	 */
	if (monitor->p.stdout_m_fd > -1) {
	    evloop_set_fd(monitor->evloop,monitor->p.stdout_m_fd,
			  EVLOOP_FDTYPE_R,__monitor_stdio_evh,monitor);
	}

	/*
	 * Add a waitpipe handler for the child.
	 */
	fd = waitpipe_add(pid);
	evloop_set_fd(monitor->evloop,fd,EVLOOP_FDTYPE_R,
		      __monitor_pid_evh,monitor);

	/*
	 * Close child ends of pipes.
	 */
	if (monitor->child_recv_fd > -1) {
	    close(monitor->child_recv_fd);
	    monitor->child_recv_fd = -1;
	}
	if (monitor->child_send_fd > -1) {
	    close(monitor->child_send_fd);
	    monitor->child_send_fd = -1;
	}
	if (monitor->p.stdin_c_fd > -1) {
	    close(monitor->p.stdin_c_fd);
	    monitor->p.stdin_c_fd = -1;
	}
	if (monitor->p.stdout_c_fd > -1) {
	    close(monitor->p.stdout_c_fd);
	    monitor->p.stdout_c_fd = -1;
	}
	if (monitor->p.stderr_c_fd > -1) {
	    close(monitor->p.stderr_c_fd);
	    monitor->p.stderr_c_fd = -1;
	}
    }

    return pid;
}

static int __monitor_error_evh(int errortype,int fd,int fdtype,
			       struct evloop_fdinfo *error_fdinfo) {
    /*
     * Basically, we have to check all our FDs, see which one the error
     * happened for, then decide what to do!
     */
    vdebug(5,LOG_OTHER,"errortype %d fd %d fdtype %d\n",
	   errortype,fd,fdtype);

    return EVLOOP_HRET_SUCCESS;
}

/*
 * Runs the monitor (basically just runs its internal evloop).
 */
int monitor_run(struct monitor *monitor) {
    struct evloop_fdinfo *error_fdinfo = NULL;
    int rc;

    while (1) {
	rc = evloop_run(monitor->evloop,NULL,&error_fdinfo);
	if (rc < 0) {
	    /*
	     * XXX: Fatal error -- handle I/O errors of our own, and
	     * call the fatal handler for the objtype; then free
	     * ourself.
	     */
	    verror("fatal error, cleaning up!\n");
	    if (monitor->objtype_ops && monitor->objtype_ops->fatal_error)
		monitor->objtype_ops->fatal_error(MONITOR_ERROR_UNKNOWN,
						  monitor->obj);
	    monitor_free(monitor);

	    return -1;
	}
	else {
	    return 0;
	}
    }

    /* Never reached. */
    return -1;
}

void monitor_cleanup(struct monitor *monitor) {
    if (!pthread_equal(pthread_self(),monitor->mtid)) {
	verror("only monitor thread can clean itself!\n");
	errno = EPERM;
	return;
    }

    pthread_mutex_lock(&monitor->mutex);

    if (monitor->monitor_send_fd > -1) {
	close(monitor->monitor_send_fd);
	monitor->monitor_send_fd = -1;
    }
    if (monitor->child_recv_fd > -1) {
	if (monitor->flags & MONITOR_FLAG_BIDI) {
	    /* This should have been closed when we forked the child... */
	    vwarn("BUG: child_recv_fd still live!\n");
	}
	close(monitor->child_recv_fd);
	monitor->child_recv_fd = -1;
    }

    if (monitor->flags & MONITOR_FLAG_BIDI) {
	if (monitor->child_send_fd > -1) {
	    /* This should have been closed when we forked the child... */
	    vwarn("BUG: child_send_fd still live!\n");
	    close(monitor->child_send_fd);
	    monitor->child_send_fd = -1;
	}
	if (monitor->monitor_recv_fd > -1)  {
	    close(monitor->monitor_recv_fd);
	    monitor->monitor_recv_fd = -1;
	}
    }

    if (monitor->type == MONITOR_TYPE_PROCESS) {
	if (monitor->p.stdin_buf) {
	    free(monitor->p.stdin_buf);
	    monitor->p.stdin_buf = NULL;
	}

	if (monitor->p.stdin_m_fd > -1) {
	    close(monitor->p.stdin_m_fd);
	    monitor->p.stdin_m_fd = -1;
	}
	if (monitor->p.stdin_c_fd > -1) {
	    /* This should have been closed when we forked the child... */
	    vwarn("BUG: p.stdin_c_fd still live!\n");
	    close(monitor->p.stdin_c_fd);
	    monitor->p.stdin_c_fd = -1;
	}

	if (monitor->p.stdout_m_fd > -1) {
	    close(monitor->p.stdout_m_fd);
	    monitor->p.stdout_m_fd = -1;
	}
	if (monitor->p.stdout_c_fd > -1) {
	    /* This should have been closed when we forked the child... */
	    vwarn("BUG: p.stdout_c_fd still live!\n");
	    close(monitor->p.stdout_c_fd);
	    monitor->p.stdout_c_fd = -1;
	}
	if (monitor->p.stdout_log_fd > -1) {
	    close(monitor->p.stdout_log_fd);
	    monitor->p.stdout_log_fd = -1;
	}

	if (monitor->p.stderr_m_fd > -1) {
	    close(monitor->p.stderr_m_fd);
	    monitor->p.stderr_m_fd = -1;
	}
	if (monitor->p.stderr_c_fd > -1) {
	    /* This should have been closed when we forked the child... */
	    vwarn("BUG: p.stderr_c_fd still live!\n");
	    close(monitor->p.stderr_c_fd);
	    monitor->p.stderr_c_fd = -1;
	}
	if (monitor->p.stderr_log_fd > -1) {
	    close(monitor->p.stderr_log_fd);
	    monitor->p.stderr_log_fd = -1;
	}
    }

    pthread_mutex_unlock(&monitor->mutex);

    return;
}

/*
 * Who calls this??  The incoming request that Finish()s a target or
 * analysis?  Yes, probably.  Wait, no -- th
 */
void monitor_free(struct monitor *monitor) {
    if (!pthread_equal(pthread_self(),monitor->mtid)) {
	verror("only monitor thread can free itself!\n");
	errno = EPERM;
	return;
    }

    monitor_cleanup(monitor);

    if (monitor->objtype_ops && monitor->objtype_ops->evloop_detach) {
	if (monitor->objtype_ops->evloop_detach(monitor->evloop,
						monitor->obj) < 0) {
	    vwarn("could not detach evloop from obj!\n");
	}
    }

    monitor_remove(monitor);

    g_hash_table_destroy(monitor->msg_obj_tab);

    evloop_free(monitor->evloop);

    if (monitor->type == MONITOR_TYPE_PROCESS) {
	/*
	if (monitor->p.stdout_cbuf)
	    free(monitor->p.stdout_cbuf);
	*/

	/*
	if (monitor->p.stderr_cbuf)
	    cbuf_free(monitor->p.stderr_cbuf);
	*/
    }

    /* XXX: free results! */
    if (monitor->results) {
	/* XXX: deep free! */
	array_list_free(monitor->results);
    }

    /*
     * This is the last stuff the monitor thread should run before it
     * exits/returns!
     */
    if (monitor->type == MONITOR_TYPE_THREAD) {
	free(monitor);
    }
    else {
	free(monitor);
    }

    return;
}

void monitor_msg_free(struct monitor_msg *msg) {
    if (msg->msg)
	free(msg->msg);
    free(msg);
}

struct monitor_msg *monitor_msg_create(int id,int seqno,int buflen,char *buf) {
    struct monitor_msg *msg = calloc(1,sizeof(*msg));

    msg->id = id;
    msg->seqno = seqno;
    msg->len = buflen;
    msg->msg = buf;

    return msg;
}

void *monitor_get_msg_obj(struct monitor *monitor,int msg_id) {
    void *retval;

    pthread_mutex_lock(&monitor->msg_obj_tab_mutex);
    retval = (void *)g_hash_table_lookup(monitor->msg_obj_tab,
					 (gpointer)(uintptr_t)msg_id);
    pthread_mutex_unlock(&monitor->msg_obj_tab_mutex);

    return retval;
}

void monitor_del_msg_obj(struct monitor *monitor,int msg_id) {
    pthread_mutex_lock(&monitor->msg_obj_tab_mutex);
    g_hash_table_remove(monitor->msg_obj_tab,(gpointer)(uintptr_t)msg_id);
    pthread_mutex_unlock(&monitor->msg_obj_tab_mutex);
}

#define __M_SAFE_IO(fn,fns,fd,buf,buflen) {				\
    char *_p;								\
    int _rc = 0;							\
    int _left;								\
									\
    _p = (char *)(buf);							\
    _left = (buflen);							\
									\
    while (_rc < _left) {						\
        _rc = fn((fd),_p,_left);					\
	if (_rc < 0) {							\
	    if (errno == EAGAIN || errno == EWOULDBLOCK) {		\
		goto errout_wouldblock;					\
	    }								\
	    else if (errno != EINTR) {					\
	        verror(fns "(%d,%d): %s\n",				\
		       fd,buflen,strerror(errno));			\
		goto errout_fatal;					\
	    }								\
	    else {							\
	        verror(fns "(%d,%d): %s\n",				\
		       fd,buflen,strerror(errno));			\
	    }								\
	}								\
	else if (_rc == 0) {						\
	    goto errout_wouldblock;					\
	}								\
	else {								\
	    _left -= _rc;						\
	    _p += _rc;							\
	}								\
    }									\
}

int monitor_sendfor(void *obj,struct monitor_msg *msg,void *msg_obj) {
    struct monitor *monitor;
    int rc = 0;
    int len;

    /*
     * We have to lookup the monitor and hold its lock to make sure
     * the monitor thread does not monitor_free() it out from under us!
     */
    monitor = monitor_lookup_and_lock(obj);
    if (!monitor) {
	errno = ESRCH;
	return -1;
    }

    /*
     * Insert the object and release the lock first so receiver does not
     * block on it if it reads the msg before the sender releases the
     * lock.
     */
    pthread_mutex_lock(&monitor->msg_obj_tab_mutex);
    g_hash_table_insert(monitor->msg_obj_tab,(gpointer)(uintptr_t)msg->id,
			msg_obj);
    pthread_mutex_unlock(&monitor->msg_obj_tab_mutex);

    len = (int)sizeof(msg->id) + (int)sizeof(msg->seqno) + (int)sizeof(msg->len);
    if (msg->len > 0)
	len += msg->len;

    /*
     * Now send the message.
     */
    if (monitor->monitor_send_fd < 1) {
	if (monitor->type == MONITOR_TYPE_THREAD) {
	    verror("no way to send to thread %lu!\n",monitor->mtid);
	}
	else if (monitor->type == MONITOR_TYPE_PROCESS) {
	    verror("no way to send to process %d!\n",monitor->p.pid);
	}
	errno = EINVAL;
	goto errout;
    }

    /* Write the msg id */
    __M_SAFE_IO(write,"write",monitor->monitor_send_fd,
		&msg->id,(int)sizeof(msg->id));
    rc += (int)sizeof(msg->id);

    /* Write the msg seqno */
    __M_SAFE_IO(write,"write",monitor->monitor_send_fd,
		&msg->seqno,(int)sizeof(msg->seqno));
    rc += (int)sizeof(msg->seqno);

    /* Write the msg payload len */
    __M_SAFE_IO(write,"write",monitor->monitor_send_fd,
		&msg->len,(int)sizeof(msg->len));
    rc += (int)sizeof(msg->len);

    if (msg->len > 0) {
	/* Write the msg payload, if any */
	__M_SAFE_IO(write,"write",monitor->monitor_send_fd,msg->msg,msg->len);
	rc += msg->len;
    }

    pthread_mutex_unlock(&monitor->mutex);
    return 0;

 errout_wouldblock:
    if (rc < len && (errno == EAGAIN || errno == EWOULDBLOCK)) {
	verror("would have blocked after %d of %d bytes!\n",rc,len);
	goto errout;
    }

 errout_fatal:
    /*
     * Error while writing to pipe; may be in bad state; must nuke the
     * pipe.  We can leave the monitor open, but all communication ends
     * here.
     *
     * Actually, we can't nuke the pipe, because the caller may not be
     * the thread monitoring the monitor's evloop -- so we cannot alter
     * the evloop.
     *
     * The only thing we *can* do is close() the pipe FD; do that for
     * now and let the evloop handle that normally (it should see an
     * error condition too, if it's a real problem?).
     */
    if (errno == EPIPE) {
	close(monitor->monitor_send_fd);
	monitor->monitor_send_fd = -1;
    }

 errout:
    pthread_mutex_unlock(&monitor->mutex);
    pthread_mutex_lock(&monitor->msg_obj_tab_mutex);
    if (msg_obj)
	g_hash_table_remove(monitor->msg_obj_tab,(gpointer)(uintptr_t)msg->id);
    pthread_mutex_unlock(&monitor->msg_obj_tab_mutex);
    return -1;
}

struct monitor_msg *monitor_recv(struct monitor *monitor) {
    struct monitor_msg *msg = monitor_msg_create(0,0,0,NULL);
    int rc = 0;
    int len;

    len = (int)sizeof(msg->id) + (int)sizeof(msg->seqno) + (int)sizeof(msg->len);

    /* Read the msg id */
    __M_SAFE_IO(read,"read",monitor->monitor_recv_fd,
		&msg->id,(int)sizeof(msg->id));
    rc += (int)sizeof(msg->id);

    /* Read the msg seqno */
    __M_SAFE_IO(read,"read",monitor->monitor_recv_fd,&msg->seqno,
		(int)sizeof(msg->seqno));
    rc += (int)sizeof(msg->seqno);

    /* Read the msg payload len */
    __M_SAFE_IO(read,"read",monitor->monitor_recv_fd,
		&msg->len,(int)sizeof(msg->len));
    rc += (int)sizeof(msg->len);

    if (msg->len > 0)
	len += msg->len;

    /* Read the msg payload */
    if (msg->len > 0) {
	msg->msg = malloc(msg->len);
	__M_SAFE_IO(read,"read",monitor->monitor_recv_fd,
		    msg->msg,(int)sizeof(msg->len));
	rc += msg->len;
    }

    return msg;

 errout_wouldblock:
    if (rc < len && (errno == EAGAIN || errno == EWOULDBLOCK)) {
	verror("would have blocked after %d of (at least) %d bytes !\n",rc,len);
	goto errout_fatal;
    }

 errout_fatal:
    monitor_msg_free(msg);

    return NULL;
}

int monitor_child_sendfor(void *obj,struct monitor_msg *msg,void *msg_obj) {
    struct monitor *monitor;
    int rc = 0;
    int len;

    /*
     * We have to lookup the monitor and hold its lock to make sure
     * the monitor thread does not monitor_free() it out from under us!
     */
    monitor = monitor_lookup_and_lock(obj);
    if (!monitor) {
	errno = ESRCH;
	return -1;
    }

    len = (int)sizeof(msg->id) + (int)sizeof(msg->seqno) + (int)sizeof(msg->len);
    if (msg->len > 0)
	len += msg->len;

    /*
     * If this is a process-based monitor, we allow multiple threads in
     * the child!  So we have to lock to ensure our sends are
     * synchronous.
     *
     * Insert the object and release the lock first so receiver does not
     * block on it if it reads the msg before the sender releases the
     * lock.
     */
    if (monitor->type == MONITOR_TYPE_PROCESS) {
	pthread_mutex_lock(&monitor->msg_obj_tab_mutex);
	g_hash_table_insert(monitor->msg_obj_tab,
			    (gpointer)(uintptr_t)msg->id,msg_obj);
	pthread_mutex_unlock(&monitor->msg_obj_tab_mutex);
    }

    /*
     * Now send the message.  No locking FOR THREADS because only one caller.
     */
    if (monitor->child_send_fd < 1) {
	if (monitor->type == MONITOR_TYPE_THREAD) {
	    verror("no way to send from monitor thread!\n");
	}
	else if (monitor->type == MONITOR_TYPE_PROCESS) {
	    verror("no way to send from monitored process!\n");
	}
	errno = EINVAL;
	goto errout;
    }

    /* Write the msg id */
    __M_SAFE_IO(write,"write",monitor->child_send_fd,
		&msg->id,(int)sizeof(msg->id));
    rc += (int)sizeof(msg->id);

    /* Write the msg seqno */
    __M_SAFE_IO(write,"write",monitor->child_send_fd,
		&msg->seqno,(int)sizeof(msg->seqno));
    rc += (int)sizeof(msg->seqno);

    /* Write the msg payload len */
    __M_SAFE_IO(write,"write",monitor->child_send_fd,
		&msg->len,(int)sizeof(msg->len));
    rc += (int)sizeof(msg->len);

    if (msg->len > 0) {
	/* Write the msg payload, if any */
	__M_SAFE_IO(write,"write",monitor->child_send_fd,msg->msg,msg->len);
	rc += msg->len;
    }

    pthread_mutex_unlock(&monitor->mutex);
    return 0;

 errout_wouldblock:
    if (rc < len && (errno == EAGAIN || errno == EWOULDBLOCK)) {
	verror("would have blocked after %d of %d bytes!\n",rc,len);
	goto errout;
    }

 errout_fatal:
    /*
     * Error while writing to pipe; may be in bad state; must nuke the
     * pipe.  We can leave the monitor open, but all communication ends
     * here.
     *
     * Actually, we can't nuke the pipe, because the caller may not be
     * the thread monitoring the monitor's evloop -- so we cannot alter
     * the evloop.  The only thing we *could* do is close() the pipe
     * FDs, but for now let's not, and let's let the evloop handle that
     * normally (it should see an error condition too, if it's a real
     * problem?).
     */

 errout:
    pthread_mutex_unlock(&monitor->mutex);
    pthread_mutex_lock(&monitor->msg_obj_tab_mutex);
    if (msg_obj)
	g_hash_table_remove(monitor->msg_obj_tab,(gpointer)(uintptr_t)msg->id);
    pthread_mutex_unlock(&monitor->msg_obj_tab_mutex);
    return -1;
}

struct monitor_msg *monitor_child_recv(struct monitor *monitor) {
    struct monitor_msg *msg = monitor_msg_create(0,0,0,NULL);
    int rc = 0;
    int len;

    len = (int)sizeof(msg->id) + (int)sizeof(msg->seqno) + (int)sizeof(msg->len);

    /* Read the msg id */
    __M_SAFE_IO(read,"read",monitor->child_recv_fd,
		&msg->id,(int)sizeof(msg->id));
    rc += (int)sizeof(msg->id);

    /* Read the msg seqno */
    __M_SAFE_IO(read,"read",monitor->child_recv_fd,&msg->seqno,
		(int)sizeof(msg->seqno));
    rc += (int)sizeof(msg->seqno);

    /* Read the msg payload len */
    __M_SAFE_IO(read,"read",monitor->child_recv_fd,
		&msg->len,(int)sizeof(msg->len));
    rc += (int)sizeof(msg->len);

    if (msg->len > 0)
	len += msg->len;

    /* Read the msg payload */
    if (msg->len > 0) {
	msg->msg = malloc(msg->len);
	__M_SAFE_IO(read,"read",monitor->child_recv_fd,
		    msg->msg,(int)sizeof(msg->len));
	rc += msg->len;
    }

    return msg;

 errout_wouldblock:
    if (rc < len && (errno == EAGAIN || errno == EWOULDBLOCK)) {
	verror("would have blocked after %d of (at least) %d bytes !\n",rc,len);
	goto errout_fatal;
    }

 errout_fatal:
    monitor_msg_free(msg);

    return NULL;
}
