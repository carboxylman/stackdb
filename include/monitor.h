/*
 * Copyright (c) 2012 The University of Utah
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

#ifndef __MONITOR_H__
#define __MONITOR_H__

#include <stdlib.h>
#include <pthread.h>

struct monitor;
struct monitor_msg;

typedef enum {
    /*
     * This type of monitored object can run in a thread.
     */
    MONITOR_TYPE_THREAD = 1,
    /*
     * This type of monitored object runs in a separate process.
     */
    MONITOR_TYPE_PROCESS = 2,
} monitor_type_t;

typedef enum {
    MONITOR_FLAG_NONE = 0,
    /*
     * This flag means that we need to setup bidirectional communication
     * between the monitor and the child.
     */
    MONITOR_FLAG_BIDI = 1,
} monitor_flag_t;

typedef int monitor_flags_t;

typedef enum {
    MONITOR_ERROR_UNKNOWN = 1,
    MONITOR_ERROR_STDIN   = 2,
    MONITOR_ERROR_STDOUT  = 3,
    MONITOR_ERROR_STDERR  = 4,
    MONITOR_ERROR_OBJ     = 5,
} monitor_error_t;

/*
 * If we fork a binary, before we exec the binary, we dup2()
 * some file descriptors so the monitor and child can communicate.
 * These are the environment var names.  To be a monitored child, at
 * least MONITOR_CHILD_RECV_FD must be set; MONITOR_CHILD_SEND_FD may
 * also be set if the monitor is listening for replies.
 */

#define MONITOR_CHILD_RECV_FD_ENVVAR "MONITOR_CHILD_RECV_FD"
#define MONITOR_CHILD_SEND_FD_ENVVAR "MONITOR_CHILD_SEND_FD"

/*
 * Object type-specific functions.
 */
struct monitor_objtype_ops {
    /*
     * When the monitor is created, and the evloop is built, we call
     * this function to allow @obj to add any of the FDs it needs to our
     * @evloop.
     */
    int (*evloop_attach)(struct evloop *evloop,void *obj);
    /*
     * When the monitor is freed, and the evloop is built, we call
     * this function to allow @obj to add any of the FDs it needs to our
     * @evloop.
     */
    int (*evloop_detach)(struct evloop *evloop,void *obj);
    int (*error)(monitor_error_t error,void *obj);
    int (*fatal_error)(monitor_error_t error,void *obj);
    /*
     * Replace the built-in handler for the child read end of the
     * monitor pipe.  This function can choose to call the below msg
     * callback functions, or not; the built-in handlers call the msg
     * callback functions, if specified.
     *
     * (@state will be the the monitor associated with this @fd.)
     */
    int (*child_recv_evh)(int fd,int fdtype,void *state);
    /*
     * Replace the built-in handler for the monitor read end of the
     * monitor pipe.  This function can choose to call the below msg
     * callback functions, or not; the built-in handlers call the msg
     * callback functions, if specified.
     *
     * (@state will be the the monitor associated with this @fd.)
     */
    int (*recv_evh)(int fd,int fdtype,void *state);
    /*
     * For ease of use, we allow library users to specify callbacks to
     * receive just the msgs without having to specify an evloop handler
     * (above).  Our built-in handlers call these callbacks by default;
     * as noted above, if the user overrides our handlers via the above
     * two fields, these callbacks will only be called if the
     * user-supplied ones call them.
     *
     * (Note: these functions must clone the msg if they need its
     * contents to persist after the handler returns.)
     */
    int (*child_recv_msg)(struct monitor *monitor,struct monitor_msg *msg);
    int (*recv_msg)(struct monitor *monitor,struct monitor_msg *msg);
};

/*
 * Each monitored object we launch is paired with a monitor struct in
 * the server thread that created it; we launch the child object from a
 * thread that becomes the monitor thread.  That thread is the owner of
 * this structure.
 *
 * If the monitored object requires a process, the monitor thread
 * watches the forked process, exchanges msgs with it, logs/buffers its
 * stdio.
 *
 * If the monitored object requires a thread, that thread is itself the
 * monitor thread for the object, and both interacts with the object and
 * replies to requests.
 */
struct monitor {
    /* Either of MONITOR_TYPE_(THREAD|PROCESS). */
    monitor_type_t type;

    monitor_flags_t flags;

    /* The thread monitoring this object. */
    pthread_t mtid;

    /*
     * Used to ensure safe writes to the FDs, or the thread queue.  The
     * child CANNOT take this lock!
     */
    pthread_mutex_t mutex;

    /*
     * Each sent monitor message can be associated with an object.
     * These are stored in this hashtable.  It is up to the user of the
     * monitor to remove these when finished with them.
     *
     * (The intended use for us is that each split request (transmitted
     * as a monitor_msg) is associated with a real, live soap request.
     * For thread-based target objects, the monitor thread can pull the
     * object out from this table when it is ready to process the
     * request, and respond directly on the soap struct.  For
     * process-based analysis objects, the monitor thread call leave the
     * object in this table until the process replies with the response,
     * then reply on the soap object in this table.)
     *
     * Thus, for threads, the parent/child must agree on the
     * locking/freeing behavior of this table, and the objects contained
     * in it; objects are not locked per object.
     */
    GHashTable *msg_obj_tab;

    /*
     * Used to assure serialized access to @msg_obj_tab.  The only way
     * the server should take this lock is before taking the @mutex lock
     * above; and it had better release this lock before sending a
     * message!  Otherwise if the child is notified and reads the
     * message first, it might try to grab this lock and block; we don't
     * want that.
     */
    pthread_mutex_t msg_obj_tab_mutex;

    /*
     * The object we are monitoring.  Either a target or analysis, for
     * now.
     */
    int objtype;
    void *obj;
    struct monitor_objtype_ops *objtype_ops;

    /*
     * Our internal evloop.  Each monitor runs an evloop, which is how
     * it monitors its monitored object, and how it monitors
     * communication on its file descriptors for monitor/child
     * communication.
     *
     * Thus, users should call monitor_run() after creating a monitor,
     * its monitored object, and linking the monitored object to this
     * evloop.  XXX: is there a way we can abstract this?
     */
    struct evloop *evloop;

    /*
     * If non-negative, the monitored thread/process will be listening
     * on @child_request_recv_fd for new msgs from the parent.  The
     * parent sends via @handler_request_send_fd.
     *
     * For threads, the monitor_msg sent has no payload.  For processes,
     * the monitor_msg has a variable-length payload.
     */
    int monitor_send_fd; /* open with F_CLOEXEC */
    int child_recv_fd;   /* close in parent after fork */

    /*
     * These reply descriptors are only created if this is a
     * MONITOR_TYPE_PROCESS.
     * 
     * The request-handling thread will have buffered the request,
     * authenticated it and checked its permissions, demuxed it to the
     * right child, and passed it to the child via
     * @parent_request_send_fd, and must wait for a response on
     * @parent_reply_recv_fd, assuming the child will respond on
     * @child_reply_send_fd .
     *
     * We have to do it this way because all the connection state is in
     * the parent, but all the ability to interact with the target is in
     * the child (i.e., ptrace).
     */
    int child_send_fd;   /* close in parent after fork */
    int monitor_recv_fd; /* open with F_CLOEXEC */

    /*
     * Process-specific monitor state.  There is no thread-specific
     * state because the monitor thread is the same as the object thread
     * -- they both share the thread.  Only objects that expose an
     * evloop interface can be used in those threads anyway.
     */
    struct {
	int pid;
	int status;

	/*
	 * Input/output buffers for the monitored process.
	 */
	int stdin_m_fd; /* open with F_CLOEXEC */
	int stdin_c_fd; /* close in parent after fork */
	char *stdin_buf;
	int stdin_left;
	int stdin_bufsiz;

	int stdout_m_fd; /* open with F_CLOEXEC */
	int stdout_c_fd; /* close in parent after fork */
	/* struct cbuf *stdout_buf; */
	int stdout_log_fd;
	int (*stdout_callback)(int fd,char *buf,int len);

	int stderr_m_fd; /* open with F_CLOEXEC */
	int stderr_c_fd; /* close in parent after fork */
	/* struct cbuf *stderr_buf; */
	int stderr_log_fd;
	int (*stderr_callback)(int fd,char *buf,int len);
    } p;

    /*
     * XXX: need to buffer results...
     */
    struct array_list *results;
};

struct monitor_msg {
    int id;
    int seqno;
    int len;
    char *msg;
};

/*
 * Allows us to have dynamic object types, associated with handler
 * functions.  If @objtype is -1, its value is assigned automatically,
 * and the caller should save it for future use (i.e., passing to
 * monitor_create/monitor_attach).
 */
int monitor_register_objtype(int objtype,struct monitor_objtype_ops *ops);

/*
 * Return the monitor struct corresponding to @obj, if any.
 */
struct monitor *monitor_lookup(void *obj);

/*
 * Return the monitor struct corresponding to @obj, with it locked.
 * This allows the caller to ensure that the monitor thread will not
 * monitor_free @obj's monitor out from under it!
 */
struct monitor *monitor_lookup_and_lock(void *obj);

/*
 * Creates a monitor of @type, for a valid @objtype.
 */
struct monitor *monitor_create(monitor_type_t type,monitor_flags_t flags,
			       int objtype,void *obj);

/*
 * Creates a monitor of @type, for a (possibly unknown) @objtype.
 */
struct monitor *monitor_create_custom(monitor_type_t type,monitor_flags_t flags,
				      int objtype,void *obj);

/*
 * Checks for at least one of the two env vars that specify file
 * descriptors for communication with a monitor
 */
int monitor_can_attach(void);

/*
 * Return 1 if the caller is a monitored child with both recv/send
 * comms to the monitor; else 0.
 */
int monitor_can_attach_bidi(void);

/*
 * "Attaches" to a monitor via pipes.  This should only be called from
 * monitored processes.
 */
struct monitor *monitor_attach(monitor_type_t type,monitor_flags_t flags,
			       int objtype,void *obj);

/*
 * Call if the target spec or analysis spec dictates I/O behavior -- and
 * if we're forking the child.  Can't do this for threaded children,
 * obviously.
 */
int monitor_setup_stdin(struct monitor *monitor,
			char *stdin_buf,int stdin_buflen);
int monitor_setup_stdout(struct monitor *monitor,
			 int maxbufsiz,char *stdout_logfile,
			 int (*stdout_callback)(int fd,char *buf,int len));
int monitor_setup_stderr(struct monitor *monitor,
			 int maxbufsiz,char *stderr_logfile,
			 int (*stderr_callback)(int fd,char *buf,int len));

/*
 * Should be called from the control thread to fork() and exec() a new
 * process to run either a target or analysis in.  This basically calls
 * putenv() in the child to set the child MONITOR_CHILD_SEND_FD and
 * MONITOR_CHILD_RECV_FD variables; closes FDs in the child that should
 * not be open (and cleans up other state); and sets up the child's
 * standard FDs as dictated by monitor_setup_*().
 *
 * We cannot provide a generic fork() function due to our use of
 * pthreads, of course (see pthread_atfork() for detailed discussion).
 * This means that if we want to run a specific target in a separate
 * address space (i.e., for greater stability of the server), we have to
 * have a wrapper program that spawns the target in a paused state, but
 * knows how to expose it to the XML RPC server(s).  Very doable.
 *
 * For now, just be careful to mark any mmap()s you don't want with
 * MADV_DONTFORK, and any file descriptors that cannot be inherited,
 * with CLOEXEC.  That should pretty much do it.
 */
int monitor_spawn(struct monitor *monitor,char *filename,
		  char *const argv[],char *const envp[],char *dir);

/*
 * Runs the monitor (basically just runs its internal evloop).
 */
int monitor_run(struct monitor *monitor);

/*
 * Cleans up a monitor, but does not free it.  In particular, it closes
 * open sockets with the child so that _sendfor()/recv() do not hang or
 * error.
 */
void monitor_cleanup(struct monitor *monitor);

/*
 * Cleans up and frees a monitor.
 */
void monitor_free(struct monitor *monitor);

/* Free @msg, and its buffer (if non-NULL). */
void monitor_msg_free(struct monitor_msg *msg);

/* Returns a monitor_msg consisting of the argument values. */
struct monitor_msg *monitor_msg_create(int id,int seqno,int buflen,char *buf);

/*
 * Gets a msg_obj if we have stored one corresponding to @msg_id.
 */
void *monitor_get_msg_obj(struct monitor *monitor,int msg_id);

/*
 * Removes the msg_obj corresponding to @msg_id, if any.
 */
void monitor_del_msg_obj(struct monitor *monitor,int msg_id);

/*
 * Send @msg to the monitor associated with @obj, storing
 * @msg->id/@msg_obj in our internal table.
 *
 * (The point of associating @msg_obj with a message id is so that if
 * the monitor user wants to associate a custom request handler (with a
 * thread-based monitor child), or a custom request handler for a
 * monitor_child and a custom reply handler for the monitor (with a
 * process-based monitor), the handlers will have a stateful object that
 * they can work on, if necessary.)
 */
int monitor_sendfor(void *obj,struct monitor_msg *msg,void *msg_obj);

/*
 * Receive a msg from @monitor (blocking).
 */
struct monitor_msg *monitor_recv(struct monitor *monitor);

/*
 * A monitored child must call this to send a message to its parent
 * (blocking).
 */
int monitor_child_sendfor(void *obj,struct monitor_msg *msg,void *msg_obj);

/*
 * A monitored child must call this to read a message from its parent
 * (blocking).
 */
struct monitor_msg *monitor_child_recv(struct monitor *monitor);

#endif /* __MONITOR_H__ */
