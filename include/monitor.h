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

#ifndef __MONITOR_H__
#define __MONITOR_H__

#include <stdlib.h>
#include <pthread.h>
#include <limits.h>

#include "common.h"
#include "evloop.h"

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
 *
 * We also set an object id so that the parent and child can refer to
 * the same object.
 */

#define MONITOR_CHILD_RECV_FD_ENVVAR "MONITOR_CHILD_RECV_FD"
#define MONITOR_CHILD_SEND_FD_ENVVAR "MONITOR_CHILD_SEND_FD"
#define MONITOR_OBJID_ENVVAR         "MONITOR_OBJID"
#define MONITOR_OBJTYPE_ENVVAR       "MONITOR_OBJTYPE"

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
    /*
     * When the monitor is shutdown, we call this function to allow the
     * object to clean itself up and destroy itself.
     *
     * @sig is currently set to 1 if close should kill; 0 if not (i.e.,
     * hard close vs soft close).  Later we'll maybe need to define more
     * semantics.
     */
    int (*close)(int sig,void *obj);
    /*
     * If @evloop is already attached to @obj, this function should
     * return 1; if not, 0; if error, < 0.
     */
    int (*evloop_is_attached)(struct evloop *evloop,void *obj);
    int (*error)(monitor_error_t error,void *obj);
    int (*fatal_error)(monitor_error_t error,void *obj);
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

    uint8_t running:1,
	    interrupt:1,
	    halfdead:1,
	    done:1,
	    finalize:1;

    result_t done_status;

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
     * Auto-assign msg ids if caller of monitor_msg_create does not
     * assign one.
     */
    int msg_obj_id_counter;

    /*
     * The primary object we are monitoring.  Either a target or analysis, for
     * now.
     */
    int objid;
    void *obj;

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

    int (*stdin_callback)(int fd,char *buf,int len);

    /*
     * XXX: need to buffer results...
     */
    struct array_list *results;
};

#define SEQNO_MAX SHRT_MAX

struct monitor_msg {
    /*
     * @objid is the monitored object ID; demuxes the message to the
     * right monitored object.
     */
    int objid;

    /*
     * User-defined fields.  The idea is to support a generic
     * communication protocol to the monitored @objid/@objtype, and to
     * associate a state object with each msg.  The state object might
     * persist across several messages.  @id is intended to serve as a
     * msg ID; it uniquely binds one or more messages to a state object.
     * @cmd is a command ID, or something; @seqno is intended to serve
     * as a sequence number for a command, so that commands can be
     * ordered and multi-message.
     */
    int id;

    short cmd;
    short seqno;
    int len;
    char *msg;

    /*
     * This field is not transmitted; it's just convenience for the msg
     * handler.  Corresponds to @objid above.
     */
    void *obj;

    /*
     * This field is not transmitted; this is the state object for
     * stateful commands.
     */
    void *msg_obj;
};

/*
 * Lib init/fini.
 */
void monitor_init(void);
void monitor_fini(void);

/*
 * Allows us to have dynamic object types, associated with handler
 * functions.  If @objtype is -1, its value is assigned automatically,
 * and the caller should save it for future use (i.e., passing to
 * monitor_create/monitor_attach).
 */
int monitor_register_objtype(int objtype,struct monitor_objtype_ops *ops,
			     pthread_mutex_t *objtype_mutex);
/*
 * Sometimes we need to lock/unlock the per-objtype lock.
 */
int monitor_lock_objtype(int objtype);
int monitor_unlock_objtype(int objtype);
/*
 * Most times we unlock an objtype mutex, we don't really need to hold
 * the global monitor mutex to do so.  This could only get us in trouble
 * if we call it when the monitor lib is being uninitialized, I think.
 */
int monitor_unlock_objtype_unsafe(int objtype);
/*
 * Sometimes we need to atomically lock the per-objtype mutex when we
 * lookup an object, but not lock the object's monitor's lock.
 */
int monitor_lookup_objid_lock_objtype(int objid,int objtype,
				      void **obj,struct monitor **monitor);
/*
 * Sometimes we need to atomically lock the per-objtype mutex AND the
 * object's monitor's lock when we lookup an object.
 */
int monitor_lookup_objid_lock_objtype_and_monitor(int objid,int objtype,
						  void **obj,
						  struct monitor **monitor);

/*
 * Returns an array_list of all the monitored objects of @objtype.  Some
 * objects may be NULL if they are instantiated in a child process that
 * is monitored.
 *
 * The user is basically responsible for ensuring no object on the list
 * is used, by making sure that any such accesses to those objects only
 * happen when the objtype lock is held -- we do not leave the primary
 * monitor mutex locked when we return from this call.  BUT,
 * monitor_add_obj and monitor_del_obj are both supposed be called only
 * with the objtype lock held.
 *
 * The monitor code cannot try to lock the objtype lock except when
 * instructed to do so by the user.
 */
struct array_list *monitor_list_objs_by_objtype_lock_objtype(int objtype,
							     int include_null);

struct array_list *monitor_list_objids_by_objtype_lock_objtype(int objtype,
							       int include_null);

/*
 * Get a new ID for a monitored object; we want these things to be
 * globally unique, even amongst different monitored object types.
 * Makes life much easier.
 */
int monitor_get_unique_objid(void);

/*
 * Creates a monitor of @type, for a valid @objtype.
 */
struct monitor *monitor_create(monitor_type_t type,monitor_flags_t flags,
			       int objid,int objtype,void *obj);

/*
 * Creates a monitor of @type, for a (possibly unknown) @objtype.
 *
 * If @custom_child_recv_evh is specified, it replaces the built-in
 * handler for the child read end of the monitor pipe (i.e., the child
 * reading from the monitor parent thread).  This function should
 * support the monitor's builtin objid/objtype demultiplexing, but it
 * could elect not to.  If not specified, the built-in handler calls the
 * objtype msg callback functions for that objid, if they were
 * specified.  Same for @custom_recv_evh, except that it receives from
 * the child (the monitor parent reading from the child).
 */
struct monitor *monitor_create_custom(monitor_type_t type,monitor_flags_t flags,
				      int objid,int objtype,void *obj,
				      evloop_handler_t custom_recv_evh,
				      evloop_handler_t custom_child_recv_evh);

/*
 * If you created a monitor without an @obj, you MUST call this function
 * before the monitored obj will be installed into the main monitor
 * hashtables.
 *
 * (Users might call this when they need the monitor created before the
 * object is created; i.e., the target library might want the
 * monitor-created evloop as it is creating the target object.)
 *
 * Users must call this with the objtype lock held!
 */
int monitor_add_primary_obj(struct monitor *monitor,
			    int objid,int objtype,void *obj);

/*
 * Looks up a monitor based on monitored object id.  Useful for server
 * threads who have to find the monitor for a request for an object,
 * perhaps.
 */
int monitor_lookup_objid(int objid,
			 int *objtype,void **obj,
			 struct monitor **monitor);

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
			       int objtype,void *obj,
			       evloop_handler_t custom_child_recv_evh,
			       int (*stdin_callback)(int fd,char *buf,int len));

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
 *
 * If the monitor is done (via monitor_interrupt_done), returns 0 and
 * monitor_is_done() returns 1.
 *
 * If the monitor's child half is dead, returns 0 and
 * monitor_is_halfdead() returns 1.
 *
 * If the monitor was interrupted, returns 0.  If the monitor's evloop
 * has no descriptors left, also returns 0.
 *
 * If the evloop failed badly internally (probably a bug), we remove all
 * its monitored objects, set the monitor to a "done" state (its
 * done_status set to RESULT_ERROR), and return -1.
 */
int monitor_run(struct monitor *monitor);

/*
 * Breaks a monitor out of its evloop (causes monitor_run to return).
 */
void monitor_interrupt(struct monitor *monitor);

/*
 * Breaks a monitor out of its evloop (causes monitor_run to return),
 * and ensures that monitor_run() will not run again!  Only the monitor
 * thread itself should call this function (i.e., when it detects that
 * it should terminate by receiving a msg or processing some state
 * change).  If @finalize is set, the caller of monitor_run() should
 * destroy the monitor, rather than allowing it to persist.
 */
void monitor_interrupt_done(struct monitor *monitor,result_t status,int finalize);

/*
 * Returns 1 if monitor is done; else 0;
 */
int monitor_is_done(struct monitor *monitor);

/*
 * Returns 1 if monitor should self-terminate; else 0;
 */
int monitor_should_self_finalize(struct monitor *monitor);

/*
 * Breaks a monitor out of its evloop (causes monitor_run to return),
 * and declares the other side dead.  This means the monitor should
 * terminate safely after assessing the state of its world, and its
 * child; or its child should take appropriate action (cleanup and
 * continue, or self-terminate independently).
 */
void monitor_halfdead(struct monitor *monitor);

/*
 * Returns 1 if monitor half has died; else 0 if it is live.
 */
int monitor_is_halfdead(struct monitor *monitor);

/*
 * Shuts down a monitor and destroys the evloop.
 */
void monitor_shutdown(struct monitor *monitor);

/*
 * Cleans up and frees a monitor.
 */
void monitor_destroy(struct monitor *monitor);

/*
 * Free @msg, and its buffer (if non-NULL).
 *
 * Also, if the msg is associated with a msg_obj, remove it!
 */
void monitor_msg_free(struct monitor_msg *msg);

/* Free @msg, but not its buffer. */
void monitor_msg_free_save_buffer(struct monitor_msg *msg);

/*
 * Returns a monitor_msg consisting of the argument values.  Caller must
 * specify @monitor and @objid; @monitor provides the default
 * objid/objtype (which are used if objid == -1); but this also allows
 * the caller to specify a secondary monitored object, if/when they exist.
 */
struct monitor_msg *monitor_msg_create(int objid,
				       int id,short cmd,short seqno,
				       int buflen,char *buf,
				       void *msg_obj);

/*
 * Send @msg to the monitored child associated with @msg->objid, storing
 * @msg->id/@msg->msg_obj in our internal table if @msg->msg_obj exists.
 *
 * (The point of associating @msg_obj with a message id is so that if
 * the monitor user wants to associate a custom request handler (with a
 * thread-based monitor child), or a custom request handler for a
 * monitor_child and a custom reply handler for the monitor (with a
 * process-based monitor), the handlers will have a stateful object that
 * they can work on, if necessary.)
 */
int monitor_send(struct monitor_msg *msg);

/*
 * Receive a msg from @monitor (blocking).  Retrieves a msg_obj if one
 * was stored for this msg's id
 */
struct monitor_msg *monitor_recv(struct monitor *monitor);

/*
 * A monitored child must call this to send a message to its parent
 * (blocking).
 */
int monitor_child_send(struct monitor_msg *msg);

/*
 * A monitored child must call this to read a message from its parent
 * (blocking).
 */
struct monitor_msg *monitor_child_recv(struct monitor *monitor);

#endif /* __MONITOR_H__ */
