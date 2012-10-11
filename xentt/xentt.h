/*
 * Copyright (c) 2011, 2012 The University of Utah
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
#ifndef __XENTT_H__
#define __XENTT_H__

#include <stdint.h>
#include <xen/xen.h>

/* XXX placeholder */
struct xentt_analysis {
	void *foo;
};

/*
 * Used to identify a point in "time" in a replay.
 * A unique location is identified by an EIP value (that we can put a
 * probe on), a branch counter value (to ensure we identify the unique
 * instance of the EIP value), and the value of the CX register in case
 * we are probing an instruction with the "rep" prefix.
 *
 * XXX yes, this is x86 specific.
 */
struct xentt_replay_location {
    uint64_t eip;
    uint64_t brctr;
    uint64_t cx;
};

struct xentt_replay_session {
    char *name;		/* ascii ID for messages */
    char *statedir;	/* directory containing good shit */
    uint32_t state;	/* state of the replay */
    domid_t domid;	/* Xen domain ID associated with replay run */
    struct xentt_replay_location loc; /* current location when paused */
};
#define REPLAY_INVALID		0xDEADBEEF
#define REPLAY_INITIALIZED	1
#define REPLAY_ACTIVE		2

/*
 * Create a replay session from state previously recorded by a tt_record.pl
 * run. @statedir is the directory given to tt_record when the VM was
 * recorded. @name is an identifier used to name the Xen domain when it is
 * created via xentt_replay_start. Note that the create call only verifies
 * the state and creates an object, it does NOT create a Xen domain.
 *
 * Returns a pointer to a replay object on success, NULL otherwise.
 */
struct xentt_replay_session *xentt_replay_create(char *name, char *statedir);

/*
 * Starts the replay domain identified by @session and lets it run til
 * it reaches location @pauseat or exits. It @pauseat is NULL, the domain
 * is created paused. Once started, the domain can be passed to
 * target_xen_attach and manipulated with the VMI interface.
 *
 * Returns zero on success, an error otherwise. 
 */
int xentt_replay_start(struct xentt_replay_session *session,
		       struct xentt_replay_location *pauseat);

/*
 * Return the domid associated with the replay session @session.
 *
 * Returns zero on success with domid in @domid, non-zero on error.
 */
int xentt_replay_domid(struct xentt_replay_session *session, domid_t *domid);

/*
 * Stop the replay session identified by @session.
 * This call kills the domain and associated daemons, but does not remove
 * the event log or any other state. It can thus be restarted and run from
 * the beginning with a call to xentt_replay_start.
 *
 * Returns zero on success an error code otherwise.
 */
int xentt_replay_stop(struct xentt_replay_session *session);

/*
 * Destroys the replay session identified by @session.
 * This kills the domain and any associated daemons and deallocates
 * the session object. The state used to create the session originally
 * is not touched. Thus the session cannot be restarted with
 * xentt_replay_runtil, but a new session may be created using the
 * same state directory.
 */
void xentt_replay_destroy(struct xentt_replay_session *session);

/*
 * Replay log functions.
 */

/*
 * Open the replay log associated with the active session @session.
 *
 * Returns a stdio file descriptor on success, an error otherwise.
 * The file descriptor should be closed with fclose on completion.
 */
FILE *xentt_replay_openlog(struct xentt_replay_session *session);

/*
 * Read the next record from the logfile identified by @fd.
 * Normally, xentt_replay_readlog is called with a file descriptor returned
 * by xentt_replay_openlog, but it can be called with any FILE * representing
 * an open, valid replay logfile; e.g., an fd returned by fopen of a logfile
 * no longer associated with a replay session.
 *
 * Returns a pointer to the malloc'ed next record, or NULL on an error.
 * Returned record should be free'd by the caller.
 */
struct ttd_rec *xentt_readlog(FILE *fd);

void xentt_dumplog(FILE *fd, int summary);
void xentt_dumplogentry(struct ttd_rec *rec, int concise);

/*
 * Couple Xen TT replay runs with analyses.
 * XXX not defined yet.
 */
int xentt_replay_run_analysis(struct xentt_replay_session *replay_session,
			      struct xentt_analysis *analysis);

#endif /* __XENTT_H__ */
