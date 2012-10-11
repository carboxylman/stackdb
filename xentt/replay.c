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

/*
 * Lower level replay functions
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>

#include "common.h"
#include "log.h"

#include "xentt.h"

/* XXX! */
static char REPLAY_TOOL[] = "/usr/local/bin/tt_replay";

/*
 * Create a replay session from state previously recorded by a tt_record.pl
 * run. @statedir is the directory given to tt_record when the VM was
 * recorded. @name is an identifier used to name the Xen domain when it is
 * created via xentt_replay_start. Note that the create call only verifies
 * the state and creates an object, it does NOT create a Xen domain.
 *
 * Returns a pointer to a replay object on success, NULL otherwise.
 */
struct xentt_replay_session *
xentt_replay_create(char *name, char *statedir)
{
    struct xentt_replay_session *session;
    struct stat sb;

    if (stat(REPLAY_TOOL, &sb) != 0 || !S_ISREG(sb.st_mode)) {
	verror("%s: replay script does not exist\n", REPLAY_TOOL);
	if (errno == 0)
	    errno = EINVAL;
	return NULL;
    }
    if (stat(statedir, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
	verror("%s: invalid state directory\n", statedir);
	if (errno == 0)
	    errno = EINVAL;
	return NULL;
    }
    if ((session = malloc(sizeof *session)) == NULL) {
	verror("failed to allocate a replay sesson object\n");
	return NULL;
    }
    memset(session, 0, sizeof(*session));
    session->name = strdup(name);
    session->statedir = strdup(statedir);
    session->state = REPLAY_INITIALIZED;
    session->domid = -1;

    return session;
}

/*
 * Starts the replay domain identified by @session and lets it run til
 * it reaches location @pauseat or exits. It @pauseat is NULL, the domain
 * is created paused. Once started, the domain can be passed to
 * target_xen_attach and manipulated with the VMI interface.
 *
 * Returns zero on success, an error otherwise. 
 */
int
xentt_replay_start(struct xentt_replay_session *session,
		   struct xentt_replay_location *pauseat)
{
    char cmdline[256];
    int domid = 0;
    FILE *fd;

    /* XXX */
    if (pauseat != NULL) {
	verror("pauseat parameter not supported yet\n");
	return EINVAL;
    }

    if (session == NULL || session->state != REPLAY_INITIALIZED) {
	if (session)
	    verror("%s: invalid session\n", session->name ?: "???");
	else
	    verror("null session\n");
	return EINVAL;
    }

    /* startup the session paused */
    snprintf(cmdline, sizeof(cmdline), "%s -s %s -p %s",
	     REPLAY_TOOL, session->statedir, session->name);
    if (system(cmdline)) {
	int err = errno;
	verror("failed to start replay domain %s (in %s)\n",
	       session->name, session->statedir);
	return err;
    }

    /* set now in case of failure below */
    session->state = REPLAY_ACTIVE;

    /* record the domid (XXX hack, hack) */
    snprintf(cmdline, sizeof(cmdline), "%s/domid", session->statedir);
    fd = fopen(cmdline, "r");
    if (fd == NULL || fscanf(fd, "%d", &domid) != 1) {
	verror("failed to get domain ID for %s\n", session->name);
	if (fd)
	    fclose(fd);
	(void)xentt_replay_stop(session);
	return EINVAL;
    }
    fclose(fd);

    session->domid = domid;

    return 0;
}

/*
 * Return the domid associated with the replay session @session.
 *
 * Returns zero on success with domid in @domid, non-zero on error.
 */
int
xentt_replay_domid(struct xentt_replay_session *session, domid_t *domid)
{
    if (session == NULL || session->state == REPLAY_INVALID) {
	verror("null or invalid session\n");
	return EINVAL;
    }
    if (session->state != REPLAY_ACTIVE) {
	verror("session replay domain is not running\n");
	return EINVAL;
    }

    if (domid)
	*domid = session->domid;
    return 0;
}


/*
 * Stop the replay session identified by @session.
 * This call kills the domain and associated daemons, but does not remove
 * the event log or any other state. It can thus be restarted and run from
 * the beginning with a call to xentt_replay_start.
 *
 * Returns zero on success an error code otherwise.
 */
int
xentt_replay_stop(struct xentt_replay_session *session)
{
    char cmdline[256];

    if (session == NULL || session->state == REPLAY_INVALID) {
	verror("null or invalid session\n");
	return EINVAL;
    }

    if (session->state != REPLAY_INITIALIZED) {
	/* stop the session */
	snprintf(cmdline, sizeof(cmdline), "%s -s %s -K %s",
		 REPLAY_TOOL, session->statedir, session->name);
	if (system(cmdline)) {
	    int err = errno;
	    verror("failed to stop replay domain %s (in %s)\n",
		   session->name, session->statedir);
	    return err;
	}
	session->domid = 0;
	session->state = REPLAY_INITIALIZED;
    }

    return 0;
}

/*
 * Destroys the replay session identified by @session.
 * This kills the domain and any associated daemons and deallocates
 * the session object. The state used to create the session originally
 * is not touched. Thus the session cannot be restarted with
 * xentt_replay_runtil, but a new session may be created using the
 * same state directory.
 */
void
xentt_replay_destroy(struct xentt_replay_session *session)
{
    if (session == NULL || session->state == REPLAY_INVALID) {
	verror("null or invalid session\n");
	return EINVAL;
    }
    (void) xentt_replay_stop(session);
    assert(session->state == REPLAY_INITIALIZED);

    if (session->name)
	free(session->name);
    if (session->statedir)
	free(session->statedir);

    /* XXX just in case someone tries to reuse it */
    session->state = REPLAY_INVALID;

    free(session);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
