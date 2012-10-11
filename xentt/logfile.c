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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <xen/xen.h>
#include <xen/time_travel.h>

#include "common.h"
#include "log.h"

#include "xentt.h"

/* Perform sanity checks on logfile */
static int sanity = 1;

/*
 * Open the replay log associated with the active session @session.
 * Note that this is NOT the log created during the original recording.
 *
 * Returns a stdio file descriptor on success, an error otherwise.
 * The file descriptor should be closed with fclose on completion.
 */
FILE *
xentt_replay_openlog(struct xentt_replay_session *session)
{
    char buf[256];

    if (session == NULL || session->state == REPLAY_INVALID) {
	verror("null or invalid session\n");
	return NULL;
    }

    snprintf(buf, sizeof buf, "%s/ttd.log.%s.replay.0",
	     session->statedir, session->name);

    return fopen(buf, "r");
}

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
struct ttd_rec *
xentt_readlog(FILE *fd)
{
    struct ttd_rec *rec = 0;
    uint32_t len, extra;

    rec = malloc(sizeof(*rec));
    if (rec == 0) {
	verror("out of memory\n");
	return 0;
    }

    /* read a fixed-size "ring buffer" record */
    if (fread(rec, sizeof(*rec), 1, fd) != 1) {
	if (!feof(fd))
	    verror("error reading record\n");
	goto bogus;
    }

#define _ASSERT(cond) { \
    if (!(cond)) { \
	verror("Bogus event:\n"); \
	xentt_dumplogentry(rec, 1); \
	goto bogus; \
    } \
}

    /* sanity check basic info */
    if (sanity) {
	_ASSERT(rec->data_len < 100000);
	_ASSERT(rec->event.event < TTD_MAX_DEFINED_EVENT);
#if 0	/* info can take on more than the enum and packed values */
	_ASSERT((rec->event.info >= TTD_INFO_NONE &&
		 rec->event.info <= TTD_INFO_VCPU_GET_CONTEXT) ||
		(rec->event.info & 0xFF) == 0xFF);
#endif
	_ASSERT(rec->domid >= 1 && rec->domid < 1000);
	_ASSERT(rec->vcpu_id >= 0 && rec->vcpu_id <= 64);
    }

#undef _ASSERT

    /* actual TTD records are an integral number of ring buffer records */
    len = rec->data_len;
    if (len <= sizeof(rec->data))
	return rec;

    /* bigger than a single record, realloc to actual size */
    extra = len - sizeof(rec->data);
    extra = ((extra + sizeof(*rec)-1) / sizeof(*rec)) * sizeof(*rec);

#if 0
    printf("rec_size=%u, data_size=%u, len=%u, extra=%u, roundup_extra=%u\n",
	   sizeof(*rec), sizeof(rec->data), len, len-sizeof(rec->data), extra);
#endif

    rec = realloc(rec, sizeof(*rec)+extra);
    if (rec == 0) {
	verror("out of memory\n");
	return 0;
    }

    /* and read the rest of the data */
    if (fread(&rec[1], extra, 1, fd) == 1)
	return rec;

    verror("error reading extended record\n");
 bogus:
    if (rec)
	free(rec);
    return 0;
}

void
xentt_dumplog(FILE *fd, int summary)
{
    unsigned long bins[TTD_MAX_DEFINED_EVENT+1];
    struct ttd_rec *rec;
    int nrec;

    nrec = 0;
    memset(bins, 0, sizeof(bins));
    while ((rec = xentt_readlog(fd)) != 0) {
	if (summary) {
	    if (rec->event.event < TTD_MAX_DEFINED_EVENT)
		bins[rec->event.event]++;
	    else
		bins[TTD_MAX_DEFINED_EVENT]++;
	    nrec++;
	}
	free(rec);
    }

    if (summary) {
	int i;

	printf("Read %d TT records, bins:\n", nrec);
	for (i = 0; i <= TTD_MAX_DEFINED_EVENT; i++) {
	    if (bins[i] > 0)
		printf("  %12lu: %d (%s)\n", bins[i], i, ttd_event_descr(i));
	}
    }
}

/*
 * Dump the replay logentry @rec in human readable form to STDOUT.
 * If @concise is non-zero, prints a less verbose (single-line) version.
 */
void
xentt_dumplogentry(struct ttd_rec *rec, int concise)
{
    if (concise) {
	printf("len=%u(%x), event=%d(%x), info=%d(%x), "
	       "domid=%d(%x), vcpu_id=%d(%x)\n",
	       rec->data_len, rec->data_len, rec->event.event,
	       rec->event.event, rec->event.info, rec->event.info,
	       rec->domid, rec->domid, rec->vcpu_id, rec->vcpu_id);
	return;
    }

    printf("%0*llx: event=%s, info=%s, len=%u\n", 12,
	   rec->cpu_state.brctr_virt, ttd_event_descr(rec->event.event),
	   ttd_event_info_descr(rec->event.info), rec->data_len);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
