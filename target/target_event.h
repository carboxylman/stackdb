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

#ifndef __TARGET_EVENT_H__
#define __TARGET_EVENT_H__

#include "common.h"

/**
 ** Target Events.
 **/

typedef enum {
    T_EVENT_EXITED = 1,
    T_EVENT_EXITING,
    T_EVENT_ERROR,

    /*
    T_EVENT_THREAD_CREATED,
    T_EVENT_THREAD_EXITED,
    T_EVENT_THREAD_EXITING,

    T_EVENT_SPACE_NEW,
    T_EVENT_SPACE_MOD,
    T_EVENT_SPACE_DEL,

    T_EVENT_REGION_NEW,
    T_EVENT_REGION_MOD,
    T_EVENT_REGION_DEL,

    T_EVENT_RANGE_NEW,
    T_EVENT_RANGE_MOD,
    T_EVENT_RANGE_DEL,
    */

    T_EVENT_OS_THREAD_CREATED,
    T_EVENT_OS_THREAD_EXITED,
    T_EVENT_OS_THREAD_EXITING,
    T_EVENT_OS_SPACE_NEW,
    T_EVENT_OS_SPACE_MOD,
    T_EVENT_OS_SPACE_DEL,
    T_EVENT_OS_REGION_NEW,
    T_EVENT_OS_REGION_MOD,
    T_EVENT_OS_REGION_DEL,
    T_EVENT_OS_RANGE_NEW,
    T_EVENT_OS_RANGE_MOD,
    T_EVENT_OS_RANGE_DEL,

    T_EVENT_OS_PROCESS_THREAD_CREATED,
    T_EVENT_OS_PROCESS_THREAD_EXITED,
    T_EVENT_OS_PROCESS_THREAD_EXITING,
    T_EVENT_OS_PROCESS_SPACE_NEW,
    T_EVENT_OS_PROCESS_SPACE_MOD,
    T_EVENT_OS_PROCESS_SPACE_DEL,
    T_EVENT_OS_PROCESS_REGION_NEW,
    T_EVENT_OS_PROCESS_REGION_MOD,
    T_EVENT_OS_PROCESS_REGION_DEL,
    T_EVENT_OS_PROCESS_RANGE_NEW,
    T_EVENT_OS_PROCESS_RANGE_MOD,
    T_EVENT_OS_PROCESS_RANGE_DEL,

    T_EVENT_PROCESS_THREAD_CREATED,
    T_EVENT_PROCESS_THREAD_EXITED,
    T_EVENT_PROCESS_THREAD_EXITING,
    T_EVENT_PROCESS_SPACE_NEW,
    T_EVENT_PROCESS_SPACE_MOD,
    T_EVENT_PROCESS_SPACE_DEL,
    T_EVENT_PROCESS_REGION_NEW,
    T_EVENT_PROCESS_REGION_MOD,
    T_EVENT_PROCESS_REGION_DEL,
    T_EVENT_PROCESS_RANGE_NEW,
    T_EVENT_PROCESS_RANGE_MOD,
    T_EVENT_PROCESS_RANGE_DEL,
} target_event_t;

#define T_EVENT_IS_OS(event)						\
    ((event)->type >= T_EVENT_OS_THREAD_CREATED				\
     && (event)->type <= T_EVENT_OS_RANGE_DEL)
#define T_EVENT_IS_OS_PROCESS(event)					\
    ((event)->type >= T_EVENT_OS_PROCESS_THREAD_CREATED			\
     && (event)->type <= T_EVENT_OS_PROCESS_RANGE_DEL)
#define T_EVENT_IS_PROCESS(event)					\
    ((event)->type >= T_EVENT_PROCESS_THREAD_CREATED			\
     && (event)->type <= T_EVENT_PROCESS_RANGE_DEL)
#define T_EVENT_IS_SPACE(event,ttype)				\
    ((event)->type >= T_EVENT_ ## ttype ## _SPACE_NEW		\
     && (event)->type <= T_EVENT_ ## ttype ## _SPACE_DEL)
#define T_EVENT_IS_REGION(event,ttype)				\
    ((event)->type >= T_EVENT_ ## ttype ## _REGION_NEW		\
     && (event)->type <= T_EVENT_ ## ttype ## _REGION_DEL)
#define T_EVENT_IS_RANGE(event,ttype)				\
    ((event)->type >= T_EVENT_ ## ttype ## _RANGE_NEW		\
     && (event)->type <= T_EVENT_ ## ttype ## _RANGE_DEL)

static inline char *TARGET_EVENT_NAME(target_event_t type) {
    switch (type) {
    case T_EVENT_EXITED: return "EXITED";
    case T_EVENT_EXITING: return "EXITING";
    case T_EVENT_ERROR: return "ERROR";
	/*
    case T_EVENT_THREAD_CREATED: return "THREAD_CREATED";
    case T_EVENT_THREAD_EXITED: return "THREAD_EXITED";
    case T_EVENT_THREAD_EXITING: return "THREAD_EXITING";

    case T_EVENT_SPACE_NEW: return "SPACE_NEW";
    case T_EVENT_SPACE_MOD: return "SPACE_MOD";
    case T_EVENT_SPACE_DEL: return "SPACE_DEL";

    case T_EVENT_REGION_NEW: return "REGION_NEW";
    case T_EVENT_REGION_MOD: return "REGION_MOD";
    case T_EVENT_REGION_DEL: return "REGION_DEL";

    case T_EVENT_RANGE_NEW: return "RANGE_NEW";
    case T_EVENT_RANGE_MOD: return "RANGE_MOD";
    case T_EVENT_RANGE_DEL: return "RANGE_DEL";
	*/
    case T_EVENT_OS_THREAD_CREATED: return "OS_THREAD_CREATED";
    case T_EVENT_OS_THREAD_EXITED: return "OS_THREAD_EXITED";
    case T_EVENT_OS_THREAD_EXITING: return "OS_THREAD_EXITING";
    case T_EVENT_OS_SPACE_NEW: return "OS_SPACE_NEW";
    case T_EVENT_OS_SPACE_MOD: return "OS_SPACE_MOD";
    case T_EVENT_OS_SPACE_DEL: return "OS_SPACE_DEL";
    case T_EVENT_OS_REGION_NEW: return "OS_REGION_NEW";
    case T_EVENT_OS_REGION_MOD: return "OS_REGION_MOD";
    case T_EVENT_OS_REGION_DEL: return "OS_REGION_DEL";
    case T_EVENT_OS_RANGE_NEW: return "OS_RANGE_NEW";
    case T_EVENT_OS_RANGE_MOD: return "OS_RANGE_MOD";
    case T_EVENT_OS_RANGE_DEL: return "OS_RANGE_DEL";

    case T_EVENT_OS_PROCESS_THREAD_CREATED: return "OS_PROCESS_THREAD_CREATED";
    case T_EVENT_OS_PROCESS_THREAD_EXITED: return "OS_PROCESS_THREAD_EXITED";
    case T_EVENT_OS_PROCESS_THREAD_EXITING: return "OS_PROCESS_THREAD_EXITING";
    case T_EVENT_OS_PROCESS_SPACE_NEW: return "OS_PROCESS_SPACE_NEW";
    case T_EVENT_OS_PROCESS_SPACE_MOD: return "OS_PROCESS_SPACE_MOD";
    case T_EVENT_OS_PROCESS_SPACE_DEL: return "OS_PROCESS_SPACE_DEL";
    case T_EVENT_OS_PROCESS_REGION_NEW: return "OS_PROCESS_REGION_NEW";
    case T_EVENT_OS_PROCESS_REGION_MOD: return "OS_PROCESS_REGION_MOD";
    case T_EVENT_OS_PROCESS_REGION_DEL: return "OS_PROCESS_REGION_DEL";
    case T_EVENT_OS_PROCESS_RANGE_NEW: return "OS_PROCESS_RANGE_NEW";
    case T_EVENT_OS_PROCESS_RANGE_MOD: return "OS_PROCESS_RANGE_MOD";
    case T_EVENT_OS_PROCESS_RANGE_DEL: return "OS_PROCESS_RANGE_DEL";

    case T_EVENT_PROCESS_THREAD_CREATED: return "PROCESS_THREAD_CREATED";
    case T_EVENT_PROCESS_THREAD_EXITED: return "PROCESS_THREAD_EXITED";
    case T_EVENT_PROCESS_THREAD_EXITING: return "PROCESS_THREAD_EXITING";
    case T_EVENT_PROCESS_SPACE_NEW: return "PROCESS_SPACE_NEW";
    case T_EVENT_PROCESS_SPACE_MOD: return "PROCESS_SPACE_MOD";
    case T_EVENT_PROCESS_SPACE_DEL: return "PROCESS_SPACE_DEL";
    case T_EVENT_PROCESS_REGION_NEW: return "PROCESS_REGION_NEW";
    case T_EVENT_PROCESS_REGION_MOD: return "PROCESS_REGION_MOD";
    case T_EVENT_PROCESS_REGION_DEL: return "PROCESS_REGION_DEL";
    case T_EVENT_PROCESS_RANGE_NEW: return "PROCESS_RANGE_NEW";
    case T_EVENT_PROCESS_RANGE_MOD: return "PROCESS_RANGE_MOD";
    case T_EVENT_PROCESS_RANGE_DEL: return "PROCESS_RANGE_DEL";

    default: return NULL;
    }
}

struct target;
struct target_thread;

/**
 * Target events are broadcast by target drivers when they notice an
 * event has occurred on the target.  Currently, drivers must broadcast
 * them *before* handling any user-registered probes.  Thus, probe
 * handlers should always see the newest model of the target that the
 * driver knows of.
 *
 * Events (and their privileged data) are only valid during the lifetime
 * of the callback that is handling them.  They are immediately deleted
 * afterward!
 */
struct target_event {
    target_event_t type;
    /*
     * We copy the target id and thread id in case we have to NULL out
     * target/thread after creating the event, because the objects got
     * deleted.
     */
    int id;
    tid_t tid;
    struct target *target;
    struct target_thread *thread;
    void *priv;
    void *priv2;
};

/*
 * Creates an event.
 */
struct target_event *target_create_event(struct target *target,
					 struct target_thread *thread,
					 target_event_t event,void *priv);

struct target_event *target_create_event_2(struct target *target,
					   struct target_thread *thread,
					   target_event_t event,
					   void *priv,void *priv2);
/*
 * Broadcasts an @event on @target (and target_queue_event iff @target
 * == @event->target).  If @target == @event->target, @target itself
 * will not be notified.  If @target->base, the base target will be
 * notified.  If @event->thread->tid is a member of one of
 * @target->overlays, the corresponding overlay will be notified too.
 */
void target_broadcast_event(struct target *target,struct target_event *event);

#endif /* __TARGET_EVENT_H__ */
