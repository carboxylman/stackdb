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

#include <stdlib.h>

#include "log.h"
#include "target_event.h"
#include "target_api.h"
#include "target.h"

struct target_event *target_create_event(struct target *target,
					 struct target_thread *thread,
					 target_event_t type,void *priv) {
    struct target_event *retval = calloc(1,sizeof(*retval));

    retval->type = type;
    retval->target = target;
    if (target)
	retval->id = target->id;
    else
	retval->id = -1;
    if (thread)
	retval->tid = thread->tid;
    else
	retval->tid = -1;
    retval->thread= thread;
    retval->priv = priv;

    return retval;
}

struct target_event *target_create_event_2(struct target *target,
					   struct target_thread *thread,
					   target_event_t type,
					   void *priv,void *priv2) {
    struct target_event *retval = target_create_event(target,thread,type,priv);
    retval->priv2 = priv2;
    return retval;
}

void target_broadcast_event(struct target *target,struct target_event *event) {
    struct target *overlay;

    vdebug(5,LA_TARGET,LF_TARGET,
	   "event %s from target %s broadcasting on target %s\n",
	   TARGET_EVENT_NAME(event->type),event->target->name,target->name);

    /* Tell the given target, if it's different. */
    if (target != event->target) {
	if (target->ops->handle_event)
	    target->ops->handle_event(target,event);
    }

    /* Bubble down... */
    if (target->base) {
	vdebug(5,LA_TARGET,LF_TARGET,
	       "event %s from target %s broadcasting to base target %s\n",
	       TARGET_EVENT_NAME(event->type),event->target->name,
	       target->base->name);
	if (target->base->ops->handle_event)
	    target->base->ops->handle_event(target->base,event);
    }

    /* And bubble up... */
    if (event->thread) {
	overlay = target_lookup_overlay(target,event->thread->tid);
	if (overlay) {
	    vdebug(5,LA_TARGET,LF_TARGET,
		   "event %s from target %s broadcasting to overlay target %s\n",
		   TARGET_EVENT_NAME(event->type),event->target->name,
		   overlay->name);
	    if (overlay->ops->handle_event)
		overlay->ops->handle_event(overlay,event);
	}
    }

    free(event);
}
