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

#ifndef __OBJECT_H__
#define __OBJECT_H__

/**
 * Object liveness tracking.  Some of our objects are either "live" or
 * not.  "Live" (in the case of the target components, especially) tends
 * to mean the object is a model of a real object that is live in the
 * target program, and thus the model object is hashed (tracked) in the
 * main target object.  Objects may also be marked new, updated, and
 * deleted.  Many objects and algorithms watching them benefit from
 * having these flags.
 *
 * Any objects you wish to apply liveness macros to must have a field
 * "obj_flags_t obj_flags", and there must be a function called
 * "<type>_obj_flags_propagate()" function so that some macros can
 * propagate the new flags to the object's owned children.  Not all
 * macro setters propagate the values to children; see their
 * documentation below to know which is which!  At the moment, only the
 * LIVE flag (set via OBJSLIVE() and OBJSDEAD() macros) is propagated.
 * Anyway, this propagation assumes that the flags for the object have
 * already been set.  Thus, the propagation function must set the flags
 * on any child objects, then call their propagation function, and so
 * on.
 */
typedef enum {
    /**
     * Marks the object as validly loaded since the last check or
     * exception.
     */
    OBJ_VALID = 1 << 0,
    /**
     * Marks the object as modified since the last check or exception.
     */
    OBJ_DIRTY = 1 << 1,
    /**
     * Marks the object as live.
     */
    OBJ_LIVE = 1 << 2,
    /**
     * Marks if the object is newly created.
     */
    OBJ_NEW = 1 << 3,
    /**
     * Marks if the object was modified in the last check or exception.
     */
    OBJ_MOD = 1 << 4,
    /**
     * The deleted flag exists separately from the live flag because an
     * object may be still live, but deleted --- because it is live in
     * the library, but deleted in the target program.
     */
    OBJ_DEL = 1 << 5,
} obj_flags_t;

/**
 * True if the object is valid; false otherwise.
 */
#define OBJVALID(obj) ((obj)->obj_flags & OBJ_VALID)
/**
 * True if the object is dirty; false otherwise.
 */
#define OBJDIRTY(obj) ((obj)->obj_flags & OBJ_DIRTY)
/**
 * True if the object is live; false otherwise.
 */
#define OBJLIVE(obj) ((obj)->obj_flags & OBJ_LIVE)
/**
 * True if the object is new; false otherwise.
 */
#define OBJNEW(obj) ((obj)->obj_flags & OBJ_NEW)
/**
 * True if the object is modified; false otherwise.
 */
#define OBJMOD(obj) ((obj)->obj_flags & OBJ_MOD)
/**
 * True if the object is deleted; false otherwise.
 */
#define OBJDEL(obj) ((obj)->obj_flags & OBJ_DEL)

/**
 * Mark the object as valid.  Not propagated to children.
 */
#define OBJSVALID(obj) \
    ((obj)->obj_flags |= OBJ_VALID)
/**
 * Mark the object as not valid.  Not propagated to children.
 */
#define OBJSINVALID(obj) \
    (obj)->obj_flags &= ~OBJ_VALID
/**
 * Mark the object as dirty.  Not propagated to children.
 */
#define OBJSDIRTY(obj) \
    ((obj)->obj_flags |= OBJ_DIRTY)
/**
 * Mark the object as not dirty (clean).  Not propagated to children.
 */
#define OBJSCLEAN(obj) \
    (obj)->obj_flags &= ~OBJ_DIRTY
/**
 * Mark the object as live.  This is propagated to children.
 */
#define OBJSLIVE(obj,type) \
    (obj)->obj_flags |= OBJ_LIVE ; type ## _obj_flags_propagate(obj,OBJ_LIVE,0)
/**
 * Mark the object as dead -- this also unsets the new and mod bits.
 * This is propagated to children.
 */
#define OBJSDEAD(obj,type) \
    (obj)->obj_flags &= ~(OBJ_LIVE | OBJ_NEW | OBJ_MOD) ; type ## _obj_flags_propagate(obj,0,OBJ_DEL)

/**
 * Mark the object as new (and live).  Not propagated to children.
 */
#define OBJSNEW(obj) ((obj)->obj_flags |= (OBJ_NEW | OBJ_LIVE))
/**
 * Mark the object as modified (and live).  Not propagated to children.
 */
#define OBJSMOD(obj) ((obj)->obj_flags |= (OBJ_MOD | OBJ_LIVE))
/**
 * Mark the object as deleted.  Not propagated to children.
 */
#define OBJSDEL(obj) ((obj)->obj_flags |= OBJ_DEL)
/**
 * Clear the new, mod, and del bits -- but *not* the liveness bit!  Not
 * propagated to children.
 */
#define OBJSCLEAR(obj) ((obj)->obj_flags &= OBJ_LIVE)

#endif /* __OBJECT_H__ */
