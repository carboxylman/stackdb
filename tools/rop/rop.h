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

#ifndef __ROP_H__
#define __ROP_H__

#include <glib.h>
#include "common.h"
#include "target_api.h"
#include "probe_api.h"

struct rop_gadget {
    ADDR start;
    ADDR end;
    char *meta;
};

struct rop_checkret_status {
    uint8_t ingadget:1,
	    isviolation:1,
	    isfpviolation:1,
	    isjmpfpviolation:1,
	    isjccfpviolation:1;
    uint16_t violations;
    uint16_t fpviolations;
    uint16_t jmpfpviolations;
    uint16_t jccfpviolations;
    uint16_t total;
    ADDR current_ret_addr;
};

typedef enum {
    /*
     * Starts at start of real instr, and ends at end of real instr.
     * This means the entry/exit probes are always in place, never get
     * removed, and are always hit whether the gadget is validly used or
     * not.
     */
    GADGET_TYPE_REAL = 1,
    /*
     * Starts in middle of real instr, and ends at end of real instr.
     * This means that we need a guard probe on the real instruction
     * that includes the gadget's first instruction, so that we can
     * remove the entry probe until we have executed the real
     * instruction.  Once we have done so, we put both the guard probe
     * and entry probe back in.
     */
    GADGET_TYPE_MID_REAL,
    /*
     * Starts in the middle of a real instr, and ends in the middle of a
     * real instr.
     *
     * This means that we need a guard probe on the real instr
     * containing the gadget's first instr, so that we can remove the
     * entry point.  Initially, the gadget exit probe will NOT be
     * inserted.  If the gadget entry probe is inserted, we'll insert
     * the gadget exit probe; otherwise we won't!
     */
    GADGET_TYPE_MID_MID,
} rop_gadget_t;

struct rop_checkret_data {
    rop_gadget_t type;
    ADDR cont_start;

    struct rop_gadget *gadget;

    /* 
     * If the rop gadget is not aligned with the rest of the text, this
     * is the probe that guards the first instruction before the
     * gadget.
     */
    struct probe *cont_probe;
    /* The probe on the gadget's first instruction. */
    struct probe *entry_probe;
    /* The probe on the gadget's RET instruction. */
    struct probe *ret_probe;

    /* The high-level probe. */
    struct probe *rop_probe;

    /* Status of the high-level probe. */
    struct rop_checkret_status status;
};

GHashTable *rop_load_gadget_file(char *filename);
GHashTable *rop_load_gadget_stream(FILE *stream);
struct probe *probe_rop_checkret(struct target *target,tid_t tid,
				 struct rop_gadget *rg,
				 probe_handler_t pre_handler,
				 probe_handler_t post_handler,
				 void *handler_data);

#endif
