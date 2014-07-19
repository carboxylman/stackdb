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

#ifndef __TARGET_GDB_RSP_H__
#define __TARGET_GDB_RSP_H__

#include "config.h"

#include "common.h"
#include "regcache.h"
#include "target_gdb.h"

typedef enum {
    GDB_UNKNOWN = 0,
    GDB_PACKET = 1 << 0,
    GDB_NOTIFICATION = 1 << 1,
    GDB_ACK = 1 << 2,
    GDB_NAK = 1 << 3,
    GDB_INTERRUPT = 1 << 4,
} gdb_ptype_t;

/*
 * This allows a multi-packet command-response pattern.  If the handler
 * returns -1, there was an error.  If the handler returns 1, it means
 * it expects more packets.  If the handler returns 0, it has reached
 * the end of its sequence.  If it returns 2, it could not interpret the
 * message as the proper response to its command (then the default
 * handler will try to handle it).
 */
typedef enum {
    GDB_RSP_HANDLER_ERR  = -1,
    GDB_RSP_HANDLER_DONE = 0,
    GDB_RSP_HANDLER_MORE = 1,
    GDB_RSP_HANDLER_NOTMINE = 2,
} gdb_rsp_handler_ret_t;

typedef gdb_rsp_handler_ret_t (*gdb_rsp_handler_t)(struct target *target,
						   char *data,unsigned int len,
						   void *handler_data);
typedef enum {
    GDB_RSP_STOP_UNKNOWN = -1,
    GDB_RSP_STOP_NONE = 0,
    GDB_RSP_STOP_SIGNAL = 1,
    GDB_RSP_STOP_WATCH = 2,
    GDB_RSP_STOP_RWATCH = 3,
    GDB_RSP_STOP_AWATCH = 4,
    GDB_RSP_STOP_LIBRARY = 5,
    GDB_RSP_STOP_REPLAYLOG = 6,
    GDB_RSP_STOP_EXITED = 7,
    GDB_RSP_STOP_TERMINATED = 8,
    /*
     * NB: we don't bother supporting this "stop status"... sigh.
     */
    /* GDB_RSP_STOP_CONSOLE_OUTPUT = 9, */
} gdb_rsp_stop_reason_t;

struct gdb_rsp_stop_status {
    uint8_t has_pid:1,
	    has_tid:1,
	    has_core:1;
    gdb_rsp_stop_reason_t reason;
    unsigned long signal;
    long int pid;
    long int tid;
    unsigned long core;
    unsigned long exit_status;
    ADDR addr;
    /*
     * NB: right now, we don't bother to read any register values it
     * sends us.
     */
};

typedef enum {
    GDB_RSP_BREAK_SW = 0,
    GDB_RSP_BREAK_HW = 1,
    GDB_RSP_BREAK_WATCH = 2,
    GDB_RSP_BREAK_RWATCH = 3,
    GDB_RSP_BREAK_AWATCH = 4,
} gdb_rsp_break_t;

/*
 * Prototypes.
 */
int gdb_rsp_connect(struct target *target);
int gdb_rsp_close(struct target *target);
int gdb_rsp_recv(struct target *target,int blocking,int only_one,
		 gdb_ptype_t *ptype);
int gdb_rsp_recv_until_handled(struct target *target,
			       gdb_rsp_handler_t handler,
			       gdb_rsp_handler_ret_t *handler_ret);

int gdb_rsp_interrupt(struct target *target);
int gdb_rsp_ack(struct target *target);
int gdb_rsp_nak(struct target *target);
int gdb_rsp_send_packet(struct target *target,
			char *data,unsigned int len,
			gdb_rsp_handler_t handler,void *handler_data);
//int gdb_rsp_send_notification(struct target *target,
//				char *data,unsigned int len);

target_status_t gdb_rsp_load_status(struct target *target);

int gdb_rsp_pause(struct target *target);
int gdb_rsp_resume(struct target *target);
int gdb_rsp_step(struct target *target);

int gdb_rsp_read_regs(struct target *target,struct regcache *regcache);
int gdb_rsp_write_regs(struct target *target,struct regcache *regcache);

/* Memory access.  Only virtual addresses. */
struct gdb_rsp_read_mem_data {
    char *buf;
    unsigned long length;
    int error;
};
int gdb_rsp_read_mem(struct target *target,ADDR addr,
		     unsigned long length,unsigned char *buf);
int gdb_rsp_write_mem(struct target *target,ADDR addr,
		      unsigned long length,unsigned char *buf);

int gdb_rsp_insert_break(struct target *target,ADDR addr,
			 gdb_rsp_break_t bt,int kind);
int gdb_rsp_remove_break(struct target *target,ADDR addr,
			 gdb_rsp_break_t bt,int kind);

#endif /* __TARGET_GDB_RSP_H__ */
