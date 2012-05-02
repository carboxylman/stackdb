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

/*
 *  examples/context-aware-probes/private.h
 * 
 *  Private helper functions that simpify the main workflow of 
 *  context-aware probes.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#ifndef __CTXPROBES_PRIVATE_H__
#define __CTXPROBES_PRIVATE_H__

#define THREAD_SIZE (8192)
#define current_thread_ptr(esp) ((esp) & ~(THREAD_SIZE - 1))

struct pt_regs {
    long ebx;
    long ecx;
    long edx;
    long esi;
    long edi;
    long ebp;
    long eax;
    int  xds;
    int  xes; 
    long orig_eax;
    long eip;
    int  xcs;
    long eflags;
    long esp;
    int  xss;
};

int register_call_probe(char *symbol, 
                        probe_handler_t handler,
                        struct probe_ops *ops,
                        probepoint_whence_t whence,
                        symbol_type_flag_t ftype,
                        void *data);

int register_prologue_probe(char *symbol, 
                            probe_handler_t handler,
                            struct probe_ops *ops,
                            probepoint_whence_t whence,
                            symbol_type_flag_t ftype,
                            void *data);

int register_return_probe(char *symbol, 
                          probe_handler_t handler,
                          struct probe_ops *ops,
                          probepoint_whence_t whence,
                          symbol_type_flag_t ftype,
                          void *data);

int register_var_probe(char *symbol,
                       probe_handler_t handler,
                       struct probe_ops *ops,
                       probepoint_whence_t whence,
                       symbol_type_flag_t ftype,
                       void *data);

int register_raw_probe(unsigned long addr, 
                       char *name,
                       probe_handler_t handler,
                       probepoint_whence_t whence,
                       void *data);

void unregister_probes();

unsigned long sysmap_symbol_addr(char *symbol);

unsigned long current_task_addr(void);
int load_task_info(ctxprobes_task_t **task, unsigned long task_struct_addr);
void unload_task_info(ctxprobes_task_t *task);

char *context_string(ctxprobes_context_t context);


int load_func_args(ctxprobes_var_t **arg_list, 
                   int *arg_count, 
                   struct probe *probe);
void unload_func_args(ctxprobes_var_t *arg_list, int arg_count);
int load_func_retval(ctxprobes_var_t **retval, struct probe *probe);
void unload_func_retval(ctxprobes_var_t *retval);

#endif /* __CTXPROBES_PRIVATE_H__  */
