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
 * Foundation, 51 Franklin St, Suite 500, Boston, MA 02110-1335, USA.
 *
 *  examples/context-aware-probes/ctxprobes.h
 *
 *  Probes aware of guest's context changes -- task switches, traps, 
 *  and interrupts.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#ifndef __CTXPROBES_H__
#define __CTXPROBES_H__

typedef enum {
    CTXPROBES_CONTEXT_NORMAL,
    CTXPROBES_CONTEXT_TRAP,
    CTXPROBES_CONTEXT_INTERRUPT 
} ctxprobes_context_t;

typedef struct ctxprobes_var {
    char *name;
    int size;
    char *buf;
} ctxprobes_var_t;

typedef struct ctxprobes_task {
    unsigned long vaddr; /* virtual address of the task_struct */
    unsigned int pid;
    unsigned int tgid;
    unsigned int uid, euid, suid, fsuid;
    unsigned int gid, egid, sgid, fsgid;
    char *comm;
    struct ctxprobes_task *parent;
    struct ctxprobes_task *real_parent;
} ctxprobes_task_t;

typedef void (*ctxprobes_func_prologue_handler_t)(char *symbol,
                                                  unsigned long retaddr,
                                                  ctxprobes_task_t *task,
                                                  ctxprobes_context_t context);

typedef void (*ctxprobes_func_call_handler_t)(char *symbol,
                                              ctxprobes_var_t *arg_list,
                                              int arg_count,
                                              ctxprobes_task_t *task,
                                              ctxprobes_context_t context);

typedef void (*ctxprobes_func_return_handler_t)(char *symbol,
                                                ctxprobes_var_t *arg_list, 
                                                int arg_count,
                                                ctxprobes_var_t *retval,
                                                unsigned long retaddr,
                                                ctxprobes_task_t *task,
                                                ctxprobes_context_t context);

//typedef void (*ctxprobes_var_handler_t)(char *symbol,
//                                        ctxprobes_var_t *var,
//                                        ctxprobes_task_t *task,
//                                        ctxprobes_context_t context);


int ctxprobes_init(char *domain_name, 
                   char *sysmap_file, 
                   int debug_level);
void ctxprobes_cleanup(void);

int ctxprobes_wait(void);

int ctxprobes_reg_func_call(char *symbol,
                            ctxprobes_func_call_handler_t handler);
int ctxprobes_reg_func_prologue(char *symbol,
                                ctxprobes_func_prologue_handler_t handler);
int ctxprobes_reg_func_return(char *symbol,
                              ctxprobes_func_return_handler_t handler);
//int ctxprobes_reg_var(char *symbol,
//                      ctxprobes_var_handler_t handler);

void ctxprobes_unreg_func_call(char *symbol,
                               ctxprobes_func_call_handler_t handler);
void ctxprobes_unreg_func_prologue(char *symbol,
                                   ctxprobes_func_prologue_handler_t handler);
void ctxprobes_unreg_func_return(char *symbol,
                                 ctxprobes_func_return_handler_t handler);
//void ctxprobes_unreg_var(char *symbol,
//                         ctxprobes_var_handler_t handler);

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL

unsigned long long ctxprobes_get_rdtsc(void);

unsigned long long ctxprobes_get_brctr(void);

#endif /* CONFIG_DETERMINISTIC_TIMETRAVEL */

#endif /* __CTXPROBES_H__ */
