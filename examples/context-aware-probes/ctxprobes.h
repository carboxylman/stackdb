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

typedef struct var {
    char *name;
	int size;
	char *buf;
} var_t;

typedef void (*ctxprobes_func_call_handler_t)(var_t *arg_list,
                                              int arg_count);

typedef void (*ctxprobes_func_return_handler_t)(var_t *arg_list, 
                                                int arg_count,
                                                var_t retval);

//typedef void (*ctxprobes_var_handler_t)(var_t *var);


int ctxprobes_init(char *domain_name, int debug_level);

void ctxprobes_cleanup(void);

int ctxprobes_wait(void);


int ctxprobes_func_call(char *symbol,
                        ctxprobes_func_call_handler_t handler);

int ctxprobes_func_return(char *symbol,
                          ctxprobes_func_return_handler_t handler);

//int ctxprobes_var(char *symbol,
//                  ctxprobes_var_handler_t handler);

#endif /* __CTXPROBES_H__ */
