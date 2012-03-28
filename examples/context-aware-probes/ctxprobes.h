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
 *  ctxprobes/ctxprobes.h
 *
 *  Probes aware of guest's context changes -- task switches, traps, 
 *  and interrupts.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#ifndef __CTXPROBES_H__
#define __CTXPROBES_H__

typedef void (*ctxprobes_function_call_handler_t)(void);
typedef void (*ctxprobes_function_return_handler_t)(void);
typedef void (*ctxprobes_variable_handler_t)(void);


int ctxprobes_init(char *domain_name, int debug_level);
void ctxprobes_cleanup(void);
int ctxprobes_wait(void);


int ctxprobes_function_call(char *symbol,
                            ctxprobes_function_call_handler_t handler);

int ctxprobes_function_return(char *symbol,
                              ctxprobes_function_return_handler_t handler);

int ctxprobes_variable(char *symbol,
                       ctxprobes_variable_handler_t handler);

#endif /* __CTXPROBES_H__ */
