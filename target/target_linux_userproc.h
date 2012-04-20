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
 */

#ifndef __TARGET_LINUX_USERPROC_H__
#define __TARGET_LINUX_USERPROC_H__

#include "target_api.h"

/* linux userproc target ops */
/*
 * Attaches to @pid, a current process id.  @dfoptlist is a
 * NULL-terminated list of debugfile_load_opts structs (ideally parsed
 * from debugfile_load_opts_parse if you're coming from the command
 * line).
 */
struct target *linux_userproc_attach(int pid,
				     struct debugfile_load_opts **dfoptlist);
/*
 * Executes @filename with the given @argv and @envp NULL-terminated
 * lists.  If @keepstdin is set, we don't close it before the call to
 * exec in the child.  If @outfile and/or @errfile are set, those files
 * are opened and the standard file descriptors for the child process
 * are redirected appropriately (you cannot use the same filename for
 * both!).  @dfoptlist is a NULL-terminated list of debugfile_load_opts
 * structs (ideally parsed from debugfile_load_opts_parse if you're
 * coming from the command line).
 */
struct target *linux_userproc_launch(char *filename,char **argv,char **envp,
				     int keepstdin,char *outfile,char *errfile,
				     struct debugfile_load_opts **dfoptlist);
int linux_userproc_last_signo(struct target *target);
int linux_userproc_stopped_by_syscall(struct target *target);

#endif /* __TARGET_LINUX_USERPROC_H__ */
