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
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _OFFSET_H
#define _OFFSET_H

int offset_task_struct(int *tasks_offset,
                       int *name_offset,
                       int *pid_offset,
                       int *files_offset,
                       const char *fsym);
int offset_files_struct(int *fdt_offset, const char *fsym);
int offset_fdtable(int *max_fds_offset, int *fd_offset, const char *fsym);
int offset_file(int *f_dentry_offset, int *f_vfsmnt_offset, const char *fsym);
int offset_dentry(int *d_parent_offset, int *d_name_offset, const char *fsym);
int offset_vfsmount(int *mnt_devname_offset, const char *fsym);
int offset_qstr(int *len_offset, int *name_offset, const char *fsym);

extern char conf_sysmap[];
extern char conf_debuginfo[];

#endif /* _OFFSET_H */
