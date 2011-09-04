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
