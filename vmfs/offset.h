#ifndef _OFFSET_H
#define _OFFSET_H

int get_task_offsets(int *tasks_offset,
                     int *name_offset,
                     int *pid_offset,
                     int *files_offset,
                     const char *fsym);

int get_files_offsets(int *fdt_offset, const char *fsym);

int get_fdt_offsets(int *max_fds_offset, int *fd_offset, const char *fsym);

int get_fd_offsets(int *f_dentry_offset, 
                   int *f_vfsmnt_offset, 
                   const char *fsym);

int get_dentry_offsets(int *d_parent_offset, 
                       int *d_name_offset, 
                       const char *fsym);

int get_vfsmnt_offsets(int *mnt_devname_offset, const char *fsym);

int get_qstr_offsets(int *len_offset, int *name_offset, const char *fsym);

#endif /* _OFFSET_H */
