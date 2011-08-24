#ifndef _TASK_OFFSET_H
#define _TASK_OFFSET_H

int get_task_offsets(int *tasks_offset,
                     int *name_offset,
                     int *pid_offset,
                     const char *fsym);

#endif /* _TASK_OFFSET_H */
