#ifndef _OFFSET_H
#define _OFFSET_H

int offset_task_struct(int *tasks_offset,
                       int *name_offset,
                       int *pid_offset,
                       const char *fsym);

extern char conf_sysmap[];
extern char conf_debuginfo[];

#endif /* _OFFSET_H */
