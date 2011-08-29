#ifndef _PROCESS_LIST_H
#define _PROCESS_LIST_H

#include "list.h"

#define PROCESS_NAME_MAX (128)

struct process {
    struct list_head list;
    int pid;
    char name[PROCESS_NAME_MAX];
};

int predict_ksyms(char *ksyms, const char *sysmap);

#endif /* _PROCESS_LIST_H */
