#ifndef _PROCESS_LIST_H
#define _PROCESS_LIST_H

#include "list.h"

#define PROCESS_NAME_MAX (128)
#define CONF_FILE_NAME   ("process-list.conf")

struct process {
    struct list_head list;
    int pid;
    char name[PROCESS_NAME_MAX];
};

int conf_handler(void* user,
                 const char* section,
                 const char* name,
                 const char* value);

int predict_ksyms(char *ksyms, const char *sysmap);

#endif /* _PROCESS_LIST_H */
