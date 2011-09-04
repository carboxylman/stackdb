#ifndef _LOG_H
#define _LOG_H

int log_init(void);
void log_cleanup(void);

extern FILE* logfile;
extern char conf_logfile[];

#endif /* _LOG_H */
