#ifndef _REPORT_H
#define _REPORT_H

int init_stats(void);
int report_event(const char *msg);

extern char opt_statsserver[];
extern char opt_querykey[];

#endif /* _REPORT_H */
