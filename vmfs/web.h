#ifndef _WEB_H
#define _WEB_H

#define STATS_MAX (128)
#define QUERY_MAX (256)
#define EVENT_TAG ("VMI")

int web_init(void);
int web_report(const char *msg);

extern char conf_statsserver[];
extern char conf_querykey[];

#endif /* _REPORT_H */
