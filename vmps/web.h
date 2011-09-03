#ifndef _WEB_H
#define _WEB_H

int web_init(void);
int web_report(const char *msg);

extern char conf_statsserver[];
extern char conf_querykey[];

#endif /* _REPORT_H */
