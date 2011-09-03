#include <stdio.h>
#include <string.h>
#include <limits.h>

FILE* logfile;
char conf_logfile[PATH_MAX];

int log_init(void)
{
    if (strlen(conf_logfile) == 0)
        return -1;

    logfile = fopen(conf_logfile, "a");
    if (!logfile)
        return -1;
	
	printf("Log file at \"%s\"\n", conf_logfile);
    return 0;
}

void log_cleanup(void)
{
    if (logfile)
        fclose(logfile);
}
