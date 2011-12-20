#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>

#include "libdwdebug.h"

extern char *optarg;
extern int optind, opterr, optopt;

int main(int argc,char **argv) {
    int pid = -1;
    char *exe = NULL;
    struct target *t;
    char ch;
    int debug = 0;
    target_status_t tstat;
    unsigned long long addr = 0;
    int value;

    while ((ch = getopt(argc, argv, "p:e:dv:")) != -1) {
	switch(ch) {
	case 'd':
	    ++debug;
	    break;
	case 'p':
	    pid = atoi(optarg);
	    break;
	case 'e':
	    exe = optarg;
	    break;
	case 'v':
	    addr = strtoll(optarg,NULL,16);
	    break;
	default:
	    fprintf(stderr,"ERROR: unknown option %c!\n",ch);
	    exit(-1);
	}
    }

    libdwdebug_init();

    libdwdebug_set_debug_level(debug);

    if ((pid == -1 && exe == NULL)
	|| (pid != -1 && exe != NULL)) {
	fprintf(stderr,"ERROR: must specify either '-p <pid>' or '-e /path/to/executable!\n");
	exit(-2);
    }

    if (pid > 0) {
	t = linux_userproc_attach(pid);
	if (!t) {
	    fprintf(stderr,"could not attach to pid %d!\n",pid);
	    exit(-3);
	}
    }
    else {
	t = linux_userproc_launch(exe,NULL,NULL);
	if (!t) {
	    fprintf(stderr,"could not launch exe %s!\n",exe);
	    exit(-3);
	}
    }

    if (target_open(t)) {
	fprintf(stderr,"could not open pid %d!\n",pid);
	exit(-4);
    }

    while (1) {
	tstat = target_monitor(t);
	if (tstat == STATUS_PAUSED) {
	    printf("pid %d interrupted",pid);
	    if (addr) {
		if (target_read_addr(t,addr,sizeof(int),
				     (unsigned char *)&value) != NULL)
		    printf(": value %d\n",value);
		else
		    printf(": could not read value: %s\n",strerror(errno));
	    }
	    else 
		printf(".\n");

	    if (target_resume(t)) {
		fprintf(stderr,"could not resume target pid %d\n",pid);
		target_close(t);
		exit(-16);
	    }
	}
	else {
	    target_close(t);
	    if (tstat == STATUS_DONE)  {
		printf("pid %d finished.\n",pid);
		break;
	    }
	    else if (tstat == STATUS_ERROR) {
		printf("pid %d monitoring failed!\n",pid);
		return -9;
	    }
	    else {
		printf("pid %d monitoring failed with %d!\n",pid,tstat);
		return -10;
	    }
	}
    }

    return 0;
}
