/*
 * XXX try to create (must more verbose) output compatible with the old
 * version for comparison.
 */
//#define OLD_VPG_COMPAT

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <regex.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <netdb.h>
#include <signal.h>

#include "vmprobes.h"
#include "list.h"

#define ARG_STRING_LEN	1024
#define ARG_BYTES_LEN	1024

static int debug = -1;

typedef enum {
    SC_ARG_TYPE_INT = 0,
    SC_ARG_TYPE_PT_REGS,
    SC_ARG_TYPE_STRING,
    SC_ARG_TYPE_BYTES,
    SC_ARG_TYPE_SIZE_T,
    SC_ARG_TYPE_UINT,
    SC_ARG_TYPE_PID_T,
    SC_ARG_TYPE_OFF_T,
    SC_ARG_TYPE_TIME_T,
    SC_ARG_TYPE_LONG,
    SC_ARG_TYPE_ULONG,
    SC_ARG_TYPE_UID_T,
    SC_ARG_TYPE_GID_T,
    SC_ARG_TYPE_PTR,
    SC_ARG_TYPE_TIMEVAL,
    SC_ARG_TYPE_TIMEZONE,
    SC_ARG_TYPE_ITIMERVAL,
    SC_ARG_TYPE_TIMESPEC,
    SC_ARG_TYPE_SIGSET_T,
    SC_ARG_TYPE_SIGINFO_T,
    SC_ARG_TYPE_HEXINT,		/* for ints to display in hex */
    SC_ARG_TYPE__MAX__,
} sc_arg_type_t;

struct argdata;
struct argfilter;
struct process_data;

typedef void *(argloader_t)(vmprobe_handle_t,struct cpu_user_regs *,
			    int,int,int,unsigned long,
			    struct argdata **argdata,
			    struct process_data *data);
typedef void (argdecoder_t)(vmprobe_handle_t,struct cpu_user_regs *,
			    int,int,int,
			    struct argdata **argdata,
			    struct process_data *data);

struct syscall_arg_info {
    int num;
    char *name;
    sc_arg_type_t type;
    argdecoder_t *ad;
    char **decodings;
    int decodings_len;
    argloader_t *al;
    int len_arg_num;
};

struct syscall_info {
    int num;
    char *name;
    unsigned long addr;
    unsigned long raddr;
    int argc;
    struct syscall_arg_info args[6];
    vmprobe_handle_t vp;
};

#define WHEN_PRE	0
#define WHEN_POST	1

struct argfilter {
    int dofilter;
    int when;
    int syscallnum;
    int pid;
    int ppid;
    int ppid_search;
    int uid;
    int gid;

    int argnum;
    int decoding;
    regex_t *preg;
    char *strfrag;

    int retval;
    regex_t *ret_preg;
    char *ret_strfrag;

    int abort_retval;
    char *name;
    int name_search;
    int index;
};

void free_argfilter(struct argfilter *f) {
    if (f->preg) {
	regfree(f->preg);
	free(f->preg);
    }
    if (f->strfrag)
	free(f->strfrag);
    if (f->ret_preg) {
	regfree(f->ret_preg);
	free(f->ret_preg);
    }
    if (f->ret_strfrag)
	free(f->ret_strfrag);
    if (f->name)
	free(f->name);
    free(f);
}

struct argdata {
    struct syscall_arg_info *info;
    unsigned char *data;
    char *str;
    char **decodings;
    int postcall;
};

void free_argdata(struct argdata *d) {
    int i;

    if (d->data) {
	if (d->data == (unsigned char *)d->str)
	    d->str = NULL;
	free(d->data);
    }
    if (d->str)
	free(d->str);
    if (d->info->decodings_len) {
	if (d->decodings) {
	    for (i = 0; i < d->info->decodings_len; ++i)
		if (d->decodings[i])
		    free(d->decodings[i]);
	    free(d->decodings);
	}
    }
    free(d);
}

void load_arg_data(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		   int pid,int i,int j,
		   struct argdata **arg_data,
		   struct process_data *data);

#define STATIC_RET_PROBE

/*
 * Indentifies "outstanding" syscall returns.
 *
 * One of these structs exists for every thread that has taken a syscall
 * for which we want to stop afterward. This record identifies which
 * syscall is in progress and the values of argument related registers.
 */
struct syscall_retinfo {
    unsigned long thread_ptr;
    int syscall_ix;
    unsigned long arg0;
    unsigned long arg1;
    unsigned long argptr;

    struct list_head list;
};
LIST_HEAD(syscalls);

struct process_data {
    unsigned int pid;
    int ppid;
    int real_ppid;
    unsigned int tgid;
    unsigned int uid;
    unsigned int euid;
    unsigned int suid;
    unsigned int fsuid;
    unsigned int gid;
    unsigned int egid;
    unsigned int sgid;
    unsigned int fsgid;
    struct process_data *parent;
    struct process_data *real_parent;
    char *name;
    unsigned long nextptr;

    struct list_head list;
};

void usage(char *progname) {
    fprintf(stderr,
	    "Usage: %s \n"
	    "          [-m <sysmapfile>]\n"
	    "          [-s sys_foo,sys_bar,...]\n"
	    "          [-f <filter_expr>]\n"
	    "          [-a [-w addr:port]]\n"
	    "          [-R <logfile>]\n"
	    "          <domain-name|dom-id>\n\n"
	    "  -m  The Sysmap file for the guest's kernel.\n"
	    "  -s  A comma-separated list of syscalls to probe.\n"
	    "  -f  A syscall return filter.\n"
	    "  -a  Report events to A3 controller.\n"
	    "  -w  IP:port of A3 controller.\n"
	    "  -R  Save A3 events in time-stamped <logfile>.\n"
	    "",
	    progname);
    exit(-1);
}

char *ssprintf(char *format,...) {
    va_list args;
    char _buf[128], *buf, *tbuf;
    int bufsiz, rc;

    va_start(args,format);

    /* try once with static buf */
    buf = _buf;
    bufsiz = sizeof _buf;
    rc = vsnprintf(buf, bufsiz, format, args);

    /* that didn't work, build a dynamic buffer */
    if (rc >= bufsiz) {
	/* don't screw around, just git er done */
	bufsiz = 1024;

	while (1) {
	    buf = malloc(bufsiz);
	    if (buf == NULL)
		return NULL;
	    rc = vsnprintf(buf, bufsiz, format, args);
	    if (rc < bufsiz)
		break;
	    free(buf);
	    bufsiz += 1024;
	}
    }

    /* copy to a comfy-sized buffer */
    bufsiz = strlen(buf) + 1;
    tbuf = malloc(bufsiz);
    memcpy(tbuf, buf, bufsiz);
    if (buf != _buf)
	free(buf);

    va_end(args);

    return tbuf;
}

void string_append(char **buf,int *bufsiz,char **endptr,char *str) {
    char *tbuf;
    int len;
    int oldlen;
    int remaining;

    if (!str)
	return;

    len = strlen(str);
    if (!*buf) {
	debug(1,"alloc'ing %d init bytes\n",len+80);
	*bufsiz = len + 80;
	*buf = malloc(sizeof(char) * *bufsiz);
	*endptr = *buf;
    }
    oldlen = *endptr - *buf;
    remaining = *bufsiz - oldlen;

    if ((len+1) > remaining) {
	debug(1,"expanding buf by %d bytes\n",len+80);
	tbuf = malloc(sizeof(char)*(*bufsiz + len + 80));
	memcpy(tbuf,*buf,*bufsiz);
	free(*buf);
	*buf = tbuf;
	*bufsiz = *bufsiz + len + 80;
	*endptr = tbuf + oldlen;
    }

    memcpy(*endptr,str,len);
    debug(1,"copied\n");
    (*endptr)[len] = '\0';
    debug(1,"terminated\n");
    *endptr = *endptr + len;
    debug(1,"endptr updated\n");

    return;
}

extern char *optarg;
extern int optind, opterr, optopt;

struct argfilter **argfilter_list;
int argfilter_list_len = 0;
int argfilter_list_alloclen = 10;
char **ps_list = NULL;
int ps_list_len = 0;

int check_filters(int syscall,int arg,
		  struct argdata **adata,
		  struct process_data *pdata,
		  char *retvalstr,
		  struct argfilter **match, int *needpost)
{
    int pmatch = 0;
    int rmatch = 0;
    int smatch = 0;
    int lpc;
    struct process_data *parent;
    char *argval = NULL;
    int postcall = (retvalstr != NULL);

    for (lpc = 0; lpc < argfilter_list_len; ++lpc) {
	debug(1,"filter name=%s, process name=%s, "
	      "filter-syscall=%d, syscall=%d, "
	      "filter-when=%s, when=%s\n",
	      argfilter_list[lpc]->name,pdata->name,
	      argfilter_list[lpc]->syscallnum,syscall,
	      argfilter_list[lpc]->when == WHEN_PRE ? "pre" : "post",
	      postcall ? "post" : "pre");

	/*
	 * If we are post-syscall, only match post-syscall filters.
	 */
	if (postcall && argfilter_list[lpc]->when != WHEN_POST)
	    continue;

	/*
	 * If we are called pre-syscall, we make a note of any post
	 * syscall filter for this syscall so that our caller
	 * will know that it needs to schedule the post-syscall probe.
	 */
	if (!postcall && argfilter_list[lpc]->when == WHEN_POST) {
	    if (argfilter_list[lpc]->syscallnum == -1 ||
		argfilter_list[lpc]->syscallnum == syscall)
		*needpost = 1;
	    continue;
	}

	if ((argfilter_list[lpc]->syscallnum == -1 || argfilter_list[lpc]->syscallnum == syscall)
	    && (argfilter_list[lpc]->argnum == -1 ||
		argfilter_list[lpc]->argnum == arg)) {
	    smatch = 1;
	}

	if (smatch) {
	    if (argfilter_list[lpc]->decoding > -1 && adata[arg]->decodings)
		argval = adata[arg]->decodings[argfilter_list[lpc]->decoding];
	    else
		argval = adata[arg]->str;
	    if (!argval)
		argval = "";

	    if (argfilter_list[lpc]->preg == NULL
		|| !regexec(argfilter_list[lpc]->preg,argval,0,NULL,0))
		smatch = 1;
	    else
		smatch = 0;
	}

	if (!postcall || argfilter_list[lpc]->retval < 0 ||
	    argfilter_list[lpc]->ret_preg == NULL ||
	    !regexec(argfilter_list[lpc]->ret_preg,retvalstr,0,NULL,0))
	    rmatch = 1;
	else
	    rmatch = 0;

	if ((argfilter_list[lpc]->pid == -1 
	     || argfilter_list[lpc]->pid == pdata->pid)
	    && (argfilter_list[lpc]->gid == -1 
		|| argfilter_list[lpc]->gid == pdata->gid)
	    && (argfilter_list[lpc]->uid == -1 
		|| argfilter_list[lpc]->uid == pdata->uid)) {
	    pmatch = 1;
	}
	if (pmatch && argfilter_list[lpc]->ppid_search) {
	    pmatch = 0;
	    parent = pdata->parent;
	    while (parent) {
		if (parent->pid == argfilter_list[lpc]->ppid) {
		    pmatch = 1;
		    break;
		}
		parent = parent->parent;
	    }
	}
	else if (pmatch 
		 && !(argfilter_list[lpc]->ppid == -1 
		      || argfilter_list[lpc]->ppid == pdata->ppid))
	    pmatch = 0;

	if (pmatch && argfilter_list[lpc]->name_search) {
	    pmatch = 0;
	    parent = pdata->parent;
	    while (parent) {
		if (!strcmp(parent->name,argfilter_list[lpc]->name)) {
		    pmatch = 1;
		    break;
		}
		parent = parent->parent;
	    }
	}
	else if (pmatch 
		 && argfilter_list[lpc]->name != NULL 
		 && strcmp(argfilter_list[lpc]->name,pdata->name))
	    pmatch = 0;

	if (smatch && rmatch && pmatch) {
	    *match = argfilter_list[lpc];
	    debug(1,"Filter match on %d %d(%d) %s %d %s (%d %d %d)\n",
		  argfilter_list[lpc]->syscallnum,
		  argfilter_list[lpc]->argnum,
		  argfilter_list[lpc]->decoding,
		  argfilter_list[lpc]->strfrag,
		  argfilter_list[lpc]->retval,
		  argfilter_list[lpc]->ret_strfrag,
		  argfilter_list[lpc]->pid,argfilter_list[lpc]->uid,
		  argfilter_list[lpc]->gid);
	    break;
	}
	else {
	    debug(1, "Filter no match (%d,%d,%d) on %d %d(%d) %s %d %s (%d %d %d)\n",
		  smatch, rmatch, pmatch,
		  argfilter_list[lpc]->syscallnum,
		  argfilter_list[lpc]->argnum,
		  argfilter_list[lpc]->decoding,
		  argfilter_list[lpc]->strfrag,
		  argfilter_list[lpc]->retval,
		  argfilter_list[lpc]->ret_strfrag,
		  argfilter_list[lpc]->pid,argfilter_list[lpc]->uid,
		  argfilter_list[lpc]->gid);
	    smatch = rmatch = pmatch = 0;
	}
    }

    /*
     * If necessary, finish scanning the list looking for possible
     * post-syscall matches.
     */
    if (!postcall && *needpost == 0) {
	for (++lpc; lpc < argfilter_list_len; ++lpc) {
	    if (argfilter_list[lpc]->when == WHEN_POST &&
		(argfilter_list[lpc]->syscallnum == -1 ||
		 argfilter_list[lpc]->syscallnum == syscall)) {
		*needpost = 1;
		break;
	    }
	}
    }

    return (smatch && pmatch);
}

typedef struct fcntlcmdent {
    int cmd;
    char *name;
} fcntlcmdent_t;

fcntlcmdent_t fcntlcmds[] = {
    { F_DUPFD, "F_DUPFD" },
    { F_GETFD, "F_GETFD" },
    { F_SETFD, "F_SETFD" },
    { F_GETFL, "F_GETFL" },
    { F_SETFL, "F_SETFL" },
    { F_GETLK, "F_GETLK" },
    { F_SETLK, "F_SETLK" },
    { F_SETLKW, "F_SETLKW" },
    { F_GETOWN, "F_GETOWN" },
    { F_SETOWN, "F_SETOWN" },
#ifdef F_GETSIG
    { F_GETSIG, "F_GETSIG" },
#endif
#ifdef F_SETSIG
    { F_SETSIG, "F_SETSIG" },
#endif
#ifdef F_SETLEASE
    { F_SETLEASE, "F_SETLEASE" },
#endif
#ifdef F_GETLEASE
    { F_GETLEASE, "F_GETLEASE" },
#endif
#ifdef F_NOTIFY
    { F_NOTIFY, "F_NOTIFY" },
#endif
};

typedef struct openflagent {
    int flag;
    char *name;
} openflagent_t;

openflagent_t openflags[] = {
    { O_RDONLY, "O_RDONLY" },
    { O_WRONLY, "O_WRONLY" },
    { O_RDWR, "O_RDWR" },
    { O_CREAT, "O_CREAT" },
    { O_EXCL, "O_EXCL" },
    { O_NOCTTY, "O_NOCTTY" },
    { O_TRUNC, "O_TRUNC" },
    { O_APPEND, "O_APPEND" },
    { O_ASYNC, "O_ASYNC" },
#ifdef O_DIRECT
    { O_DIRECT, "O_DIRECT" },
#endif
#ifdef O_DIRECTORY
    { O_DIRECTORY, "O_DIRECTORY" },
#endif
#ifdef O_LARGEFILE
    { O_LARGEFILE, "O_LARGEFILE" },
#endif
#ifdef O_NOATIME
    { O_NOATIME, "O_NOATIME" },
#endif
#ifdef O_NOFOLLOW
    { O_NOFOLLOW, "O_NOFOLLOW" },
#endif
    { O_NONBLOCK, "O_NONBLOCK" },
    { O_NDELAY, "O_NDELAY" },
    { O_SYNC, "O_SYNC" },
    { O_TRUNC, "O_TRUNC" },
};

typedef struct filemodeent {
    int mode;
    char *name;
} filemodeent_t;

filemodeent_t filemodes[] = {
    { S_IRWXU, "S_IRWXU" },
    { S_IRUSR, "S_IRUSR" },
    { S_IWUSR, "S_IWUSR" },
    { S_IXUSR, "S_IXUSR" },
    { S_IRWXG, "S_IRWXG" },
    { S_IRGRP, "S_IRGRP" },
    { S_IWGRP, "S_IWGRP" },
    { S_IXGRP, "S_IXGRP" },
    { S_IRWXO, "S_IRWXO" },
    { S_IROTH, "S_IROTH" },
    { S_IWOTH, "S_IWOTH" },
    { S_IXOTH, "S_IXOTH" },
};

typedef struct ioctlent {
    char *src;
    char *name;
    int num;
} ioctlent_t;

ioctlent_t ioctls[] = {
#include "ioctlent.h"
};

char *signals[] = {
#include "signalent.h"
};

char *socksyscalls[] = {
    "__usused0",
    "socket",
    "bind",
    "connect",
    "listen",
    "accept",
    "getsockname",
    "getpeername",
    "socketpair",
    "send",
    "recv",
    "sendto",
    "recvfrom",
    "shutdown",
    "setsockopt",
    "getsockopt",
    "sendmsg",
    "recvmsg",
};

/* Argument list sizes for sys_socketcall */
#define AL(x) ((x) * sizeof(unsigned long))
static unsigned char socketcall_nargs[18] = \
    {AL(0),AL(3),AL(3),AL(3),AL(2),AL(3),
     AL(3),AL(3),AL(4),AL(4),AL(4),AL(6),
     AL(6),AL(2),AL(5),AL(5),AL(3),AL(3)};

#if 0
struct timeval {
	time_t		tv_sec;		/* seconds */
	suseconds_t	tv_usec;	/* microseconds */
};

struct timezone {
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	/* type of dst correction */
};

struct itimerval {
	struct timeval it_interval;	/* timer interval */
	struct timeval it_value;	/* current value */
};
#endif

#if 0
typedef struct siginfo {
    int si_signo;
    int si_errno;
    int si_code;

    // bunch of junk
    //void *_sifields;
} siginfo_t;
#endif

/* Most things should be clean enough to redefine this at will, if care
   is taken to make libc match.  */

#define L_NSIG		64
#define L_NSIG_BPW	32
#define L_NSIG_WORDS	(L_NSIG / L_NSIG_BPW)

//typedef unsigned long old_sigset_t;		/* at least 32 bits */

typedef struct {
	unsigned long sig[L_NSIG_WORDS];
} vsigset_t;
int k_sigismember(vsigset_t *set, int _sig)
{
    unsigned long sig = _sig - 1;
    return 1 & (set->sig[sig / L_NSIG_BPW] >> (sig % L_NSIG_BPW));
}

void socket_call_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
			 int pid,int syscall,int arg,
			 struct argdata **arg_data,
			 struct process_data *data)
{
    int call = *((int *)(arg_data[arg]->data));

    if (call < sizeof(socksyscalls) / sizeof(char *))
	arg_data[arg]->decodings[0] = strdup(socksyscalls[call]);
    else
	arg_data[arg]->decodings[0] = strdup("unknown");

    return;
}

char *sockaddr2str(struct sockaddr *sa)
{
    char *buf;
    int buflen = 1024;
    int usedlen = 0;
    char tmpbuf[128];

    if (!sa)
	return NULL;

    buf = malloc(sizeof(char)*buflen);

    switch (sa->sa_family) {
    case AF_LOCAL:
    {
	struct sockaddr_un *sun = (struct sockaddr_un *)sa;
	strncpy(tmpbuf, sun->sun_path, sizeof(tmpbuf)-1);
	usedlen = snprintf(buf, buflen, "{.sun_family = AF_UNIX, .sun_path = '%s' }",
			   tmpbuf);
	break;
    }

    case AF_INET:
    {
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	inet_ntop(sa->sa_family,(const void *)&sin->sin_addr,
		  tmpbuf,sizeof(tmpbuf));
	tmpbuf[sizeof(tmpbuf)-1] = '\0';
	usedlen = snprintf(buf,buflen,"{ .sa_family = AF_INET, { .sin_port = %d, .sin_addr = '%s' } }",
			   ntohs(sin->sin_port),tmpbuf);
	buf[buflen - 1] = '\0';
	break;
    }

    case AF_INET6:
    {
	struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa;
	inet_ntop(sa->sa_family,(const void *)&sin->sin6_addr,tmpbuf,sizeof(tmpbuf));
	tmpbuf[sizeof(tmpbuf)-1] = '\0';
	usedlen = snprintf(buf,buflen,"{ .sa_family = AF_INET6, { .sin6_port = %d, .sin6_flowinfo = %u, .sin_addr = '%s', .sin6_scope_id = %u } }",
			   ntohs(sin->sin6_port),sin->sin6_flowinfo,tmpbuf,
			   sin->sin6_scope_id);
	buf[buflen - 1] = '\0';
	break;
    }

    case AF_NETLINK:
    {
	struct sockaddr_nl *snl = (struct sockaddr_nl *)sa;

	usedlen = snprintf(buf,buflen,"{ .nl_family = AF_NETLINK, .nl_pid = %u, .nl_groups = %u }",
			   (unsigned)snl->nl_pid, snl->nl_groups);
	break;
    }

    default:
	snprintf(buf,buflen,"(unsupported family %d)",sa->sa_family);
	break;
    }

    return buf;
}

void socket_args_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
			 int pid,int syscall,int arg,
			 struct argdata **arg_data,
			 struct process_data *data)
{
    unsigned long a[6];
    int call = 0;
    char *sas = NULL, *sasl = NULL;
    char *domainname;
    char *typename;
    struct protoent *proto;
    char *protoname;
    unsigned char *dbuf = NULL;

    call = *((int *)(arg_data[0]->data));

    if (call < 1 || call >= sizeof(socksyscalls) / sizeof(char *)) {
	arg_data[arg]->decodings[0] = strdup("<unknown socket call>");
	return;
    }

    if (arg_data[arg]->data != NULL) {
	dbuf = vmprobe_get_data(handle,regs,"socketcall_args",
				*((unsigned long *)(arg_data[arg]->data)),pid,
				socketcall_nargs[call],NULL);
    }
    if (!dbuf) {
	arg_data[arg]->decodings[0] = strdup("<bad socketcall args>");
	return;
    }

    memcpy(a,(void *)dbuf,socketcall_nargs[call]);
    free(dbuf);

    switch (call) {
    case 2: case 3:
	dbuf = vmprobe_get_data(handle,regs,"socketcall_arg1",a[1],pid,
				sizeof(struct sockaddr_storage),NULL);
	if (dbuf) {
	    sas = sockaddr2str((struct sockaddr *)dbuf);
	    free(dbuf);
	}
	break;
    /* these have a valid sockaddr on exit */
    case 5: case 6: case 7:
	if (arg_data[arg]->postcall) {
	    dbuf = vmprobe_get_data(handle,regs,"socketcall_arg1",a[1],pid,
				    sizeof(struct sockaddr_storage),NULL);
	    if (dbuf) {
		sas = sockaddr2str((struct sockaddr *)dbuf);
		free(dbuf);
	    }
	    dbuf = vmprobe_get_data(handle,regs,"socketcall_arg2",a[2],pid,
				    sizeof(unsigned long),NULL);
	    if (dbuf) {
		sasl = ssprintf("%lu", *(unsigned long *)dbuf);
		free(dbuf);
	    }
	} else {
	    sas = ssprintf("%p", (void *)a[1]);
	    sasl = ssprintf("%p", (void *)a[2]);
	}
	break;
    default:
	break;
    }

    switch (call) {
    case 1:
    case 8:
	switch ((int)a[0]) {
	case AF_UNIX: domainname = "AF_UNIX"; break;
	case AF_INET: domainname = "AF_INET"; break;
	case AF_INET6: domainname = "AF_INET6"; break;
	case AF_IPX: domainname = "AF_IPX"; break;
	case AF_NETLINK: domainname = "AF_NETLINK"; break;
	case AF_X25: domainname = "AF_X25"; break;
	case AF_AX25: domainname = "AF_AX25"; break;
	case AF_PACKET: domainname = "AF_PACKET"; break;
	case AF_ATMSVC: domainname = "AF_ATMSVC"; break;
	case AF_IRDA: domainname = "AF_IRDA"; break;
	case AF_BLUETOOTH: domainname = "AF_BLUETOOTH"; break;
	    //case AF_IEEE802154: domainname = "AF_IEEE802154"; break;
	default:
	    domainname = NULL;
	    break;
	}

	switch ((int)a[1]) {
	case SOCK_STREAM: typename = "SOCK_STREAM"; break;
	case SOCK_DGRAM: typename = "SOCK_DGRAM"; break;
	case SOCK_RAW: typename = "SOCK_RAW"; break;
	case SOCK_RDM: typename = "SOCK_RDM"; break;
	case SOCK_SEQPACKET: typename = "SOCK_SEQPACKET"; break;
	    //case SOCK_DCCP: typename = "SOCK_DCCP"; break;
	case SOCK_PACKET: typename = "SOCK_PACKET"; break;
	default:
	    typename = "unknown";
	    break;
	}

	proto = getprotobynumber((int)a[2]);
	if (!proto)
	    protoname = "unknown";
	else 
	    protoname = proto->p_name;

	if (call == 1) {
	    arg_data[arg]->decodings[0] = ssprintf("family=%s,type=%s,protocol=%s",
						   domainname,typename,protoname);
	    break;
	}

	// do socketpair last arg
	arg_data[arg]->decodings[0] = ssprintf("family=%s,type=%s,protocol=%s,usockvec=%p",
					       domainname,typename,protoname,(void *)a[3]);
	break;
    case 2:
	arg_data[arg]->decodings[0] = ssprintf("fd=%d,umyaddr=%s,addrlen=%d",
					       (int)a[0],sas,(int)a[2]);
	break;
    case 3:
	arg_data[arg]->decodings[0] = ssprintf("fd=%d,uservaddr=%s,addrlen=%d",
					       (int)a[0],sas,(int)a[2]);
	break;
    case 4:
	arg_data[arg]->decodings[0] = ssprintf("fd=%d,backlog=%d",(int)a[0],(int)a[1]);
	break;
    case 5:
	arg_data[arg]->decodings[0] = ssprintf("fd=%d,upeer_sockaddr=%s,upeer_addrlen=%s",
					       (int)a[0],sas,sasl);
	break;
    case 6:
    case 7:
	arg_data[arg]->decodings[0] = ssprintf("fd=%d,usockaddr=%s,usockaddr_len=%s",
					       (int)a[0],sas,sasl);
	break;
    default:
	arg_data[arg]->decodings[0] = strdup("unknown");
	break;
    }

    if (sas)
	free(sas);
    if (sasl)
	free(sasl);

    return;
}

void sigset_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		    int pid,int syscall,int arg,
		    struct argdata **arg_data,
		    struct process_data *data)
{
    vsigset_t *ss = (vsigset_t *)(arg_data[arg]->data);
    int i;
    int done = 0;
    char *buf = NULL;
    int bufsiz;
    char *endptr;

    if (ss == NULL) {
	return;
    }

    for (i = 1; i < sizeof(signals) / sizeof(signals[0]); ++i) {
	if (k_sigismember(ss,i)) {
	    if (done)
		string_append(&buf,&bufsiz,&endptr,"|");
	    else 
		done = 1;

	    string_append(&buf,&bufsiz,&endptr,signals[i]);
	}
    }
    arg_data[arg]->decodings[0] = buf;

    return;
}

void siginfo_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		     int pid,int syscall,int arg,
		     struct argdata **arg_data,
		     struct process_data *data)
{
    siginfo_t *si = (siginfo_t *)(arg_data[arg]->data);

    arg_data[arg]->decodings[0] = ssprintf("{si_signo=%d,si_errno=%d,si_code=%d}",
					   si->si_signo,si->si_errno,si->si_code);

    return;
}

void timespec_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		      int pid,int syscall,int arg,
		      struct argdata **arg_data,
		      struct process_data *data)
{
    struct timespec *tv = (struct timespec *)(arg_data[arg]->data);

    if (!tv) {
	arg_data[arg]->decodings[0] = NULL;
	return;
    }

    arg_data[arg]->decodings[0] = ssprintf("{tv_sec=%ld,tv_nsec=%ld}",
					   tv->tv_sec,tv->tv_nsec);

    return;
}

void timeval_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		     int pid,int syscall,int arg,
		     struct argdata **arg_data,
		     struct process_data *data)
{
    struct timeval *tv = (struct timeval *)(arg_data[arg]->data);

    if (!tv) {
	arg_data[arg]->decodings[0] = NULL;
	return;
    }

    arg_data[arg]->decodings[0] = ssprintf("{tv_sec=%ld,tv_usec=%ld}",
					   tv->tv_sec,tv->tv_usec);

    return;
}

void timezone_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		      int pid,int syscall,int arg,
		      struct argdata **arg_data,
		      struct process_data *data)
{
    struct timezone *tz = (struct timezone *)(arg_data[arg]->data);

    if (!tz) {
	arg_data[arg]->decodings[0] = NULL;
	return;
    }

    arg_data[arg]->decodings[0] = ssprintf("{tz_minuteswest=%d,tz_dsttime=%d}",
					   tz->tz_minuteswest,tz->tz_dsttime);

    return;
}

void itimerval_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		       int pid,int syscall,int arg,
		       struct argdata **arg_data,
		       struct process_data *data)
{
    struct itimerval *itv = (struct itimerval *)(arg_data[arg]->data);

    if (!itv) {
	arg_data[arg]->decodings[0] = NULL;
	return;
    }

    arg_data[arg]->decodings[0] = ssprintf("{it_interval={tv_sec=%ld,tv_usec=%ld},it_value={tv_sec=%ld,tv_usec=%ld}}",
					   itv->it_interval.tv_sec,itv->it_interval.tv_usec,
					   itv->it_value.tv_sec,itv->it_value.tv_usec);

    return;
}

struct pt_regs {
        long ebx;
        long ecx;
        long edx;
        long esi;
        long edi;
        long ebp;
        long eax;
        int  xds;
        int  xes;
        long orig_eax;
        long eip;
        int  xcs;
        long eflags;
        long esp;
        int  xss;
};

int sc_arg_type_len[SC_ARG_TYPE__MAX__] = {
    sizeof(uint32_t),
    sizeof(struct pt_regs),
    0,
    0,
    sizeof(uint32_t),
    sizeof(unsigned int),
    sizeof(uint32_t),
    sizeof(off_t),
    sizeof(uint32_t),
    sizeof(long),
    sizeof(unsigned long),
    sizeof(uint32_t),
    sizeof(uint32_t),
    sizeof(uint32_t),
    sizeof(struct timeval),
    sizeof(struct timezone),
    sizeof(struct itimerval),
    sizeof(struct timespec),
    sizeof(vsigset_t),
    sizeof(siginfo_t),
};

#define THREAD_SIZE 8192
#define current_thread_ptr(esp) ((esp) & ~(THREAD_SIZE - 1))

#define TASK_STRUCT_SIZE 1312
#define TASK_STRUCT_OFFSET 0
#define PID_OFFSET 168
#define TGID_OFFSET 172
#define REAL_PARENT_OFFSET 176
#define PARENT_OFFSET 180
#define UID_OFFSET 336
#define EUID_OFFSET 340
#define SUID_OFFSET 344
#define FSUID_OFFSET 348
#define GID_OFFSET 352
#define EGID_OFFSET 356
#define SGID_OFFSET 360
#define FSGID_OFFSET 364
#define COMM_OFFSET 396
#define TASKS_OFFSET 108

uint32_t init_task_addr = 0;

void print_process_data(vmprobe_handle_t handle,
			struct cpu_user_regs *regs,
			struct process_data *data)
{
    fprintf(stdout,
	    "pid=%d,ppid=%d,name=%s,rppid=%d,tgid=%d,uid=%d,euid=%d,suid=%d," //fsuid=%d,
	    "gid=%d,egid=%d,sgid=%d", //fsgid=%d",
	    data->pid,data->ppid,data->name,data->real_ppid,data->tgid,
	    data->uid,data->euid,data->suid,
	    data->gid,data->egid,data->sgid);
    fflush(stdout);
    return;
}

void free_process_data(struct process_data *data)
{
    struct process_data *real_parent = data->real_parent;
    struct process_data *parent = data->parent;

    assert(data != NULL && data != parent && data != real_parent);

    if (real_parent && real_parent != parent) 
	free_process_data(real_parent);
    if (parent)
	free_process_data(parent);

    if (data->name)
	free(data->name);
    free(data);
}

struct process_data *load_process_data(vmprobe_handle_t handle,
				       struct cpu_user_regs *regs,
				       unsigned long task_addr,
				       int recurse,int printtree)
{
    struct process_data *data;
    struct process_data *real_parent_data = NULL;
    struct process_data *parent_data = NULL;
    unsigned char *task_struct_buf;
    unsigned long parent_addr;
    unsigned long real_parent_addr;

    task_struct_buf =
	vmprobe_get_data(handle,regs,"task_struct",task_addr,0,
			 TASK_STRUCT_SIZE,NULL);
    if (!task_struct_buf)
	return NULL;

    data = (struct process_data *)malloc(sizeof(struct process_data));
    if (!data) {
	free(task_struct_buf);
	return NULL;
    }
    memset(data,0,sizeof(struct process_data));

    data->pid = *((unsigned int *)(task_struct_buf+PID_OFFSET));
    data->tgid = *((unsigned int *)(task_struct_buf+TGID_OFFSET));
    data->uid = *((unsigned int *)(task_struct_buf+UID_OFFSET));
    data->euid = *((unsigned int *)(task_struct_buf+EUID_OFFSET));
    data->suid = *((unsigned int *)(task_struct_buf+SUID_OFFSET));
    data->fsuid = *((unsigned int *)(task_struct_buf+FSUID_OFFSET));
    data->gid = *((unsigned int *)(task_struct_buf+GID_OFFSET));
    data->egid = *((unsigned int *)(task_struct_buf+EGID_OFFSET));
    data->sgid = *((unsigned int *)(task_struct_buf+SGID_OFFSET));
    data->fsgid = *((unsigned int *)(task_struct_buf+FSGID_OFFSET));
    data->nextptr = *((unsigned long *)(task_struct_buf+TASKS_OFFSET)) - TASKS_OFFSET;
    if ((char *)(task_struct_buf+COMM_OFFSET) != NULL)
	data->name = strndup((char *)(task_struct_buf+COMM_OFFSET),16);

    real_parent_addr = *((unsigned int *)(task_struct_buf+REAL_PARENT_OFFSET));
    parent_addr = *((unsigned int *)(task_struct_buf+PARENT_OFFSET));

    free(task_struct_buf);

    /*
     * Find our parent and handle recursion
     */
    data->ppid = data->real_ppid = -1;
    if (data->pid != 1 && recurse) {
	if (parent_addr) {
	    parent_data = load_process_data(handle,regs,parent_addr,
					    recurse - 1,printtree);
	    if (parent_data) {
		data->ppid = parent_data->pid;
		data->parent = parent_data;
	    }
	}
	if (parent_addr == real_parent_addr) {
	    data->real_ppid = data->ppid;
	    data->real_parent = data->parent;
	}
	else if (real_parent_addr) {
	    real_parent_data = load_process_data(handle,regs,real_parent_addr,
						 recurse - 1,printtree);
	    if (real_parent_data) {
		data->real_ppid = real_parent_data->pid;
		data->real_parent = real_parent_data;
	    }
	}
    }

    if (printtree
#ifndef OLD_VPG_COMPAT
	&& debug >= 0
#endif
    ) {
	fprintf(stdout,"    pstree: ");
	print_process_data(handle,regs,data);
	fprintf(stdout,"\n");
	fflush(stdout);
    }

    return data;
}

LIST_HEAD(processes);

void free_process_list(void)
{
    struct process_data *pdata, *tmp_pdata;

    if (!list_empty(&processes)) {
	list_for_each_entry_safe(pdata,tmp_pdata,&processes,list) {
	    debug(2,"freeing %d %s\n",pdata->pid,pdata->name);
	    list_del(&pdata->list);
	    free_process_data(pdata);
	}
    }
}

int reload_process_list(vmprobe_handle_t handle,
			struct cpu_user_regs *regs)
{
    struct process_data *pdata;
    unsigned long next;
    int startpid;
    int i = 0;

    // blow away the old list
    free_process_list();

    // grab init task
    pdata = load_process_data(handle,regs,init_task_addr,1,0);

    if (!pdata) {
	fprintf(stderr,"ERROR: could not load init process data for ps list!\n");
	return -1;
    }

    startpid = pdata->pid;
    while (1) {
	// when we hit init the second time, break!
	if (i && pdata->pid == startpid) {
	    free_process_data(pdata);
	    break;
	}
	++i;

	//INIT_LIST_HEAD(&pdata->list);
	list_add_tail(&pdata->list,&processes);
	debug(1,"adding %d\n",pdata->pid);

	// grab the next one!
	next = pdata->nextptr;
	pdata = load_process_data(handle,regs,next,1,0);

	if (!pdata) {
	    fprintf(stderr,"ERROR: could not load intermediate process data for ps list; returning what we have!\n");
	    return 1;
	}
    }

    return 0;
}

void print_process_list(void)
{
    struct process_data *pdata;

    list_for_each_entry(pdata,&processes,list) {
	printf("  ");
	print_process_data(0, NULL, pdata);
	printf("\n");
    }
}

int pid_in_pslist(int pid)
{
    struct process_data *pdata;
    int j;

    if (ps_list_len == 0)
	return 1;

    list_for_each_entry(pdata,&processes,list) {
	if (pdata->pid == pid) {
	    for (j = 0; j < ps_list_len; ++j) {
		if (strcmp(pdata->name,ps_list[j]) == 0)
		    return 1;
	    }
	}
    }

    return 0;
}

char *process_list_to_string(vmprobe_handle_t handle,
			     struct cpu_user_regs *regs,
			     char *delim)
{
    char pbuf[1024];
    int bufsiz = 1024;
    int buflen = 0;
    char *buf;
    char *bufptr;
    char *tbuf;
    int len;
    int delimlen;
    char *rdelim = delim;
    int j;
    int found;
    struct process_data *pdata;

    if (!rdelim)
	rdelim = "\n";
    delimlen = strlen(rdelim);

    buf = malloc(bufsiz);
    bufptr = buf;

    list_for_each_entry(pdata,&processes,list) {
	found = 0;
	for (j = 0; j < ps_list_len; ++j) {
	    if (strcmp(pdata->name,ps_list[j]) == 0) {
		found = 1;
		break;
	    }
	}
	// if we are filtering what we report based on process name,
	// don't report it unless it's in our list.
	if (found || !ps_list_len) {
	    debug(1,"adding to string: pid=%d,ppid=%d,name=%s\n",
		  pdata->pid,pdata->ppid,pdata->name);
	    // tostring, then grab the next one!
	    len = snprintf(pbuf,sizeof(pbuf),"pid=%d,ppid=%d,name=%s%s",
			   pdata->pid,pdata->ppid,pdata->name,delim);
	    if ((bufsiz - buflen) < (delimlen+len+1)) {
		tbuf = malloc(bufsiz+1024);
		memcpy(tbuf,buf,bufsiz);
		bufsiz += 1024;
		free(buf);
		buf = tbuf;
		tbuf = NULL;
		bufptr = buf + buflen;
	    }
	    memcpy(bufptr,pbuf,len);
	    bufptr += len;
	    buflen += len;
	}
    }
    buf[buflen] = '\0';

    return buf;
}

struct process_data *load_current_process_data(vmprobe_handle_t handle,
					       struct cpu_user_regs *regs,
					       int recurse)
{
    struct process_data *data;
    unsigned long thread_info_ptr = current_thread_ptr(regs->esp);
    unsigned char *task_struct_ptr_buf = \
	vmprobe_get_data(handle,regs,"current_thread_ptr",thread_info_ptr,0,
			 sizeof(unsigned long),NULL);
    if (!task_struct_ptr_buf)
	return NULL;

    data = load_process_data(handle,regs,*((unsigned long *)task_struct_ptr_buf),
			     recurse,1);

    free(task_struct_ptr_buf);
    return data;
}

void fcntl_cmd_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		       int pid,int syscall,int arg,
		       struct argdata **arg_data,
		       struct process_data *data)
{
    int cmd = *((int *)(arg_data[arg]->data));
    int i;
    int didone = 0;
    char *buf = NULL;
    int bufsiz;
    char *endptr;

    for (i = 0; i < sizeof(fcntlcmds) / sizeof(fcntlcmds[0]); ++i) {
	if (cmd & fcntlcmds[i].cmd) {
	    if (didone)
		string_append(&buf,&bufsiz,&endptr,"|");
	    else 
		didone = 1;

	    string_append(&buf,&bufsiz,&endptr,fcntlcmds[i].name);
	}
    }
    arg_data[arg]->decodings[0] = buf;
 
    return;
}

void file_mode_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		       int pid,int syscall,int arg,
		       struct argdata **arg_data,
		       struct process_data *data)
{
    unsigned long mode = *((unsigned long *)(arg_data[arg]->data));
    int i;
    int didone = 0;
    char *buf = NULL;
    int bufsiz;
    char *endptr;

    for (i = 0; i < sizeof(filemodes) / sizeof(filemodes[0]); ++i) {
	if (mode & filemodes[i].mode) {
	    if (didone)
		string_append(&buf,&bufsiz,&endptr,"|");
	    else 
		didone = 1;
	    string_append(&buf,&bufsiz,&endptr,filemodes[i].name);
	}
    }
    arg_data[arg]->decodings[0] = buf;
 
    return;
}

void open_flags_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
			int pid,int syscall,int arg,
			struct argdata **arg_data,
			struct process_data *data)
{
    int flags = *((int *)(arg_data[arg]->data));
    int i;
    int didone = 0;
    char *buf = NULL;
    int bufsiz;
    char *endptr;

    for (i = 0; i < sizeof(openflags) / sizeof(openflags[0]); ++i) {
	if (flags & openflags[i].flag) {
	    if (didone) {
		string_append(&buf,&bufsiz,&endptr,"|");
	    }
	    else
		didone = 1;

	    string_append(&buf,&bufsiz,&endptr,openflags[i].name);
	}
    }
    arg_data[arg]->decodings[0] = buf;
 
    /*
     * XXX if flags don't include O_CREAT, then the following mode
     * argument (which we already fetched) is garbage. Just zero it here.
     */
    if ((flags & O_CREAT) == 0 && arg_data[arg+1]->data != NULL) {
	*(int *)arg_data[arg+1]->data = 0;
	if (arg_data[arg+1]->str != NULL && strlen(arg_data[arg+1]->str) >= 10)
	    strcpy(arg_data[arg+1]->str, "0x00000000");
    }
    return;
}

void signal_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		    int pid,int syscall,int arg,
		    struct argdata **arg_data,
		    struct process_data *data)
{
    unsigned long signo = *((unsigned long *)(arg_data[arg]->data));

    if (signo < 0 || signo >= sizeof(signals) / sizeof(signals[0])) {
	arg_data[arg]->decodings[0] = strdup("unknown");
	return;
    }
    arg_data[arg]->decodings[0] = strdup(signals[signo]);
 
    return;
}

void ioctl_cmd_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		       int pid,int syscall,int arg,
		       struct argdata **arg_data,
		       struct process_data *data)
{
    int i = 0;
    unsigned long cmd = *((unsigned long *)(arg_data[arg]->data));

    for (i = 0; i < sizeof(ioctls) / sizeof(ioctls[0]); ++i) {
	if (cmd == ioctls[i].num) {
	    arg_data[arg]->decodings[0] = strdup(ioctls[i].name);
	    return;
	}
    }
    arg_data[arg]->decodings[0] = strdup("unknown");
 
    return;
}

void exit_code_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		       int pid,int syscall,int arg,
		       struct argdata **arg_data,
		       struct process_data *data)
{
    long code = *((long *)(arg_data[arg]->data));

    //arg_data[arg]->str = ssprintf("0x%08lx",code);

    if (1) {
	if (WIFEXITED(code)) {
	    arg_data[arg]->decodings[0] = strdup("exit");
	    arg_data[arg]->decodings[1] = ssprintf("%d",WEXITSTATUS(code));
	    arg_data[arg]->decodings[2] = strdup("");
	}
	else if (WIFSIGNALED(code)) {
	    int signo = WTERMSIG(code);
	    char *signame = "unknown";
	    arg_data[arg]->decodings[0] = strdup("signal");
	    arg_data[arg]->decodings[1] = strdup("");
	    if (signo >= 0 && signo < sizeof(signals) / sizeof(signals[0]))
		signame = signals[signo];
	    arg_data[arg]->decodings[2] = strdup(signame);
	}
	else {
	    arg_data[arg]->decodings[0] = strdup("unknown");
	    arg_data[arg]->decodings[1] = strdup("");
	    arg_data[arg]->decodings[2] = strdup("");
	}
    }
 
    return;
}

void wait_stat_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		       int pid,int syscall,int arg,
		       struct argdata **arg_data,
		       struct process_data *data)
{
    unsigned long addr = *((unsigned long *)arg_data[arg]->data);

    if (arg_data[arg]->postcall) {
	long code = 0;

	if (addr && vmprobe_get_data(handle,regs,"waitpid_stat",addr,pid,
				     sizeof(long),(void *)&code)) {
	    if (WIFEXITED(code)) {
		arg_data[arg]->decodings[0] = strdup("exit");
		arg_data[arg]->decodings[1] = ssprintf("%d",WEXITSTATUS(code));
		arg_data[arg]->decodings[2] = strdup("");
		return;
	    }
	    if (WIFSIGNALED(code)) {
		int signo = WTERMSIG(code);
		char *signame = "unknown";
		arg_data[arg]->decodings[0] = strdup("signal");
		arg_data[arg]->decodings[1] = strdup("");
		if (signo >= 0 && signo < sizeof(signals) / sizeof(signals[0]))
		    signame = signals[signo];
		arg_data[arg]->decodings[2] = strdup(signame);
		return;
	    }
	}
    }

    arg_data[arg]->decodings[0] = strdup(addr ? "undef" : "nostatus");
    arg_data[arg]->decodings[1] = strdup("");
    arg_data[arg]->decodings[2] = strdup("");
}

void process_ptregs_decoder(vmprobe_handle_t handle,struct cpu_user_regs *regs,
			    int pid,int syscall,int arg,
			    struct argdata **arg_data,
			    struct process_data *data)
{
    unsigned char *argi_ptr;
    unsigned long argi_addr;
    unsigned char *argi;
    unsigned char *envi_ptr;
    unsigned long envi_addr;
    unsigned char *envi;
    int i = 0;
    char *buf = NULL;
    int bufsiz = 0;
    char *endptr = NULL;

    struct pt_regs *r = (struct pt_regs *)(arg_data[arg]->data);

    if (!r) 
	return;

    if (syscall == 11) { /* execve */
	arg_data[arg]->decodings[0] = (char *)vmprobe_get_data(handle,regs,"syscall_ebx",r->ebx,pid,0,NULL);


	string_append(&buf,&bufsiz,&endptr,"[");
	while (1) {
	    argi_ptr = vmprobe_get_data(handle,regs,
					"execve_argi_ptr",
					r->ecx + i * sizeof(char *),
					pid,sizeof(char *),NULL);
	    if (argi_ptr == NULL || *argi_ptr == '\0') {
		if (argi_ptr)
		    free(argi_ptr);
		break;
	    }
	    argi_addr = *((unsigned long *)argi_ptr);
	    free(argi_ptr);
	    argi = vmprobe_get_data(handle,regs,
				    "execve_argi",argi_addr,
				    pid,0,NULL);
	    if (!argi)
		argi = (unsigned char *)strdup("(null)");
	    string_append(&buf,&bufsiz,&endptr,(char *)argi);
	    string_append(&buf,&bufsiz,&endptr,",");
	    if (argi)
		free(argi);
	    ++i;
	}
	string_append(&buf,&bufsiz,&endptr,"]");
	arg_data[arg]->decodings[1] = buf;

	i = 0;
	buf = endptr = NULL;
	bufsiz = 0;
	string_append(&buf,&bufsiz,&endptr,"[");
	while (1) {
	    envi_ptr = vmprobe_get_data(handle,regs,
					"execve_envi_ptr",
					r->edx + i * sizeof(char *),
					pid,sizeof(char *),NULL);
	    if (envi_ptr == NULL || *envi_ptr == '\0') {
		/* last arg of list, so break */
		if (envi_ptr)
		    free(envi_ptr);
		break;
	    }
	    envi_addr = *((unsigned long *)envi_ptr);
	    free(envi_ptr);
	    envi = vmprobe_get_data(handle,regs,
				    "execve_envi",envi_addr,
				    pid,0,NULL);
	    if (!envi)
		envi = (unsigned char *)strdup("(null)");
	    string_append(&buf,&bufsiz,&endptr,(char *)envi);
	    string_append(&buf,&bufsiz,&endptr,",");
	    if (envi)
		free(envi);
	    ++i;
	}
	string_append(&buf,&bufsiz,&endptr,"]");
	arg_data[arg]->decodings[2] = buf;
    }

    return;
}

void *process_ptregs_loader(vmprobe_handle_t handle,struct cpu_user_regs *regs,
			    int pid,int syscall,int arg,unsigned long argval,
			    struct argdata **arg_data,
			    struct process_data *data)
{
    struct pt_regs *r =
	(struct pt_regs *)vmprobe_get_data(handle,regs,
					   "pt_regs",regs->esp+4,0,
					   sizeof(struct pt_regs),NULL);

    if (!r) {
	arg_data[arg]->str = strdup("<data access error>");
	return NULL;
    }

    arg_data[arg]->data = (unsigned char *)r;
    arg_data[arg]->str = ssprintf("{ebx=%08lx,ecx=%08lx,edx=%08lx,esi=%08lx,edi=%08lx,eax=%08lx,"
				  "ebp=%08lx,esp=%08lx,eip=%08lx,eflags=%08lx,orig_eax=%08lx,"
				  "xds=%08x,xes=%08x,xcs=%08x,xss=%08x}",
				  r->ebx,r->ecx,r->edx,r->esi,r->edi,r->eax,
				  r->ebp,r->esp,r->eip,r->eflags,r->orig_eax,
				  r->xds,r->xes,r->xcs,r->xss);

    return arg_data[arg]->data;
}

#define SYSCALL_MAX 303

/*
 * If a syscall has RADDR_YES set for the raddr field, it means that it
 * returns through the generic syscall_call stub and thus we can statically
 * identify a "return address" where we can stop. Note that we could determine
 * a return address on the fly by looking at the top of the stack when we
 * are stopped at the entry point, but that is a little too much for my
 * pretty little head right now.
 *
 * The default value is NO unless we empirically determine that a particular
 * syscall goes through the stub.
 *
 * We define some constants here just so we can easily pick the raddr field
 * out of the soup of numbers below.
 */
#define RADDR_NO	0
#define RADDR_YES	1

struct syscall_info sctab[SYSCALL_MAX] = {
    { 0 },
    { 1, "sys_exit", 0xc0121df0, RADDR_NO, 1,
      { { 1, "error_code", SC_ARG_TYPE_INT, 
	  exit_code_decoder, 
	  (char *[]) { "error_code:cause","error_code:status","error_code:signal" },
	  3 } } },
    { 2, "sys_fork", 0xc0102ef0, RADDR_NO, 1,
      { { 1, "regs", SC_ARG_TYPE_PT_REGS, NULL, NULL, 0, process_ptregs_loader } } },
    { 3, "sys_read", 0xc01658e0, RADDR_YES, 3,
      { { 1, "fd", SC_ARG_TYPE_UINT },
	{ 2, "buf", SC_ARG_TYPE_BYTES, NULL, NULL, 0, NULL, 3 },
	{ 3, "count", SC_ARG_TYPE_INT } } },
    { 4, "sys_write", 0xc0165950, RADDR_YES, 3,
      { { 1, "fd", SC_ARG_TYPE_UINT },
	{ 2, "buf", SC_ARG_TYPE_BYTES, NULL, NULL, 0, NULL, 3 },
	{ 3, "count", SC_ARG_TYPE_INT } } },
    { 5, "sys_open", 0xc01633f0, RADDR_YES, 3,
      { { 1, "filename", SC_ARG_TYPE_STRING },
	{ 2, "flags", SC_ARG_TYPE_HEXINT, open_flags_decoder,(char *[]) { "flags:flags" }, 1, NULL, 3 },
	{ 3, "mode", SC_ARG_TYPE_HEXINT, file_mode_decoder,(char *[]) { "mode:mode" }, 1 } } },
    { 6, "sys_close", 0xc0164510, RADDR_YES, 1,
      { { 1, "fd", SC_ARG_TYPE_UINT } } },
    { 7, "sys_waitpid", 0xc0121340, RADDR_YES, 3,
      { { 1, "pid", SC_ARG_TYPE_PID_T },
	{ 2, "status", SC_ARG_TYPE_PTR, wait_stat_decoder,
	  (char *[]) { "status:cause","status:code","status:signal" }, 3 },
	{ 3, "options", SC_ARG_TYPE_INT } } },
    { 8, "sys_creat", 0xc0163420, RADDR_YES, 2, 
      { { 1, "filename", SC_ARG_TYPE_STRING },
	{ 2, "mode", SC_ARG_TYPE_HEXINT, file_mode_decoder,(char *[]) { "mode:mode" }, 1 } } },
    { 9, "sys_link", 0xc0176eb0, RADDR_NO, 2, 
      { { 1, "oldname", SC_ARG_TYPE_STRING },
	{ 2, "newname", SC_ARG_TYPE_STRING } } },
    { 10, "sys_unlink", 0xc01768e0, RADDR_NO, 1, 
      { { 1, "pathname", SC_ARG_TYPE_STRING } } },
    { 11, "sys_execve", 0xc01036e0, RADDR_YES, 1, 
      { { 1, "regs", SC_ARG_TYPE_PT_REGS, process_ptregs_decoder, (char *[]){ "regs:filename","regs:args","regs:env"}, 3, process_ptregs_loader } } },
    { 12, "sys_chdir", 0xc0164330, RADDR_YES, 1, 
      { { 1, "filename", SC_ARG_TYPE_STRING } } },
    { 13, "sys_time", 0xc0123200, RADDR_NO, 1,
      { { 1, "tloc", SC_ARG_TYPE_PTR } } },
    { 14, "sys_mknod", 0xc0176d00, RADDR_NO, 3, 
      { { 1, "filename", SC_ARG_TYPE_STRING },
	{ 2, "mode", SC_ARG_TYPE_HEXINT },
	{ 3, "dev", SC_ARG_TYPE_UINT } } },
    { 15, "sys_chmod", 0xc01638c0, RADDR_NO, 2, 
      { { 1, "filename", SC_ARG_TYPE_STRING },
	{ 2, "mode", SC_ARG_TYPE_HEXINT, file_mode_decoder,(char *[]) { "mode:mode" }, 1 } } },
    { 0 },
    { 0 },
    { 18, "sys_stat", 0xc016f7f0, RADDR_NO, 2, 
      { { 1, "filename", SC_ARG_TYPE_STRING },
	{ 2, "statbuf", SC_ARG_TYPE_PTR } } },
    { 19, "sys_lseek", 0xc01657a0, RADDR_NO, 3, 
      { { 1, "fd", SC_ARG_TYPE_UINT },
	{ 2, "offset", SC_ARG_TYPE_INT },
	{ 3, "origin", SC_ARG_TYPE_UINT } } },
    { 20, "sys_getpid", 0xc0129710, RADDR_NO, 0, { } },
    { 21, "sys_mount", 0xc0183690, RADDR_NO, 5, 
      { { 1, "dev_name", SC_ARG_TYPE_STRING },
	{ 2, "dir_name", SC_ARG_TYPE_STRING },
	{ 3, "type", SC_ARG_TYPE_STRING },
	{ 4, "flags", SC_ARG_TYPE_HEXINT },
	{ 5, "data", SC_ARG_TYPE_PTR } } },
    { 22, "sys_oldumount", 0xc01839c0, RADDR_NO, 1, 
      { { 1, "name", SC_ARG_TYPE_STRING } } },
    { 0 },
    { 0 },
    { 25, "sys_stime", 0xc0123970, RADDR_NO, 1,
      { { 1, "tptr", SC_ARG_TYPE_PTR } } },
    { 26, "sys_ptrace", 0xc0127d80, RADDR_NO, 4, 
      { { 1, "request", SC_ARG_TYPE_LONG },
	{ 2, "pid", SC_ARG_TYPE_LONG },
	{ 3, "addr", SC_ARG_TYPE_PTR },
	{ 4, "data", SC_ARG_TYPE_PTR } } },
    { 27, "sys_alarm", 0xc01285e0, RADDR_NO, 1, 
      { { 1, "seconds", SC_ARG_TYPE_UINT } } },
    { 28, "sys_fstat", 0xc016f8e0, RADDR_NO, 2, 
      { { 1, "fd", SC_ARG_TYPE_UINT },
	{ 2, "statbuf", SC_ARG_TYPE_PTR } } },
    { 29, "sys_pause", 0xc012c960, RADDR_NO, 0 },
    { 30, "sys_utime", 0xc01641f0, RADDR_NO, 2, 
      { { 1, "filename", SC_ARG_TYPE_STRING },
	{ 2, "times", SC_ARG_TYPE_PTR } } },
    { 0 },
    { 0 },
    { 33, "sys_access", 0xc0163a40, RADDR_NO, 2, 
      { { 1, "filename", SC_ARG_TYPE_STRING },
	{ 2, "mode", SC_ARG_TYPE_HEXINT, file_mode_decoder,(char *[]) { "mode:mode" }, 1 } } },
    { 34, "sys_nice", 0xc011a9a0, RADDR_NO, 1, 
      { { 1, "increment", SC_ARG_TYPE_INT } } },
    { 0 },
    { 36, "sys_sync", 0xc01677d0, RADDR_NO, 0 },
    { 37, "sys_kill", 0xc012c630, RADDR_NO, 2, 
      { { 1, "pid", SC_ARG_TYPE_INT },
	{ 2, "sig", SC_ARG_TYPE_INT, signal_decoder,(char *[]) { "sig:sig" }, 1 } } },
    { 38, "sys_rename", 0xc0176630, RADDR_NO, 2, 
      { { 1, "oldname", SC_ARG_TYPE_STRING },
	{ 2, "newname", SC_ARG_TYPE_STRING } } },
    { 39, "sys_mkdir", 0xc0176b30, RADDR_NO, 2, 
      { { 1, "pathname", SC_ARG_TYPE_STRING },
	{ 2, "mode", SC_ARG_TYPE_HEXINT, file_mode_decoder,(char *[]) { "mode:mode" }, 1 } } },
    { 40, "sys_rmdir", 0xc0176a20, RADDR_YES, 1, 
      { { 1, "pathname", SC_ARG_TYPE_STRING } } },
    { 41, "sys_dup", 0xc0177fe0, RADDR_NO, 1, 
      { { 1, "fildes", SC_ARG_TYPE_UINT } } },
    { 42, "sys_pipe", 0xc010a4b0, RADDR_NO, 1,
      { { 1, "fildes", SC_ARG_TYPE_PTR } } },
    { 43, "sys_times", 0xc012ea90, RADDR_NO, 1,
      { { 1, "tbuf", SC_ARG_TYPE_PTR } } },
    { 0 },
    { 45, "sys_brk", 0xc0155920, RADDR_NO, 1,
      { { 1, "brk", SC_ARG_TYPE_PTR } } },
    { 0 },
    { 0 },
    { 48, "sys_signal", 0xc012a420, RADDR_NO, 2, 
      { { 1, "sig", SC_ARG_TYPE_INT, signal_decoder,(char *[]) { "sig:sig" }, 1 },
	{ 2, "handler", SC_ARG_TYPE_PTR } } },
    { 0 },
    { 0 },
    { 51, "sys_acct", 0xc01347f0, RADDR_NO, 1,
      { { 1, "name", SC_ARG_TYPE_STRING } } },
    { 52, "sys_umount", 0xc0183770, RADDR_NO, 1, 
      { { 1, "name", SC_ARG_TYPE_STRING },
	{ 2, "flags", SC_ARG_TYPE_HEXINT } } },
    { 0 },
    { 54, "sys_ioctl", 0xc01788f0, RADDR_NO, 3,
      { { 1, "fd", SC_ARG_TYPE_UINT },
	{ 2, "cmd", SC_ARG_TYPE_HEXINT, ioctl_cmd_decoder,(char *[]) { "cmd:cmd" }, 1 },
	{ 3, "arg", SC_ARG_TYPE_PTR } } },
    { 55, "sys_fcntl", 0xc0178570, RADDR_NO, 3,
      { { 1, "fd", SC_ARG_TYPE_INT },
	{ 2, "cmd", SC_ARG_TYPE_UINT, fcntl_cmd_decoder,(char *[]) { "cmd:cmd" }, 1 },
	{ 3, "arg", SC_ARG_TYPE_PTR } } },
    { 0 },
    { 57, "sys_setpgid", 0xc012ebb0, RADDR_NO, 2, 
      { { 1, "pid", SC_ARG_TYPE_PID_T },
	{ 2, "pgid", SC_ARG_TYPE_PID_T } } },
    { 0 },
    { 0 },
    { 60, "sys_umask", 0xc012e8d0, RADDR_NO, 1,
      { { 1, "mask", SC_ARG_TYPE_HEXINT, file_mode_decoder,(char *[]) { "mask:mask" }, 1 } } },
    { 61, "sys_chroot", 0xc0164460, RADDR_YES, 1, 
      { { 1, "filename", SC_ARG_TYPE_STRING } } },
    { 62, "sys_ustat", 0xc016bcf0, RADDR_NO, 2, 
      { { 1, "dev", SC_ARG_TYPE_UINT },
	{ 2, "ubuf", SC_ARG_TYPE_PTR } } },
    { 63, "sys_dup2", 0xc0178450, RADDR_NO, 2, 
      { { 1, "oldfd", SC_ARG_TYPE_UINT },
	{ 2, "newfd", SC_ARG_TYPE_UINT } } },
    { 64, "sys_getppid", 0xc0129730, RADDR_NO, 0 },
    { 65, "sys_getpgrp", 0xc012ee10, RADDR_NO, 0 },
    { 66, "sys_setsid", 0xc012e460, RADDR_NO, 0, { } },
    { 67, "sys_sigaction", 0xc01045d0, RADDR_NO, 3, 
      { { 1, "sig", SC_ARG_TYPE_INT, signal_decoder,(char *[]) { "sig:sig" }, 1 },
	{ 2, "act", SC_ARG_TYPE_PTR },
	{ 3, "oact", SC_ARG_TYPE_PTR } } },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 72, "sys_sigsuspend", 0xc0105020, RADDR_NO, 3, 
      { { 1, "history0", SC_ARG_TYPE_INT },
	{ 2, "history1", SC_ARG_TYPE_INT },
	{ 2, "mask", SC_ARG_TYPE_UINT } } },
    { 73, "sys_sigpending", 0xc012a010, RADDR_NO, 1, 
      { { 1, "set", SC_ARG_TYPE_PTR } } },
    { 74, "sys_sethostname", 0xc012e130, RADDR_NO, 2, 
      { { 1, "hostname", SC_ARG_TYPE_STRING, NULL, NULL, 0, NULL, 2 },
	{ 2, "len", SC_ARG_TYPE_INT } } },
    { 75, "sys_setrlimit", 0xc012e6a0, RADDR_NO, 2, 
      { { 1, "resource", SC_ARG_TYPE_UINT, },
	{ 2, "rlim", SC_ARG_TYPE_PTR } } },
    { 76, "sys_old_getrlimit", 0xc012f6e0, RADDR_NO, 2, 
      { { 1, "resource", SC_ARG_TYPE_UINT, },
	{ 2, "rlim", SC_ARG_TYPE_PTR } } },
    { 77, "sys_getrusage", 0xc012e880, RADDR_NO, 2, 
      { { 1, "who", SC_ARG_TYPE_INT, },
	{ 2, "ru", SC_ARG_TYPE_PTR } } },
    { 78, "sys_gettimeofday", 0xc0123240, RADDR_YES, 2, 
      { { 1, "tv", SC_ARG_TYPE_PTR, },
	{ 2, "tz", SC_ARG_TYPE_PTR } } },
    { 79, "sys_settimeofday", 0xc01238d0, RADDR_NO, 2, 
      { { 1, "tv", SC_ARG_TYPE_TIMEVAL, timeval_decoder,(char *[]) { "tv:tv" }, 1 },
	{ 2, "tz", SC_ARG_TYPE_TIMEZONE, timezone_decoder,(char *[]) { "tz:tz" }, 1 } } },
    { 0 },
    { 0 },
    { 0 },
    { 83, "sys_symlink", 0xc0176750, RADDR_NO, 2, 
      { { 1, "oldname", SC_ARG_TYPE_STRING },
	{ 2, "newname", SC_ARG_TYPE_STRING } } },
    { 84, "sys_lstat", 0xc016f7b0, RADDR_NO, 2, 
      { { 1, "filename", SC_ARG_TYPE_STRING },
	{ 2, "statbuf", SC_ARG_TYPE_PTR } } },
    { 85, "sys_readlink", 0xc016f3d0, RADDR_NO, 3, 
      { { 1, "path", SC_ARG_TYPE_STRING },
	{ 2, "buf", SC_ARG_TYPE_PTR },
	{ 3, "bufsiz", SC_ARG_TYPE_INT } } },
    { 86, "sys_uselib", 0xc01719b0, RADDR_NO, 1, 
      { { 1, "library", SC_ARG_TYPE_STRING } } },
    { 87, "sys_swapon", 0xc015bbd0, RADDR_NO, 2, 
      { { 1, "specialfile", SC_ARG_TYPE_STRING },
	{ 2, "swap_flags", SC_ARG_TYPE_HEXINT } } },
    { 88, "sys_reboot", 0xc012de60, RADDR_NO, 4, 
      { { 1, "magic1", SC_ARG_TYPE_INT },
	{ 2, "magic2", SC_ARG_TYPE_INT },
	{ 3, "cmd", SC_ARG_TYPE_UINT },
	{ 4, "arg", SC_ARG_TYPE_PTR } } },
    { 0 },
    { 0 },
    { 91, "sys_munmap", 0xc01551d0, RADDR_NO, 2, 
      { { 1, "addr", SC_ARG_TYPE_PTR },
	{ 2, "len", SC_ARG_TYPE_INT } } },
    { 92, "sys_truncate", 0xc0163fa0, RADDR_NO, 2, 
      { { 1, "path", SC_ARG_TYPE_STRING },
	{ 2, "length", SC_ARG_TYPE_ULONG } } },
    { 93, "sys_ftruncate", 0xc0163db0, RADDR_NO, 2, 
      { { 1, "fd", SC_ARG_TYPE_INT },
	{ 2, "length", SC_ARG_TYPE_ULONG } } },
    { 94, "sys_fchmod", 0xc0163580, RADDR_NO, 2, 
      { { 1, "fd", SC_ARG_TYPE_INT },
	{ 2, "mode", SC_ARG_TYPE_HEXINT, file_mode_decoder,(char *[]) { "mode:mode" }, 1 } } },
    { 0 },
    { 96, "sys_getpriority", 0xc012f040, RADDR_NO, 2,
      { { 1, "which", SC_ARG_TYPE_INT },
	{ 2, "who", SC_ARG_TYPE_INT } } },
    { 97, "sys_setpriority", 0xc012ee30, RADDR_NO, 3,
      { { 1, "which", SC_ARG_TYPE_INT },
	{ 2, "who", SC_ARG_TYPE_INT },
	{ 3, "niceval", SC_ARG_TYPE_INT } } },
    { 0 },
    { 99, "sys_statfs", 0xc0164160, RADDR_NO, 2, 
      { { 1, "path", SC_ARG_TYPE_STRING },
	{ 2, "buf", SC_ARG_TYPE_PTR } } },
    { 100, "sys_fstatfs", 0xc0164040, RADDR_NO, 2, 
      { { 1, "fd", SC_ARG_TYPE_INT },
	{ 2, "buf", SC_ARG_TYPE_PTR } } },
    { 101, "sys_ioperm", 0xc01098f0, RADDR_NO, 3, 
      { { 1, "from", SC_ARG_TYPE_ULONG },
	{ 2, "num", SC_ARG_TYPE_ULONG },
	{ 3, "turn_on", SC_ARG_TYPE_INT } } },
    { 102, "sys_socketcall", 0xc028eaa0, RADDR_YES, 2,
      { { 1, "call", SC_ARG_TYPE_INT, socket_call_decoder,(char *[]) { "call:call" }, 1 },
	{ 2, "args", SC_ARG_TYPE_PTR, socket_args_decoder,(char *[]) { "args:args" }, 1 } } },
    { 103, "sys_syslog", 0xc011f1e0, RADDR_NO, 3,
      { { 1, "type", SC_ARG_TYPE_INT },
	{ 2, "buf", SC_ARG_TYPE_BYTES, NULL, NULL, 0, NULL, 3 },
	{ 3, "len", SC_ARG_TYPE_INT } } },
    { 104, "sys_setitimer", 0xc01229f0, RADDR_NO, 3,
      { { 1, "which", SC_ARG_TYPE_INT },
	{ 2, "value", SC_ARG_TYPE_ITIMERVAL, itimerval_decoder,(char *[]) { "value:value" }, 1 },
	{ 3, "ovalue", SC_ARG_TYPE_PTR } } },
    { 105, "sys_getitimer", 0xc0122e40, RADDR_NO, 2,
      { { 1, "which", SC_ARG_TYPE_INT },
	{ 2, "value", SC_ARG_TYPE_PTR } } },
    { 106, "sys_newstat", 0xc016f5d0, RADDR_NO, 2, 
      { { 1, "filename", SC_ARG_TYPE_STRING },
	{ 2, "statbuf", SC_ARG_TYPE_PTR } } },
    { 107, "sys_newlstat", 0xc016f460, RADDR_NO, 2, 
      { { 1, "filename", SC_ARG_TYPE_STRING },
	{ 2, "statbuf", SC_ARG_TYPE_PTR } } },
    { 108, "sys_newfstat", 0xc016f8b0, RADDR_NO, 1, 
      { { 1, "fd", SC_ARG_TYPE_INT },
	{ 2, "statbuf", SC_ARG_TYPE_PTR } } },
    { 109, "sys_uname", 0xc010a2a0, RADDR_NO, 1,
      { { 1, "name", SC_ARG_TYPE_PTR } } },
    { 110, "sys_iopl", 0xc0109820, RADDR_NO, 1,
      {	{ 1, "unused", SC_ARG_TYPE_ULONG } } },
    { 111, "sys_vhangup", 0xc0162d60, RADDR_NO, 0 },
    { 0 },
    { 0 },
    { 114, "sys_wait4", 0xc0121300, RADDR_NO, 4,
      { { 1, "pid", SC_ARG_TYPE_PID_T },
	{ 2, "stat_addr", SC_ARG_TYPE_PTR },
	{ 3, "options", SC_ARG_TYPE_INT },
	{ 4, "ru", SC_ARG_TYPE_PTR } } },
    { 115, "sys_swapoff", 0xc015b310, RADDR_NO, 1,
	{ { 1, "specialfile", SC_ARG_TYPE_STRING } } },
    { 116, "sys_sysinfo", 0xc0128480, RADDR_NO, 0 },
    { 117, "sys_ipc", 0xc010a500, RADDR_NO, 0 },
    { 118, "sys_fsync", 0xc0167720, RADDR_NO, 1,
      {	{ 1, "fd", SC_ARG_TYPE_UINT } } },
    { 119, "sys_sigreturn", 0xc01050f0, RADDR_NO, 0 },
    { 120, "sys_clone", 0xc0102eb0, RADDR_NO, 1, 
      { { 1, "regs", SC_ARG_TYPE_PT_REGS, process_ptregs_decoder,(char *[]) { "regs:flags" }, 1, process_ptregs_loader } } },
    { 121, "sys_setdomainname", 0xc012d630, RADDR_NO, 2, 
      { { 1, "name", SC_ARG_TYPE_STRING, NULL, NULL, 0, NULL, 2 },
	{ 2, "len", SC_ARG_TYPE_INT } } },
    { 122, "sys_newuname", 0xc012d840, RADDR_NO, 1,
      { { 1, "name", SC_ARG_TYPE_PTR } } },
    { 123, "sys_modify_ldt", 0xc0109f60, RADDR_NO, 0 },
    { 124, "sys_adjtimex", 0xc0123740, RADDR_NO, 0 },
    { 125, "sys_mprotect", 0xc0156480, RADDR_NO, 3, 
      { { 1, "start", SC_ARG_TYPE_ULONG },
	{ 2, "len", SC_ARG_TYPE_ULONG },
	{ 3, "prot", SC_ARG_TYPE_ULONG } } },
    { 126, "sys_sigprocmask", 0xc012cd00, RADDR_NO, 3, 
      { { 1, "how", SC_ARG_TYPE_INT },
	{ 2, "set", SC_ARG_TYPE_SIGSET_T, sigset_decoder,(char *[]) { "set:set" }, 1 },
	{ 3, "oset", SC_ARG_TYPE_PTR } } },
    { 0 },
    { 128, "sys_init_module", 0xc013d170, RADDR_NO, 3, 
      { { 1, "umod", SC_ARG_TYPE_PTR },
	{ 2, "len", SC_ARG_TYPE_ULONG },
	{ 3, "args", SC_ARG_TYPE_STRING } } },
    { 129, "sys_delete_module", 0xc013c8f0, RADDR_NO, 2, 
      { { 1, "name_user", SC_ARG_TYPE_STRING },
	{ 2, "flags", SC_ARG_TYPE_HEXINT } } },
    { 0 },
    { 131, "sys_quotactl", 0xc01347f0, RADDR_NO, 0 },
    { 132, "sys_getpgid", 0xc012eda0, RADDR_NO, 1,
      {	{ 1, "pid", SC_ARG_TYPE_PID_T } } },
    { 133, "sys_fchdir", 0xc01643c0, RADDR_NO, 1,
      {	{ 1, "fd", SC_ARG_TYPE_UINT } } },
    { 134, "sys_bdflush", 0xc0166460, RADDR_NO, 2, 
      { { 1, "func", SC_ARG_TYPE_INT },
	{ 2, "data", SC_ARG_TYPE_ULONG } } },
    { 135, "sys_sysfs", 0xc01817f0, RADDR_NO, 3, 
      { { 1, "option", SC_ARG_TYPE_INT },
	{ 2, "arg1", SC_ARG_TYPE_ULONG },
	{ 3, "arg1", SC_ARG_TYPE_ULONG } } },
    { 136, "sys_personality", 0xc011dbb0, RADDR_NO, 1,
      {	{ 1, "personality", SC_ARG_TYPE_ULONG } } },
    { 0 },
    { 0 },
    { 0 },
    { 140, "sys_llseek", 0xc0165830, RADDR_NO, 5, 
      { { 1, "fd", SC_ARG_TYPE_UINT },
	{ 2, "offset_high", SC_ARG_TYPE_ULONG },
	{ 3, "offset_low", SC_ARG_TYPE_ULONG },
	{ 4, "result", SC_ARG_TYPE_PTR },
	{ 5, "origin", SC_ARG_TYPE_UINT } } },
    { 141, "sys_getdents", 0xc0178d90, RADDR_NO, 3, 
      { { 1, "fd", SC_ARG_TYPE_UINT },
	{ 2, "dirent", SC_ARG_TYPE_PTR },
	{ 3, "count", SC_ARG_TYPE_UINT } } },
    { 142, "sys_select", 0xc017a240, RADDR_NO, 5, 
      { { 1, "n", SC_ARG_TYPE_INT },
	{ 2, "inp", SC_ARG_TYPE_PTR },
	{ 3, "outp", SC_ARG_TYPE_PTR },
	{ 4, "exp", SC_ARG_TYPE_PTR },
	{ 5, "tvp", SC_ARG_TYPE_TIMEVAL, timeval_decoder,(char *[]) { "tvp:tvp" }, 1 } } },
    { 143, "sys_flock", 0xc017cf00, RADDR_NO, 2, 
      { { 1, "fd", SC_ARG_TYPE_UINT },
	{ 2, "cmd", SC_ARG_TYPE_UINT } } },
    { 144, "sys_msync", 0xc0157430, RADDR_NO, 3, 
      { { 1, "start", SC_ARG_TYPE_ULONG },
	{ 2, "len", SC_ARG_TYPE_ULONG },
	{ 3, "flags", SC_ARG_TYPE_HEXINT } } },
    { 145, "sys_readv", 0xc0165ac0, RADDR_NO, 0 },
    { 146, "sys_writev", 0xc0165600, RADDR_NO, 0 },
    { 147, "sys_getsid", 0xc012e3f0, RADDR_NO, 11,
      {	{ 1, "pid", SC_ARG_TYPE_PID_T } } },
    { 148, "sys_fdatasync", 0xc0167700, RADDR_NO, 1,
      {	{ 1, "fd", SC_ARG_TYPE_UINT } } },
    { 149, "sys_sysctl", 0xc0126d70, RADDR_NO, 0 },
    { 150, "sys_mlock", 0xc0153ed0, RADDR_NO, 2, 
      { { 1, "start", SC_ARG_TYPE_ULONG },
	{ 2, "len", SC_ARG_TYPE_ULONG } } },
    { 151, "sys_munlock", 0xc0153d30, RADDR_NO, 2, 
      { { 1, "start", SC_ARG_TYPE_ULONG },
	{ 2, "len", SC_ARG_TYPE_ULONG } } },
    { 152, "sys_mlockall", 0xc0153da0, RADDR_NO, 1, 
      { { 1, "flags", SC_ARG_TYPE_HEXINT } } },
    { 153, "sys_munlockall", 0xc0153e80, RADDR_NO, 0 },
    { 154, "sys_sched_setparam", 0xc01190c0, RADDR_NO, 2, 
      { { 1, "pid", SC_ARG_TYPE_PID_T },
	{ 2, "param", SC_ARG_TYPE_PTR } } },
    { 155, "sys_sched_getparam", 0xc011b460, RADDR_NO, 2, 
      { { 1, "pid", SC_ARG_TYPE_PID_T },
	{ 2, "param", SC_ARG_TYPE_PTR } } },
    { 156, "sys_sched_setscheduler", 0xc01190e0, RADDR_NO, 3, 
      { { 1, "pid", SC_ARG_TYPE_PID_T },
	{ 1, "policy", SC_ARG_TYPE_INT },
	{ 3, "param", SC_ARG_TYPE_PTR } } },
    { 157, "sys_sched_getscheduler", 0xc011b400, RADDR_NO, 1, 
      { { 1, "pid", SC_ARG_TYPE_PID_T } } },
    { 158, "sys_sched_yield", 0xc0119140, 0 },
    { 159, "sys_sched_get_priority_max", 0xc0116300, RADDR_NO, 1, 
      { { 1, "policy", SC_ARG_TYPE_INT } } },
    { 160, "sys_sched_get_priority_min", 0xc0116330, RADDR_NO, 1, 
      { { 1, "policy", SC_ARG_TYPE_INT } } },
    { 161, "sys_sched_rr_get_interval", 0xc011a440, RADDR_NO, 2, 
      { { 1, "pid", SC_ARG_TYPE_PID_T },
	{ 2, "interval", SC_ARG_TYPE_TIMESPEC, timespec_decoder,(char *[]) { "interval:interval" }, 1 } } },
    { 162, "sys_nanosleep", 0xc0137590, RADDR_NO, 2, 
      { { 1, "rqtp", SC_ARG_TYPE_TIMESPEC, timespec_decoder,(char *[]) { "rqtp:rqtp" }, 1 },
	{ 2, "rmtp", SC_ARG_TYPE_TIMESPEC, timespec_decoder,(char *[]) { "rmtp:rmtp" }, 1 } } },
    { 163, "sys_mremap", 0xc01573c0, RADDR_NO, 5, 
      { { 1, "addr", SC_ARG_TYPE_PTR },
	{ 2, "old_len", SC_ARG_TYPE_ULONG },
	{ 3, "new_len", SC_ARG_TYPE_ULONG },
	{ 4, "flags", SC_ARG_TYPE_HEXINT },
	{ 5, "new_addr", SC_ARG_TYPE_PTR } } },
    { 0 },
    { 0 },
    { 166, "sys_vm86", 0xc01102b0, RADDR_NO, 0 },
    { 0 },
    { 168, "sys_poll", 0xc0179380, RADDR_NO, 3, 
      { { 1, "ufds", SC_ARG_TYPE_PTR },
	{ 2, "nfds", SC_ARG_TYPE_UINT },
	{ 3, "timeout", SC_ARG_TYPE_LONG } } },
    { 169, "sys_nfsservctl", 0xc01347f0, RADDR_NO, 0 },
    { 0 },
    { 0 },
    { 172, "sys_prctl", 0xc012e8f0, RADDR_NO, 0 },
    { 173, "sys_rt_sigreturn", 0xc0104ee0, RADDR_NO, 1, 
      { { 1, "__unused", SC_ARG_TYPE_ULONG } } },
    { 174, "sys_rt_sigaction", 0xc012a470, RADDR_NO, 4, 
      { { 1, "sig", SC_ARG_TYPE_INT, signal_decoder,(char *[]) { "sig:sig" }, 1 },
	{ 2, "act", SC_ARG_TYPE_PTR },
	{ 3, "oact", SC_ARG_TYPE_PTR },
	{ 4, "sigsetsize", SC_ARG_TYPE_UINT } } },
    { 175, "sys_rt_sigprocmask", 0xc012cbd0, RADDR_NO, 4, 
      { { 1, "how", SC_ARG_TYPE_INT },
	{ 2, "set", SC_ARG_TYPE_SIGSET_T, sigset_decoder,(char *[]) { "set:set" }, 1 },
	{ 3, "oset", SC_ARG_TYPE_PTR },
	{ 4, "sigsetsize", SC_ARG_TYPE_UINT } } },
    { 176, "sys_rt_sigpending", 0xc012a030, RADDR_NO, 2, 
      { { 1, "set", SC_ARG_TYPE_SIGSET_T, sigset_decoder,(char *[]) { "set:set" }, 1 },
	{ 2, "sigsetsize", SC_ARG_TYPE_UINT } } },
    { 177, "sys_rt_sigtimedwait", 0xc012ce50, RADDR_NO, 4, 
      { { 1, "uthese", SC_ARG_TYPE_SIGSET_T, sigset_decoder,(char *[]) { "set:set" }, 1 },
	{ 2, "uinfo", SC_ARG_TYPE_SIGINFO_T, siginfo_decoder,(char *[]) { "uinfo:uinfo" }, 1 },
	{ 3, "uts", SC_ARG_TYPE_TIMESPEC, timespec_decoder,(char *[]) { "uts:uts" }, 1 },
	{ 4, "sigsetsize", SC_ARG_TYPE_UINT } } },
    { 178, "sys_rt_sigqueueinfo", 0xc012b7a0, RADDR_NO, 3, 
      { { 1, "pid", SC_ARG_TYPE_PID_T },
	{ 2, "sig", SC_ARG_TYPE_INT, signal_decoder,(char *[]) { "sig:sig" }, 1 },
	{ 3, "uinfo", SC_ARG_TYPE_SIGINFO_T, siginfo_decoder,(char *[]) { "uinfo:uinfo" }, 1 } } },
    { 179, "sys_rt_sigsuspend", 0xc012c980, RADDR_NO, 2, 
      { { 1, "unewset", SC_ARG_TYPE_SIGSET_T, sigset_decoder,(char *[]) { "set:set" }, 1 },
	{ 2, "sigsetsize", SC_ARG_TYPE_UINT } } },
    { 180, "sys_pread64", 0xc01659c0, RADDR_NO, 0 },
    { 181, "sys_pwrite64", 0xc0165a40, RADDR_NO, 0 },
    { 0 },
    { 183, "sys_getcwd", 0xc017ecb0, RADDR_NO, 0 },
    { 184, "sys_capget", 0xc0126f60, RADDR_NO, 0 },
    { 185, "sys_capset", 0xc0127080, RADDR_NO, 0 },
    { 186, "sys_sigaltstack", 0xc01043e0, RADDR_NO, 0 },
    { 187, "sys_sendfile", 0xc0164d00, RADDR_NO, 0 },
    { 0 },
    { 0 },
    { 190, "sys_vfork", 0xc0102e70, RADDR_NO, 1, 
      { { 1, "regs", SC_ARG_TYPE_PT_REGS, NULL, NULL, 0, process_ptregs_loader } } },
    { 191, "sys_getrlimit", 0xc012f650, RADDR_NO, 0 },
    { 192, "sys_mmap2", 0xc010a360, RADDR_NO, 0 },
    { 193, "sys_truncate64", 0xc0163f80, RADDR_NO, 0 },
    { 194, "sys_ftruncate64", 0xc0163d90, RADDR_NO, 0 },
    { 195, "sys_stat64", 0xc016f640, RADDR_NO, 0 },
    { 196, "sys_lstat64", 0xc016f4d0, RADDR_NO, 0 },
    { 197, "sys_fstat64", 0xc016f880, RADDR_NO, 0 },
    { 198, "sys_lchown", 0xc01636d0, RADDR_NO, 0 },
    { 199, "sys_getuid", 0xc0129750, RADDR_YES, 0, { } },
    { 200, "sys_getgid", 0xc0129790, RADDR_YES, 0, { } },
    { 201, "sys_geteuid", 0xc0129770, RADDR_YES, 0, { } },
    { 202, "sys_getegid", 0xc01297b0, RADDR_YES, 0, { } },
    { 203, "sys_setreuid", 0xc012f790, RADDR_NO, 2, 
      { { 1, "ruid", SC_ARG_TYPE_UID_T }, 
	{ 2, "euid", SC_ARG_TYPE_UID_T } } },
    { 204, "sys_setregid", 0xc012f220, RADDR_NO, 2, 
      { { 1, "rgid", SC_ARG_TYPE_GID_T }, 
	{ 2, "egid", SC_ARG_TYPE_GID_T } } },
    { 205, "sys_getgroups", 0xc012e560, RADDR_NO, 0 },
    { 206, "sys_setgroups", 0xc012e1d0, RADDR_NO, 0 },
    { 207, "sys_fchown", 0xc0163530, RADDR_NO, 0 },
    { 208, "sys_setresuid", 0xc012fa30, RADDR_NO, 3, 
      { { 1, "ruid", SC_ARG_TYPE_UID_T }, 
	{ 2, "euid", SC_ARG_TYPE_UID_T }, 
	{ 3, "suid", SC_ARG_TYPE_UID_T } } },
    { 209, "sys_getresuid", 0xc012e2e0, RADDR_NO, 3, 
      { { 1, "ruid", SC_ARG_TYPE_PTR }, 
	{ 2, "euid", SC_ARG_TYPE_PTR }, 
	{ 3, "suid", SC_ARG_TYPE_PTR } } },
    { 210, "sys_setresgid", 0xc012f450, RADDR_NO, 3, 
      { { 1, "rgid", SC_ARG_TYPE_GID_T }, 
	{ 2, "egid", SC_ARG_TYPE_GID_T }, 
	{ 3, "sgid", SC_ARG_TYPE_GID_T } } },
    { 211, "sys_getresgid", 0xc012e320, RADDR_NO, 3, 
      { { 1, "rgid", SC_ARG_TYPE_PTR }, 
	{ 2, "egid", SC_ARG_TYPE_PTR }, 
	{ 3, "sgid", SC_ARG_TYPE_PTR } } },
    { 212, "sys_chown", 0xc0163790, RADDR_NO, 3, 
      { { 1, "filename", SC_ARG_TYPE_STRING }, 
	{ 2, "user", SC_ARG_TYPE_UID_T }, 
	{ 3, "group", SC_ARG_TYPE_GID_T } } },
    { 213, "sys_setuid", 0xc012f910, RADDR_NO, 1, 
      { { 1, "uid", SC_ARG_TYPE_UID_T } } },
    { 214, "sys_setgid", 0xc012f360, RADDR_NO, 1, 
      { { 1, "gid", SC_ARG_TYPE_GID_T } } },
    { 215, "sys_setfsuid", 0xc012f5a0, RADDR_NO, 1, 
      { { 1, "uid", SC_ARG_TYPE_UID_T } } },
    { 216, "sys_setfsgid", 0xc012e360, RADDR_NO, 1, 
      { { 1, "gid", SC_ARG_TYPE_GID_T } } },
    { 217, "sys_pivot_root", 0xc0183cb0, RADDR_NO, 0 },
    { 218, "sys_mincore", 0xc01537a0, RADDR_NO, 0 },
    { 219, "sys_madvise", 0xc014f340, RADDR_NO, 0 },
    { 220, "sys_getdents64", 0xc0178ba0, RADDR_NO, 0 },
    { 221, "sys_fcntl64", 0xc0178310, RADDR_NO, 0 },
    { 0 },
    { 0 },
    { 224, "sys_gettid", 0xc01297d0, RADDR_NO, 0 },
    { 225, "sys_readahead", 0xc0142370, RADDR_NO, 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 238, "sys_tkill", 0xc012bb50, RADDR_NO, 0 },
    { 239, "sys_sendfile64", 0xc0164c50, RADDR_NO, 0 },
    { 240, "sys_futex", 0xc013a090, RADDR_NO, 0 },
    { 241, "sys_sched_setaffinity", 0xc011a190, RADDR_NO, 0 },
    { 242, "sys_sched_getaffinity", 0xc0118cb0, RADDR_NO, 0 },
    { 243, "sys_set_thread_area", 0xc0103820, RADDR_NO, 0 },
    { 244, "sys_get_thread_area", 0xc0102d20, RADDR_NO, 0 },
    { 245, "sys_io_setup", 0xc0185be0, RADDR_NO, 0 },
    { 246, "sys_io_destroy", 0xc0184e60, RADDR_NO, 0 },
    { 247, "sys_io_getevents", 0xc0185330, RADDR_NO, 0 },
    { 248, "sys_io_submit", 0xc0186120, RADDR_NO, 0 },
    { 249, "sys_io_cancel", 0xc0186220, RADDR_NO, 0 },
    { 250, "sys_fadvise64", 0xc01466c0, RADDR_NO, 0 },
    { 0 },
    { 252, "sys_exit_group", 0xc0121dd0, RADDR_NO, 0 },
    { 253, "sys_lookup_dcookie", 0xc01347f0, RADDR_NO, 0 },
    { 254, "sys_epoll_create", 0xc0191560, RADDR_NO, 0 },
    { 255, "sys_epoll_ctl", 0xc0191810, RADDR_NO, 0 },
    { 256, "sys_epoll_wait", 0xc0191110, RADDR_NO, 0 },
    { 257, "sys_remap_file_pages", 0xc014e010, RADDR_NO, 0 },
    { 258, "sys_set_tid_address", 0xc011d140, RADDR_NO, 0 },
    { 259, "sys_timer_create", 0xc01332c0, RADDR_NO, 0 },
    { 260, "sys_timer_settime", 0xc0133ac0, RADDR_NO, 0 },
    { 261, "sys_timer_gettime", 0xc01339e0, RADDR_NO, 0 },
    { 262, "sys_timer_getoverrun", 0xc0133a80, RADDR_NO, 0 },
    { 263, "sys_timer_delete", 0xc0133d60, RADDR_NO, 0 },
    { 264, "sys_clock_settime", 0xc0133630, RADDR_NO, 0 },
    { 265, "sys_clock_gettime", 0xc01336e0, RADDR_NO, 0 },
    { 266, "sys_clock_getres", 0xc0133790, RADDR_NO, 0 },
    { 267, "sys_clock_nanosleep", 0xc0132cb0, RADDR_NO, 0 },
    { 268, "sys_statfs64", 0xc01640c0, RADDR_NO, 0 },
    { 269, "sys_fstatfs64", 0xc0163fc0, RADDR_NO, 0 },
    { 270, "sys_tgkill", 0xc012bb70, RADDR_NO, 0 },
    { 271, "sys_utimes", 0xc0163c00, RADDR_NO, 0 },
    { 272, "sys_fadvise64_64", 0xc01464e0, RADDR_NO, 0 },
    { 0 },
    { 274, "sys_mbind", 0xc01347f0, RADDR_NO, 0 },
    { 275, "sys_get_mempolicy", 0xc01347f0, RADDR_NO, 0 },
    { 276, "sys_set_mempolicy", 0xc01347f0, RADDR_NO, 0 },
    { 277, "sys_mq_open", 0xc01347f0, RADDR_NO, 0 },
    { 278, "sys_mq_unlink", 0xc01347f0, RADDR_NO, 0 },
    { 279, "sys_mq_timedsend", 0xc01347f0, RADDR_NO, 0 },
    { 280, "sys_mq_timedreceive", 0xc01347f0, RADDR_NO, 0 },
    { 281, "sys_mq_notify", 0xc01347f0, RADDR_NO, 0 },
    { 282, "sys_mq_getsetattr", 0xc01347f0, RADDR_NO, 0 },
    { 0 },
    { 284, "sys_waitid", 0xc0121370, RADDR_NO, 0 },
    { 0 },
    { 286, "sys_add_key", 0xc01347f0, RADDR_NO, 0 },
    { 287, "sys_request_key", 0xc01347f0, RADDR_NO, 0 },
    { 288, "sys_keyctl", 0xc01347f0, RADDR_NO, 0 },
    { 289, "sys_ioprio_set", 0xc018cc70, RADDR_NO, 0 },
    { 290, "sys_ioprio_get", 0xc018ca40, RADDR_NO, 0 },
    { 291, "sys_inotify_init", 0xc0190840, RADDR_NO, 0 },
    { 292, "sys_inotify_add_watch", 0xc01909f0, RADDR_NO, 0 },
    { 293, "sys_inotify_rm_watch", 0xc0190360, RADDR_NO, 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 0 },
    { 300, "do_exit", 0x0, RADDR_NO, 1,
      { { 1, "code", SC_ARG_TYPE_LONG, 
	  exit_code_decoder, 
	  (char *[]) { "code:cause","code:status","code:signal" },
	  3 } } },
    { 301, "force_sig_info", 0x0, RADDR_NO, 1,
      { { 1, "sig", SC_ARG_TYPE_INT, signal_decoder,(char *[]) { "sig:sig" }, 1 },
	{ 2, "info", SC_ARG_TYPE_PTR },
	{ 3, "t", SC_ARG_TYPE_PTR },
      } },
    /* generic syscall stub, used for catching returns (at addr+7) */
#define SYSCALL_RET_IX 302
    { 302, "syscall_call", 0x0, RADDR_NO, 0 },
};

#define STATS_MAX (128)
#define QUERY_MAX (256)
#define EVENT_TAG ("VMI")

char conf_statsserver[STATS_MAX+1] = "127.0.0.1:8989";
char conf_querykey[QUERY_MAX+1] = "index.html?op=pub&type=event&event=";

static struct sockaddr_in stats_sock;
/*
 * Open our connection to the stats server
 */
static int open_statsserver(void)
{
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct timeval tv;
        int flags;

        /*
         * Wow, never realized what a stunning pain-in-the-ass it is to
         * put a timeout on a connect operation!
         */
        flags = fcntl(sock, F_GETFL, 0);
        if (fcntl(sock, F_SETFL, flags|O_NONBLOCK)) {
            close(sock);
            return -2;
        }
        if (connect(sock, (struct sockaddr *)&stats_sock, sizeof stats_sock)) {
            fd_set fds;
            int err = errno;
            socklen_t len;

            if (err != EINPROGRESS) {
                close(sock);
                return -3;
            }

            FD_ZERO(&fds);
            FD_SET(sock, &fds);
            tv.tv_sec = 5;
            tv.tv_usec = 0;
            if (select(sock+1, NULL, &fds, NULL, &tv) != 1) {
                close(sock);
                return -4;
            }
            err = 0;
            len = sizeof err;
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) ||
                    err != 0) {
                fprintf(stderr, "Connect to stats server returned %d\n", err);
                close(sock);
                return -5;
            }
        }
        if (fcntl(sock, F_SETFL, flags)) {
            close(sock);
            return -6;
        }

        /*
         * Okay, that was a hoot, now we STILL need to set the socket
         * non-blocking for write!
         */
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv)) {
            close(sock);
            return -7;
        }
    }

    return sock;
}

int web_init(void)
{
    char *ip, *port;
    int fd;

    if (conf_statsserver == NULL)
        return 0;

    ip = conf_statsserver;
    port = index(ip, ':');
    if (port == NULL || ip == port || port[1] == '\0') {
        error("could not parse statsserver '%s'\n",conf_statsserver);
        return 1;
    }
    *port++ = '\0';
    if (!inet_aton(ip, &stats_sock.sin_addr)) {
        error("statsserver addr must be an IP address\n");
        return 1;
    }
    stats_sock.sin_port = htons(atoi(port));
    stats_sock.sin_family = AF_INET;

    /* make sure we can talk to the server */
    fd = open_statsserver();
    if (fd < 0) {
        error("could not talk to statsserver at %s (%d)\n",
                conf_statsserver, fd);
        return 1;
    }
    close(fd);

    fprintf(stderr,"Stats web server at \"%s:%d\"\n",
            inet_ntoa(stats_sock.sin_addr), ntohs(stats_sock.sin_port));
    return 0;
}

int web_report(const char *msg,const char *extras)
{
    char *statbuf = NULL;
    int sock, rv = 0;

    statbuf = (char *) malloc( strlen(msg) + QUERY_MAX + 128 );
    if (!statbuf) return 1;
    sprintf(statbuf, "GET /%s%s:%%20%s&%s HTTP/1.1\n"
	    "Host: a3\n\n", conf_querykey, EVENT_TAG, msg, extras);

    sock = open_statsserver();
    if (sock >= 0)
    {
        if (write(sock, statbuf, strlen(statbuf)+1) < 0) 
        {
            error("write to socket failed (%d)\n", errno);
            rv = 1;
        }
        close(sock);
    }
    else
    {
        rv = 1;
    }

    free(statbuf);

    return rv;
}

void load_arg_data(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		   int pid,int i,int j,
		   struct argdata **arg_data,
		   struct process_data *pdata) {
    //char *syscallname = sctab[i].name;
    //char *name = sctab[i].args[j].name;
    sc_arg_type_t mytype = sctab[i].args[j].type;
    unsigned long argval;
    unsigned char *data = NULL;
    unsigned long buflen = 0;
    int isstring = 0;
    int data_len_arg_num = sctab[i].args[j].len_arg_num;

    /*
     * It is possible that we already fetched the data for this argument.
     */    
    if (arg_data[j]->data != NULL || arg_data[j]->str != NULL) {
	return;
    }

    /*
     * Some syscall args require a buffer length that is passed as
     * a seperate argument. Grab that value here, reading the arg
     * as necessary.
     */
    if (data_len_arg_num > 0) {
	if (arg_data[data_len_arg_num-1]->data == NULL) {
	    load_arg_data(handle,regs,pid,i,data_len_arg_num-1,arg_data,pdata);
	    if (arg_data[data_len_arg_num-1]->data == NULL)
		return;
	}
	buflen = *(unsigned long *)arg_data[data_len_arg_num-1]->data;
    }

    switch (j)
    {
    case 0: 
	if (i == 300)
	    argval = regs->eax;
	else if (i == 301)
	    argval = regs->eax;
	else
	    argval = regs->ebx;
	break;
    case 1:
	argval = regs->ecx;
	break;
    case 2: 
#if 0
    /* dump a bit of the stack on the first extra arg */
    {
	unsigned long *lp;
	int ix;
	data = vmprobe_get_data(handle,regs,"syscall_argi", regs->esp,
				0, 64, NULL);
	lp = (unsigned long *)data;
	printf("*** sp=0x%08x:\n", regs->esp);
	for (ix = 0; ix < 16; ix += 4) {
	    printf("    0x%08lx 0x%08lx 0x%08lx 0x%08lx\n",
		   lp[ix+0], lp[ix+1], lp[ix+2], lp[ix+3]);
	}
	free(data);
    }
#endif
    case 3:
    case 4:
    case 5:
	//argval = regs->edx;
	data = vmprobe_get_data(handle,regs,
				"syscall_argi",
				regs->esp + 4 + j*4,
				0,
				sizeof(unsigned long *),
				NULL);
	unsigned long edx_addr = *((unsigned long *)data);
	free(data);
	argval = edx_addr;
	break;
    default:
	arg_data[j]->str = strdup("<more than 6 args>");
	return;
    }

    switch (mytype) {
    case SC_ARG_TYPE_INT:
    case SC_ARG_TYPE_SIZE_T:
    case SC_ARG_TYPE_PID_T:
    case SC_ARG_TYPE_UID_T:
    case SC_ARG_TYPE_GID_T:
    case SC_ARG_TYPE_OFF_T:
    case SC_ARG_TYPE_TIME_T:
    case SC_ARG_TYPE_UINT:
    case SC_ARG_TYPE_LONG:
    case SC_ARG_TYPE_ULONG:
    case SC_ARG_TYPE_PTR:
    case SC_ARG_TYPE_HEXINT:
	arg_data[j]->data = malloc(sizeof(unsigned long int));
	memcpy(arg_data[j]->data,(void *)&argval,sizeof(unsigned long int));

	if (mytype == SC_ARG_TYPE_INT || mytype == SC_ARG_TYPE_SIZE_T
	    || mytype == SC_ARG_TYPE_PID_T || mytype == SC_ARG_TYPE_UID_T
	    || mytype == SC_ARG_TYPE_GID_T || mytype == SC_ARG_TYPE_OFF_T
	    || mytype == SC_ARG_TYPE_TIME_T) {
	    arg_data[j]->str = ssprintf("%d",*(int *)arg_data[j]->data);
	}
	else if (mytype == SC_ARG_TYPE_UINT) {
	    arg_data[j]->str = ssprintf("%du",*(unsigned int *)arg_data[j]->data);
	}
	else if (mytype == SC_ARG_TYPE_LONG) {
	    arg_data[j]->str = ssprintf("%l",*(long *)arg_data[j]->data);
	}
	else if (mytype == SC_ARG_TYPE_ULONG) {
	    arg_data[j]->str = ssprintf("%lu",*(unsigned long *)arg_data[j]->data);
	}
	else if (mytype == SC_ARG_TYPE_PTR || mytype == SC_ARG_TYPE_HEXINT) {
	    arg_data[j]->str = ssprintf("0x%08x",*(unsigned int *)arg_data[j]->data);
	}
	break;

    /* null-terminated, printable string */
    case SC_ARG_TYPE_STRING:
	isstring = 1;
	/* fall into BYTES... */

    /* array of bytes */
    case SC_ARG_TYPE_BYTES:
	if (!argval) {
	    arg_data[j]->str = strdup("NULL");
	    return;
	}

	/*
	 * Make sure data is valid.
	 * - All strings are considered "in" params.
	 * - Byte arrays for read (3) and syslog (103) are "out",
	 *   all others (write) are "in".
	 * "in" data we can print on either side of the syscall.
	 * "out" data is only printed post-syscall.
	 */
	switch (i) {
	/* out */
	case 3: case 103:
	    if (!arg_data[j]->postcall) {
		arg_data[j]->str = strdup("<undef>");
		return;
	    }
	    break;
	/* in: */
	default:
	    break;
	}

	if (buflen) {
	    if (isstring && buflen > ARG_STRING_LEN)
		buflen = ARG_STRING_LEN;
	    else if (!isstring && buflen > ARG_BYTES_LEN)
		buflen = ARG_BYTES_LEN;

	    arg_data[j]->data = malloc(sizeof(char *)*(buflen+1));
	    data = vmprobe_get_data(handle,regs,
				    "syscall_argi_bytes",argval,
				    pid,buflen,arg_data[j]->data);
	    if (!data) {
		arg_data[j]->str = strdup("<data access error>");
		return;
	    }
	    arg_data[j]->data[buflen] = '\0';
	}
	else if (!isstring) {
	    arg_data[j]->str = strdup("<need a buffer length>");
	    return;
	}
	else {
	    buflen = sc_arg_type_len[mytype];
	    arg_data[j]->data = vmprobe_get_data(handle,regs,
					   "syscall_argi_string",argval,
					   pid,buflen,NULL);
	    if (arg_data[j]->data == NULL) {
		arg_data[j]->str = strdup("<data access error>");
		return;
	    }
	}
	if (isstring) {
	    arg_data[j]->str = (char *)arg_data[j]->data;
	} else {
	    int cc;
	    char *bp, *dp;

	    cc = buflen < 8 ? buflen : 8;
	    arg_data[j]->str = bp = malloc(cc*2 + 6);
	    dp = (char *)arg_data[j]->data;
	    strcpy(bp, "0x");
	    bp += 2;
	    while (cc-- > 0) {
		sprintf(bp, "%02x", *dp++);
		bp += 2;
	    }
	    strcpy(bp, "...");
	}
	break;

    default:
	if (!argval) {
	    arg_data[j]->str = strdup("NULL");
	    return;
	}
	if (sctab[i].args[j].al != NULL) {
	    arg_data[j]->data =
		(unsigned char *)sctab[i].args[j].al(handle,regs,pid,i,j,
						     argval,arg_data,pdata);
	}
	else {
	    arg_data[j]->data = vmprobe_get_data(handle,regs,
						 "syscall_argi_default",argval,
						 pid,
						 sc_arg_type_len[mytype],
						 NULL);
	    if (arg_data[j]->data == NULL) {
		arg_data[j]->str = strdup("<data access error>");
		return;
	    }
	    arg_data[j]->str = ssprintf("0x%08x", (uint32_t)argval);
	}
	break;
    }
}

int dofilter = 1;
int send_a3_events = 0;
char *domainname;
vmprobe_action_handle_t va;
char *configfile = NULL;
int reloadconfigfile = 0;
FILE *filtered_events_fd = NULL;

char from_hex(char ch) {
    return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

char to_hex(char code) {
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

char *url_encode(char *str) {
    char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
    while (*pstr) {
	if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') 
	    *pbuf++ = *pstr;
	else if (*pstr == ' ') 
	    *pbuf++ = '+';
	else 
	    *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
	pstr++;
    }
    *pbuf = '\0';
    return buf;
}

int execcounter = 0;
	    
struct argfilter *handle_syscall(vmprobe_handle_t handle,
				 struct cpu_user_regs *regs,
				 char **psstr,char **funcstr,char **argstr,
				 char **ancestry)
{
    unsigned long addr = vmprobe_vaddr(handle);
    uint32_t oi, i = regs->eax;
    int j,k;
    struct argdata **adata;
    struct argfilter *filter_ptr = NULL;
    struct process_data *data;
    char *psliststr = NULL;
    int mypid, dopslist = 0;
    int len, rc;
    struct cpu_user_regs tregs, *aregs = regs;
    int postcall = 0, needpost = 0;
    char *rvalstr = NULL;

    /*
     * Handle syscall returns. Only do something for those we care about.
     */
    if (addr == sctab[SYSCALL_RET_IX].addr) {
	struct syscall_retinfo *sc;
	unsigned long curthread;
	int found = 0;

#ifndef STATIC_RET_PROBE
	if (list_empty(&syscalls)) {
	    fprintf(stderr,"ERROR: syscall return with none pending!\n");
	    return NULL;
	}
#endif

	/* figure out who is running */
	curthread = current_thread_ptr(regs->esp);

	/* see if they have a pending return action */
	list_for_each_entry(sc, &syscalls, list) {
	    if (sc->thread_ptr == curthread) {
		found++;
		break;
	    }
	}

	/* if not, we are done */
	if (!found) {
	    return NULL;
	}

	/* remove ourselves from the list */
	list_del(&sc->list);

	/* for the purpose of extracting arguments, we need pre-call values */
	tregs = *regs;
	tregs.ebx = sc->arg0;
	tregs.ecx = sc->arg1;
	tregs.esp = sc->argptr;
	aregs = &tregs;

	debug(1, "Syscall %d return for thread 0x%lx\n",
	      sc->syscall_ix, curthread);

#ifndef STATIC_RET_PROBE
	/* deregister the probe if no other process has it scheduled */
	if (list_empty(&syscalls)) {
	    /* remove probe */
	    ;	
	}
#endif

	oi = SYSCALL_RET_IX;
	i = sc->syscall_ix;
	postcall = 1;

	/* dealloc the struct */
	free(sc);
    }

    // hack to catch do_exit too!
    else if (addr == sctab[300].addr) {
	oi = i = 300;
    }
    else if (addr == sctab[301].addr) {
	oi = i = 301;
    }
    // Even when the syscall number appears legit, check that the
    // address is consistent. If one of the syscall probes is triggered
    // due to an intra-kernel use, eax may not have the correct value.
    else if (i >= 0 && i < SYSCALL_MAX && addr != sctab[i].addr) {
	debug(0,"WARNING: ignoring internal use of syscall@0x%lx (i==%d)\n",
	      addr, i);
	return NULL;
    }
#if 0
    // Empirically, we have discovered that these can be called when
    // the syscall number is not in eax. Ignore these, I think they are
    // kernel-internal calls.
    else if ((addr == sctab[6].addr && i != 6) ||
	     (addr == sctab[114].addr && i != 114)) {
	debug(0,"WARNING: ignoring internal use of syscall@0x%lx\n",addr);
	return NULL;
    }
#endif
    else {
	if (i == 11) {
	    ++execcounter;
	}
	oi = i;
    }

    if (i < 0 || i >= SYSCALL_MAX) {
	// This is a break point we set, so we must at least know the address.
	// These may be internal uses of syscalls where eax is not set right.
	for (j = 0; j < SYSCALL_MAX; j++) {
	    if (addr == sctab[j].addr) {
		fprintf(stderr,"ERROR: invalid syscall #%d %s[dom%d 0x%lx], "
			"but addr matches syscall %d (%s)\n",
			i, oi == SYSCALL_RET_IX ? "(after) " : "",
			vmprobe_domid(handle), addr, j, sctab[j].name);
		return NULL;
	    }
	}
	fprintf(stderr,"ERROR: invalid syscall #%d %s[dom%d 0x%lx] ignored\n",
		i, oi == SYSCALL_RET_IX ? "(after) " : "",
		vmprobe_domid(handle), addr);
	return NULL;
    }
    if (sctab[i].num == 0) {
	fprintf(stderr,"ERROR: unknown syscall #%d %s[dom%d 0x%lx] ignored\n",
		sctab[i].num, oi == SYSCALL_RET_IX ? "(after) " : "",
		vmprobe_domid(handle), addr);
	return NULL;
    }

    fprintf(stdout,"%s [dom%d 0x%lx]",
	    sctab[i].name, vmprobe_domid(handle), addr);
    if (oi == SYSCALL_RET_IX)
	fprintf(stdout, " (rval=%d)", regs->eax);
    fprintf(stdout, "\n");
    fflush(stdout);

    adata = (struct argdata **)malloc(sizeof(struct argdata *)*sctab[i].argc);
    memset(adata,0,sizeof(struct argdata *)*sctab[i].argc);

    data = load_current_process_data(handle,regs,-1);

#if 0
    /* Lets grab the return address */
    if (oi != SYSCALL_RET_IX) {
	unsigned long raddr, loc;
	loc = (unsigned long)regs->esp - 0;
	if (vmprobe_get_data(handle, regs, "syscall_raddr", loc, 0,
			     sizeof(raddr), (unsigned char *)&raddr) == NULL)
		raddr = 0x69696969;
	printf("%s: sp=%x, addr=%lx, value=%lx\n",
	       sctab[i].name, regs->esp, loc, raddr);
	fflush(stdout);
    }
#endif

    for (j = 0; j < sctab[i].argc; ++j) {
	adata[j] = (struct argdata *)malloc(sizeof(struct argdata));
	memset(adata[j],0,sizeof(struct argdata));

	adata[j]->info = &sctab[i].args[j];
	adata[j]->data = NULL;
	adata[j]->str = NULL;
	/* XXX I don't want to change every decoder to have extra arg */
	adata[j]->postcall = postcall;

	if (sctab[i].args[j].decodings_len) {
	    adata[j]->decodings = (char **)malloc(sizeof(char *)*sctab[i].args[j].decodings_len);
	    memset(adata[j]->decodings,0,sizeof(char *)*sctab[i].args[j].decodings_len);

	    debug(1,"initialized mem for %d decodings for %s:%s\n",
		  sctab[i].args[j].decodings_len,sctab[i].name,
		  sctab[i].args[j].name);
	}
	else
	    adata[j]->decodings = NULL;
    }

    for (j = 0; j < sctab[i].argc; ++j) {
	load_arg_data(handle,aregs,data->pid,i,j,adata,data);

	debug(1,"loaded arg data for %s:%s\n",sctab[i].name,
	      sctab[i].args[j].name);
	if (sctab[i].args[j].ad) {
	    sctab[i].args[j].ad(handle,aregs,data->pid,i,j,adata,data);
	    debug(1,"decoded mem for %d decodings for %s:%s\n",
		  sctab[i].args[j].decodings_len,sctab[i].name,
		  sctab[i].args[j].name);
	}

	debug(1,"about to print str 0x%08x for %s:%s (0x%08x, 0x%08x)\n",
	      (unsigned int)(adata[j]->str),sctab[i].name,sctab[i].args[j].name,
	      (unsigned int)(adata[j]->info), (unsigned int)(adata[j]->info ? adata[j]->info->name : 0));

#ifndef OLD_VPG_COMPAT
	if (debug >= 0)
#endif
	{
	    printf("  %s: ",sctab[i].args[j].name);
	    fflush(stdout);
	    printf("%s\n",adata[j]->str);
	    fflush(stdout);
	}

	for (k = 0; k < adata[j]->info->decodings_len; ++k) {
#ifndef OLD_VPG_COMPAT
	    if (debug >= 0)
#endif
	    {
		if (adata[j]->decodings[k])
		    printf("    %s: %s\n",
			   adata[j]->info->decodings[k],
			   adata[j]->decodings[k]);
		else
		    printf("    %s: NULL\n",
			   adata[j]->info->decodings[k]);
		fflush(stdout);
	    }
	}
    }

    /* XXX hack return value handling: for now it is just an int */
    if (postcall) {
	rvalstr = ssprintf("%ld", regs->eax);

#ifndef OLD_VPG_COMPAT
	if (debug >= 0)
#endif
	{
	    printf("  ret_value: %s\n", rvalstr);
	    fflush(stdout);
	}
    }

    for (j = 0; j < sctab[i].argc; ++j) {
	if (check_filters(i,j,adata,data,rvalstr,&filter_ptr,&needpost))
	    break;
    }

    *psstr = ssprintf("pid=%d name=%s ppid=%d",data->pid,data->name,data->ppid);
    *funcstr = strdup(sctab[i].name);

    /* Track our ancestry */
    if (ancestry) {
	struct process_data *_pdata = data;
	char *str;
	int len;

	/* allow 128 chars per process */
	for (len = 0; _pdata != NULL; len += 128)
	    _pdata = _pdata->parent;
	str = *ancestry = (char *)malloc(len);

	_pdata = data;
	while (_pdata) {
	    snprintf(str, 128,
		     "    pid=%d,name=%s,ppid=%d,rppid=%d,tgid=%d,"
		     "uid=%d,euid=%d,suid=%d,gid=%d,egid=%d,sgid=%d\n",
		     _pdata->pid,_pdata->name,_pdata->ppid,_pdata->real_ppid,
		     _pdata->tgid,_pdata->uid,_pdata->euid,_pdata->suid,
		     _pdata->gid,_pdata->egid,_pdata->sgid);
	    str += strlen(str);
	    _pdata = _pdata->parent;
	}
    }

    mypid = data->pid;
    free_process_data(data);

    len = 0;
    for (j = 0; j < sctab[i].argc; ++j) {
	debug(1,"%s len = %d\n",sctab[i].args[j].name,len);
	len = len + 2 + strlen(sctab[i].args[j].name);
	if (adata[j]->str)
	    len = len + strlen(adata[j]->str);
	else 
	    len = len + 6;
	debug(1,"%s len = %d\n",sctab[i].args[j].name,len);

	for (k = 0; k < adata[j]->info->decodings_len; ++k) {
	    debug(1,"%s len = %d\n",sctab[i].args[j].decodings[k],len);
	    len = len + 2 + strlen(sctab[i].args[j].decodings[k]);
	    if (adata[j]->decodings[k])
		len = len + strlen(adata[j]->decodings[k]);
	    else 
		len = len + 6;
	    debug(1,"%s len = %d\n",sctab[i].args[j].decodings[k],len);
	}
    }

    /* XXX return value hack */
    if (rvalstr) {
	len += strlen("ret_value") + 1;
	len += strlen(rvalstr);
    }

    *argstr = malloc(len+1);

    rc = 0;
    for (j = 0; j < sctab[i].argc; ++j) {
	debug(1,"rc = %d\n",rc);
	rc += sprintf((*argstr)+rc,"%s=%s,",sctab[i].args[j].name,adata[j]->str);
	debug(1,"rc = %d\n",rc);

	for (k = 0; k < sctab[i].args[j].decodings_len; ++k) {
	    debug(1,"rc = %d\n",rc);
	    rc += sprintf((*argstr)+rc,"%s=%s,",
			  sctab[i].args[j].decodings[k],adata[j]->decodings[k]);
	    debug(1,"rc = %d\n",rc);
	}
    }

    /* XXX return value hack */
    if (rvalstr) {
	rc += sprintf((*argstr)+rc, "ret_value=%s", rvalstr);
	free(rvalstr);
    }

    (*argstr)[len] = '\0';

    for (j = 0; j < sctab[i].argc; ++j) {
	if (adata[j])
	    free_argdata(adata[j]);
    }
    free(adata);

    /*
     * See if we need to report a process list.
     *
     * As an optimization, if the user has specified a set of processes of
     * interest, we only send a list if the (waitpid,execve,fork,vfork,clone)
     * operation involved one of those processes.
     */

    /*
     * If doing a waitpid, we have to refresh the process list
     * before the call, since after the call the process of interest
     * will no longer exist!
     *
     * Note that lots of other syscalls might happen between the waitpid
     * call and the waitpid return, but at any of those syscalls, the
     * process whose pid is ultimately returned by our waipid will still
     * exist. One complication is if the last such syscall is exec, then
     * the process name will be the pre-exec'ed value. We address that
     * below by updating the process list post-exec.
     */
    if (!strcmp(sctab[i].name,"sys_waitpid")) {
	if (!postcall) {
	    reload_process_list(handle,regs);
#if 0
	    if (debug >= 0) {
		printf("pre-waitpid, reloaded process list:\n");
		print_process_list();
	    }
#endif
	} else {
#if 0
	    if (debug >= 0) {
		printf("post-waitpid, process list:\n");
		print_process_list();
	    }
#endif
	    if (regs->eax > 0 && pid_in_pslist(regs->eax)) {
		reload_process_list(handle,regs);
		dopslist = 1;
	    }
	}
    }
    /*
     * For fork, exec, et.al. we check before the call and see if the
     * caller is a process of interest.
     */
    else if (!postcall && (!strcmp(sctab[i].name,"sys_execve")
			   || !strcmp(sctab[i].name,"sys_fork")
			   || !strcmp(sctab[i].name,"sys_vfork")
			   || !strcmp(sctab[i].name,"sys_clone"))) {
	reload_process_list(handle,regs);
	if (pid_in_pslist(mypid))
	    dopslist = 1;

	/* If this is exec we may need a post-syscall probe */
	if (!needpost && ps_list_len && !strcmp(sctab[i].name,"sys_execve"))
	    needpost = 1;
    }
    /*
     * If we are post-exec, we update the process list to reflect
     * the new identity of the exec'ed process.
     */
    else if (postcall && !strcmp(sctab[i].name,"sys_execve")) {
	reload_process_list(handle,regs);
    }

    /*
     * Send the process list.
     */
    if (dopslist) {
	char *eventstrtmp, *eventstr = NULL;
	char *name_trunc, *dstr, *extras = NULL;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	psliststr = process_list_to_string(handle,regs,"|");

#ifndef OLD_VPG_COMPAT
	if (debug >= 0)
#endif
	{
	    printf("\nCurrent Process List:\n%s\n",psliststr);
	    fflush(stdout);
	}

	eventstrtmp = ssprintf("domain=%s type=pslist %s",
			       domainname,psliststr);
	if (eventstrtmp)
	    eventstr = url_encode(eventstrtmp);
	name_trunc = NULL; // strrchr(domainname,'-');
	dstr = url_encode(name_trunc ? name_trunc + 1 :domainname);
	if (dstr) {
	    uint64_t ems = ((uint64_t)tv.tv_sec) * 1000 +
		    ((uint64_t)tv.tv_usec)/1000;
	    extras = ssprintf("&ts=%llu&origin=%s&vmid=%s&eventtype=%s",
			      ems,"VMI",dstr,"OBS");
	}

	if (send_a3_events) {
	    if (eventstr && extras) {
		web_report(eventstr,extras);
	    }
	    else {
		error("internal error 2 reporting pslist to A3 monitor!\n");
	    }
	}

#ifndef OLD_VPG_COMPAT
	if (debug < 0)
	    printf(" (would send 'pslist' to A3)\n");
	else
#endif
	printf(" (would send '%s' and '%s' to A3)\n",eventstr,extras);
	fflush(stdout);

	if (eventstr)
	    free(eventstr);
	if (dstr)
	    free(dstr);
	if (extras)
	    free(extras);
	if (eventstrtmp)
	    free(eventstrtmp);

	if (psliststr)
	    free(psliststr);
    }

    /*
     * Schedule any post action required.
     */
    if (!postcall && needpost) {
	if (sctab[i].raddr != RADDR_NO) {
	    struct syscall_retinfo *sc;

	    sc = malloc(sizeof(*sc));
	    if (sc == NULL) {
		fprintf(stderr, "ERROR: cannot alloc syscall return struct\n");
		return NULL;
	    }
	    sc->thread_ptr = current_thread_ptr(regs->esp);
	    sc->syscall_ix = i;
	    sc->arg0 = regs->ebx;
	    sc->arg1 = regs->ecx;
	    sc->argptr = regs->esp;
	    list_add_tail(&sc->list, &syscalls);

#ifndef STATIC_RET_PROBE
	    if (list_empty(&syscalls)) {
		/* register probe */
		;
	    }
#endif
	    debug(1, "Registered syscall %d return probe for thread 0x%x\n",
		  sc->syscall_ix, sc->thread_ptr);
	}
    }

    return filter_ptr;
}

static int on_fn_pre(vmprobe_handle_t vp, 
		     struct cpu_user_regs *regs)
{
    char *psstr = NULL;
    char *funcstr = NULL;
    char *argstr = NULL;
    char *ancestry = NULL;
    struct argfilter *filter;
    char *eventstr = NULL;
    char *eventstrtmp = NULL;
    char *extras = NULL;
    char *dstr = NULL;
    char *gfilterstr = " (not filtering; globally off!)";

    va = -1;

#ifdef OLD_VPG_COMPAT
    /* for compat, ignore ancestry (a recent mike-ism) */
    filter = handle_syscall(vp,regs,&psstr,&funcstr,&argstr,NULL);
#else
    filter = handle_syscall(vp,regs,&psstr,&funcstr,&argstr,
			    filtered_events_fd ? &ancestry : NULL);
#endif
    if (filter) {
	char *name_trunc;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	name_trunc = NULL; // strrchr(domainname,'-');
	dstr = url_encode(name_trunc ? name_trunc + 1 :domainname);

	/* XXX */
	int postcall = (vmprobe_vaddr(vp) == sctab[SYSCALL_RET_IX].addr);

	if (dofilter) 
	    gfilterstr = "";

	if (!filter->dofilter) {
#ifndef OLD_VPG_COMPAT
	    if (debug >= 0)
#endif
	    printf(" Filter (noadjust) matched: %d %d %s (%d %d (%d) %d %d)%s\n",
		  filter->syscallnum,
		  filter->argnum == -1 ? regs->eax : filter->argnum,
		  filter->strfrag,
		  filter->pid,
		  filter->ppid,
		  filter->ppid_search,
		  filter->uid,
		  filter->gid,
		  gfilterstr);

	    eventstrtmp = ssprintf("domain=%s type=match when=%s %s %s(%s)",
				   domainname,(postcall?"post":"pre"),
				   psstr,funcstr,argstr);
	    if (eventstrtmp)
		eventstr = url_encode(eventstrtmp);

	    if (filtered_events_fd != NULL) {
		fprintf(filtered_events_fd, "%u.%03u: %s\n",
			(unsigned)tv.tv_sec, (unsigned)(tv.tv_usec/1000),
			eventstrtmp);
		if (ancestry)
		    fprintf(filtered_events_fd, "  Pid lineage:\n%s\n", ancestry);
		fflush(filtered_events_fd);
	    }

	    if (dstr) {
		uint64_t ems = ((uint64_t)tv.tv_sec) * 1000 +
			((uint64_t)tv.tv_usec)/1000;
		extras = ssprintf("&ts=%llu&origin=%s&vmid=%s&eventtype=%s",
				  ems,"VMI",dstr,"OBS");
	    }

	    if (send_a3_events) {
		if (eventstr && extras) {
		    web_report(eventstr,extras);
		}
		else {
		    error("internal error 2 reporting match-abort-returning to A3 monitor!\n");
		}
	    }

	    if (eventstr && extras) {
#ifndef OLD_VPG_COMPAT
		if (debug < 0)
		    printf(" (would send 'match' (filt #%d) to A3)\n",
			   filter->index);
		else
#endif
		printf(" (would send '%s' and '%s' to A3)\n",eventstr,extras);
	    }
	}
	else {
#ifndef OLD_VPG_COMPAT
	    if (debug >= 0)
#endif
	    printf(" Filter (adjust) matched: %d %d(%d) %s (%d %d (%d) %d %d) -- returning %d!%s\n",
		  filter->syscallnum,
		  filter->argnum,
		  filter->decoding,
		  filter->strfrag,
		  filter->pid,
		  filter->ppid,
		  filter->ppid_search,
		  filter->uid,
		  filter->gid,
		  filter->abort_retval,
		  gfilterstr);

	    if (!dofilter) 
		eventstrtmp = ssprintf("domain=%s type=would-abort retval=%d %s %s(%s)",
				       domainname,filter->abort_retval,psstr,funcstr,argstr);
	    else 
		eventstrtmp = ssprintf("domain=%s type=abort retval=%d %s %s(%s)",
				       domainname,filter->abort_retval,psstr,funcstr,argstr);
	    if (eventstrtmp)
		eventstr = url_encode(eventstrtmp);

	    if (filtered_events_fd != NULL) {
		fprintf(filtered_events_fd, "%u.%03u: %s\n",
			(unsigned)tv.tv_sec, (unsigned)(tv.tv_usec/1000),
			eventstrtmp);
		if (ancestry)
		    fprintf(filtered_events_fd, "  Pid lineage:\n%s\n", ancestry);
		fflush(filtered_events_fd);
	    }

	    if (dstr) {
		uint64_t ems = ((uint64_t)tv.tv_sec) * 1000 +
			((uint64_t)tv.tv_usec)/1000;
		extras = ssprintf("&ts=%llu&origin=%s&vmid=%s&eventtype=%s",
				  ems,"VMI",dstr,!dofilter ? "OBS" : "ENF");
	    }

	    if (send_a3_events) {
		if (eventstr && extras) {
		    web_report(eventstr,extras);
		}
		else {
		    error("internal error 2 reporting match-abort-returning to A3 monitor!\n");
		}
	    }

	    if (eventstr && extras) {
#ifndef OLD_VPG_COMPAT
		if (debug < 0)
		    printf(" (would send '%s' to A3)\n",dofilter?"abort":"would-abort");
		else
#endif
		printf(" (would send '%s' and '%s' to A3)\n",eventstr,extras);
	    }

	    if (dofilter) {
		va = action_return(filter->abort_retval);
		action_sched(vp,va,VMPROBE_ACTION_ONESHOT);
	    }
	}
    }

    if (eventstr)
	    free(eventstr);
    if (eventstrtmp)
	    free(eventstrtmp);
    if (dstr)
	    free(dstr);
    if (extras)
	    free(extras);

    if (psstr)
	free(psstr);
    if (funcstr)
	free(funcstr);
    if (argstr)
	free(argstr);
    if (ancestry)
	free(ancestry);

    return 0;
}

static int on_fn_post(vmprobe_handle_t vp, 
		      struct cpu_user_regs *regs)
{
    if (va != -1) 
	action_destroy(va);

    return 0;
}

void usrsighandle(int signo) {
    dofilter = !dofilter;
    fprintf(stderr,"Resetting global filtering to %d.\n",dofilter);
    signal(signo,usrsighandle);
}

void hupsighandle(int signo) {
    reloadconfigfile = 1;
    interrupt_vmprobes();
    signal(signo,hupsighandle);
}

int load_config_file(char *file,char ***new_function_list,int *new_function_list_len,
		     struct argfilter ***new_argfilter_list,int *new_argfilter_list_len,
		     char ***new_ps_list,int *new_ps_list_len) {
    char *buf;
    char *bufptr;
    char *tbuf;
    int bufsiz = 128;
    int rc = 0;
    FILE *ffile;
    char **flist = NULL;
    int flist_alloclen = 8;
    int flist_len = 0;
    struct argfilter *filter = NULL;
    struct argfilter **alist;
    int alist_alloclen = 8;
    int alist_len = 0;
    char **pslist = NULL;
    int pslist_alloclen = 8;
    int pslist_len = 0;
    char *saveptr, *token = NULL;
    char *saveptr2, *token2 = NULL;
    char errbuf[128];
    int i = 0;
    int j;
    char *var = NULL, *val = NULL;

    ffile = fopen(file,"r");
    if (!ffile) {
	fprintf(stderr,"ERROR: could not fopen filter file %s: %s\n",file,strerror(errno));
	fflush(stderr);
	return -1;
    }

    alist = (struct argfilter **)malloc(sizeof(struct argfilter *)*alist_alloclen);
    flist = (char **)malloc(sizeof(char *)*flist_alloclen);
    pslist = (char **)malloc(sizeof(char *)*pslist_alloclen);

    // read directives line by line.
    buf = malloc(bufsiz);
    while (1) {
	rc = 0;
	while (1) {
	    errno = 0;
	    tbuf = fgets(buf,bufsiz,ffile);
	    if (tbuf && (rc += strlen(buf)) == (bufsiz-1) && buf[bufsiz-2] != '\n') {
		// we filled up the buf; malloc more and keep going
		tbuf = malloc(bufsiz+128);
		memcpy(tbuf,buf,bufsiz);
		free(buf);
		buf = tbuf;
	    }
	    else if (tbuf && rc < bufsiz) {
		// we have our line
		break;
	    }
	    else if (errno) {
		fprintf(stderr,"ERROR: fgets: %s (aborting filter file read)\n",strerror(errno));
		fflush(stderr);
		goto errout;
	    }
	    else {
		// EOF
		free(buf);
		buf = NULL;
		break;
	    }
	}

	if (!buf)
	    break;

	debug(2,"read line %s",buf);

	if (*buf == '#')
	    continue;

	if (buf[strlen(buf)-1] == '\n') {
	    if (*buf == '\n')
		continue;
	    buf[strlen(buf)-1] = '\0';
	}

	if (strncmp(buf,"Functions",strlen("Functions")) == 0) {
	    bufptr = buf + 9;
	    while (*bufptr == ' ' || *bufptr == '\t')
		++bufptr;

	    token = NULL;
	    saveptr = NULL;
	    while ((token = strtok_r((!token)?bufptr:NULL,",",&saveptr))) {
		if (flist_alloclen == flist_len) {
		    flist_alloclen += 8;
		    if (!(flist = realloc(flist,sizeof(char *)*flist_alloclen))) {
			fprintf(stderr,"ERROR: filter file format: realloc: %s\n",strerror(errno));
			goto errout;
		    }
		}

		flist[flist_len] = strdup(token);
		++flist_len;
		debug(2,"read function %s\n",token);
	    }
	}
	else if (strncmp(buf,"ProcessListNames",strlen("ProcessListNames")) == 0) {
	    bufptr = buf + strlen("ProcessListNames");
	    while (*bufptr == ' ' || *bufptr == '\t')
		++bufptr;

	    token = NULL;
	    saveptr = NULL;
	    while ((token = strtok_r((!token)?bufptr:NULL,",",&saveptr))) {
		if (pslist_alloclen == pslist_len) {
		    pslist_alloclen += 8;
		    if (!(pslist = realloc(pslist,sizeof(char *)*pslist_alloclen))) {
			fprintf(stderr,"ERROR: filter file format: realloc: %s\n",strerror(errno));
			goto errout;
		    }
		}

		pslist[pslist_len] = strdup(token);
		++pslist_len;
		debug(2,"read ps list name %s\n",token);
	    }
	}
	else if (strncmp(buf,"Filter",strlen("Filter")) == 0) {
	    bufptr = buf + 6;
	    while (*bufptr == ' ' || *bufptr == '\t')
		++bufptr;

	    filter = (struct argfilter *)malloc(sizeof(struct argfilter));
	    memset(filter,0,sizeof(struct argfilter));
	    filter->pid = -1;
	    filter->ppid = -1;
	    filter->ppid_search = 0;
	    filter->gid = -1;
	    filter->uid = -1;
	    filter->dofilter = 0;
	    filter->name_search = 0;
	    filter->retval = -1;

	    // histroic default
	    filter->when = WHEN_PRE;

	    // parse the line into an argfilter struct!
	    token = NULL;
	    saveptr = NULL;
	    while ((token = strtok_r((!token)?bufptr:NULL,",",&saveptr))) {
		saveptr2 = NULL;
		token2 = NULL;
		i = 0;
		while ((token2 = strtok_r((!token2)?token:NULL,"=",&saveptr2))) {
		    //printf("f token2 %s\n",token2);
		    switch (i) {
		    case 0:
			var = token2;
			break;
		    case 1:
			val = token2;
			break;
		    default:
			break;
		    }
		    ++i;
		    if (i == 2)
			break;
		}
		
		if (*var == '\0' || *val == '\0') {
		    fprintf(stderr,"ERROR: filter file format: var/val cannot be empty!\n");
		    goto errout;
		}

		if (strcmp(var,"function") == 0) {
		    if (*val == '*') {
			filter->syscallnum = -1;
			filter->argnum = -1;
		    }
		    else {
			for (i = 0; i < SYSCALL_MAX; ++i) {
			    if (sctab[i].name && !strcmp(sctab[i].name,val))
				break;
			}
			if (i == SYSCALL_MAX) {
			    fprintf(stderr,"ERROR: filter file format: no such function %s to filter!\n",val);
			    goto errout;
			}
			filter->syscallnum = i;
		    }
		}
		else if (strcmp(var,"argname") == 0) {
		    if (*val == '*') {
			filter->argnum = -1;
		    }
		    else {
			if (filter->syscallnum == -1) {
			    fprintf(stderr,"ERROR: filter file format: cannot specify argname when function is wildcard!\n");
			    goto errout;
			}
			j = -1;
			for (i = 0; i < sctab[filter->syscallnum].argc; ++i) {
			    if (!strcmp(sctab[filter->syscallnum].args[i].name,val))
				break;
			    for (j = 0; j < sctab[filter->syscallnum].args[i].decodings_len; ++j)
				if (!strcmp(sctab[filter->syscallnum].args[i].decodings[j],val))
				    break;
			    if (j != sctab[filter->syscallnum].args[i].decodings_len)
				break;
			    j = -1;
			}
			if (i == sctab[filter->syscallnum].argc) {
			    fprintf(stderr,"ERROR: filter file format: no such function arg %s to filter on!\n",val);
			    goto errout;
			}
			filter->argnum = i;
			filter->decoding = j;
		    }
		}
		else if (strcmp(var,"argval") == 0) {
		    if (*val == '*') {
			filter->preg = NULL;
			filter->strfrag = strdup("*");
		    }
		    else {
			filter->strfrag = strdup(val);
			filter->preg = (regex_t *)malloc(sizeof(regex_t));
			if ((rc = regcomp(filter->preg,val,REG_EXTENDED))) {
			    regerror(rc,filter->preg,errbuf,sizeof(errbuf));
			    fprintf(stderr,"ERROR: filter file format: regcomp(%s): %s\n",val,errbuf);
			    goto errout;
			}
		    }
		}
		else if (strcmp(var,"when") == 0) {
		    if (strcmp(val, "pre") == 0) {
			filter->when = WHEN_PRE;
		    }
		    else if (strcmp(val, "post") == 0) {
			/* Make sure syscall supports it */
			if (filter->syscallnum != -1 &&
			    sctab[filter->syscallnum].raddr == RADDR_NO) {
			    fprintf(stderr, "WARNING: syscall %d does not support post-action, treating as pre-action\n", filter->syscallnum);
			    filter->when = WHEN_PRE;
			}
			else {
			    filter->when = WHEN_POST;
			}
		    }
		    else {
			fprintf(stderr, "ERROR: 'when' value must be 'pre' or 'post'\n");
			goto errout;
		    }
		}
		else if (strcmp(var,"retval") == 0) {
		    /* XXX dubious overload of retval */
		    if (filter->dofilter) {
			/* abort filter */
			filter->abort_retval = atoi(val);
		    } else {
			/* match filter */
			if (filter->when != WHEN_POST) {
			    fprintf(stderr,"WARNING: 'retval=' applied to pre-action filter, ignoring 'retval='\n");
			} else {
			    filter->retval = 0;
			    filter->ret_strfrag = strdup(val);
			    filter->ret_preg = (regex_t *)malloc(sizeof(regex_t));
			    if ((rc = regcomp(filter->ret_preg,val,REG_EXTENDED))) {
				regerror(rc,filter->ret_preg,errbuf,sizeof(errbuf));
				fprintf(stderr,"ERROR: filter file format: regcomp(%s): %s\n",val,errbuf);
				goto errout;
			    }
			}
		    }
		}
		else if (strcmp(var,"pid") == 0) {
		    filter->pid = atoi(val);
		}
		else if (strcmp(var,"ppid") == 0) {
		    if (*val == '^') {
			++val;
			filter->ppid_search = 1;
		    }
		    if (*val == '\0') {
			fprintf(stderr,"ERROR: filter file format: parent process search must have a parent pid!\n");
			goto errout;
		    }
		    else {
			filter->ppid = atoi(val);
		    }
		}
		else if (strcmp(var,"uid") == 0) {
		    filter->uid = atoi(val);
		}
		else if (strcmp(var,"gid") == 0) {
		    filter->gid = atoi(val);
		}
		else if (strcmp(var,"apply") == 0) {
		    filter->dofilter = atoi(val);
		}
		else if (strcmp(var,"name") == 0) {
		    if (*val == '^') {
			++val;
			filter->name_search = 1;
		    }
		    if (*val == '\0') {
			fprintf(stderr,"ERROR: filter file format: parent process search must have a parent name!\n");
			goto errout;
		    }
		    filter->name = strdup(val);
		}
	    }
	    
	    if (alist_alloclen == alist_len) {
		alist_alloclen += 8;
		if (!(alist = realloc(alist,sizeof(struct argfilter *)*alist_alloclen))) {
		    fprintf(stderr,"ERROR: filter file format: realloc: %s\n",strerror(errno));
		    goto errout;
		}
	    }
	    filter->index = alist_len + 1;
	    alist[alist_len] = filter;
	    ++alist_len;
	    filter = NULL;
	}
	else {
	    fprintf(stderr,"ERROR: unknown config directive on line:\n");
	    fprintf(stderr,"%s\n", buf);
	    goto errout;
	}
    }
    fclose(ffile);

    if (buf)
	free(buf);

    // if successful, update args!
    if (alist_len) {
	struct argfilter **finalalist = (struct argfilter **)malloc(sizeof(struct argfilter *)*alist_len);
	memcpy(finalalist,alist,alist_len*sizeof(struct argfilter *));
	*new_argfilter_list = finalalist;
    }
    else {
	*new_argfilter_list = NULL;
    }
    free(alist);
    *new_argfilter_list_len = alist_len;

    if (flist_len) {
	char **finalflist = (char **)malloc(sizeof(char *)*flist_len);
	memcpy(finalflist,flist,flist_len*sizeof(char *));
	*new_function_list = finalflist;
    }
    else {
	*new_function_list = NULL;
    }
    free(flist);
    *new_function_list_len = flist_len;

    if (pslist_len) {
	char **finalpslist = (char **)malloc(sizeof(char *)*pslist_len);
	memcpy(finalpslist,pslist,pslist_len*sizeof(char *));
	*new_ps_list = finalpslist;
    }
    else {
	*new_ps_list = NULL;
    }
    free(pslist);
    *new_ps_list_len = pslist_len;

    return 0;

 errout:
    fclose(ffile);

    if (buf)
	free(buf);
    if (filter)
	free_argfilter(filter);
    for (i = 0; i < alist_len; ++i) {
	free_argfilter(alist[i]);
    }
    free(alist);
    for (i = 0; i < flist_len; ++i) {
	free(flist[i]);
    }
    free(flist);
    for (i = 0; i < pslist_len; ++i) {
	free(pslist[i]);
    }
    free(pslist);

    return -1;
}

static domid_t domid = 1;
static char **syscall_list;
static int syscall_list_len = 0;

static void cleanup(int signo)
{
    struct syscall_retinfo *sc, *tmpsc;
    int i, j;

    if (signo) {
	fflush(stdout);
	fprintf(stderr, "Shutting down...\n");
    }

    // free the current process list
    free_process_list();

    // free the syscall return list
    list_for_each_entry_safe(sc,tmpsc,&syscalls,list) {
	list_del(&sc->list);
	free(sc);
    }

    // free the function list
    for (j = 0; j < syscall_list_len; ++j) {
	free(syscall_list[j]);
    }
    if (syscall_list)
	free(syscall_list);

    // free the argfilter list
    for (j = 0; j < argfilter_list_len; ++j) {
	free_argfilter(argfilter_list[j]);
    }
    if (argfilter_list)
	free(argfilter_list);

    // free the process list
    if (ps_list) {
	for (i = 0; i < ps_list_len; ++i) {
	    if (ps_list[i])
		free(ps_list[i]);
	}
	free(ps_list);
    }

    if (signo)
	raise(signo);
    exit(-1);
}

int main(int argc, char *argv[])
{
    int i,j,found;
    char ch;
    char *saveptr, *token = NULL;
    char *saveptr2, *token2 = NULL;
    struct argfilter *filter;
    char *sysmapfile = NULL;
    FILE *sysmapfh = NULL;
    char *endptr = NULL;
    int rc;
    char errbuf[128];
    unsigned int addr;
    char sym[256];
    char symtype;
    char *progname = argv[0];
    int syscall_list_alloclen = 8;
    int xa_debug = -1;
    vmprobe_handle_t schandles[SYSCALL_MAX];
    unsigned long vaddrlist[SYSCALL_MAX];

    syscall_list = (char **)malloc(sizeof(char *)*syscall_list_alloclen);
    argfilter_list = (struct argfilter **)malloc(sizeof(struct argfilter *)*argfilter_list_alloclen);

    while ((ch = getopt(argc, argv, "m:s:f:daw:u:c:xR:")) != -1) {
	switch(ch) {
	case 'c':
	    configfile = optarg;
	    break;
	case 'a':
	    send_a3_events = 1;
	    break;
	case 'R':
	    filtered_events_fd = fopen(optarg, "w+");
	    if (filtered_events_fd == NULL) {
		fprintf(stderr, "Could not open event file '%s'\n", optarg);
		exit(1);
	    }
	    break;
	case 'w':
	    strncpy(conf_statsserver,optarg,STATS_MAX);
	    break;
	case 'u':
	    strncpy(conf_querykey,optarg,QUERY_MAX);
	    break;
	case 'd':
	    vmprobes_set_debug_level(++debug,xa_debug);
	    break;
	case 'x':
	    vmprobes_set_debug_level(debug,++xa_debug);
	    break;
	case 'm':
	    sysmapfile = optarg;
	    break;
	case 's':
	    token = NULL;
	    saveptr = NULL;
	    while ((token = strtok_r((!token)?optarg:NULL,",",&saveptr))) {
		if (syscall_list_alloclen == syscall_list_len) {
		    syscall_list_alloclen += 10;
		    if (!(syscall_list = realloc(syscall_list,sizeof(char *)*syscall_list_alloclen))) {
			error("realloc: %s\n",strerror(errno));
			exit(-6);
		    }
		}
		syscall_list[syscall_list_len] = strdup(token);
		++syscall_list_len;
	    }
	    break;
	case 'f':
	    token = NULL;
	    saveptr = NULL;
	    while ((token = strtok_r((!token)?optarg:NULL,",",&saveptr))) {
		filter = (struct argfilter *)malloc(sizeof(struct argfilter));
		memset(filter,0,sizeof(struct argfilter));
		filter->pid = -1;
		filter->ppid = -1;
		filter->ppid_search = 0;
		filter->gid = -1;
		filter->uid = -1;
		filter->dofilter = 1;

		saveptr2 = NULL;
		token2 = NULL;
		int i = 0;
		while ((token2 = strtok_r((!token2)?token:NULL,":",&saveptr2))) {
		    //printf("f token2 %s\n",token2);
		    switch (i) {
		    case 0:
			if (!strcmp("*",token2)) {
			    filter->syscallnum = -1;
			    filter->argnum = -1;
			    break;
			}
			for (j = 0; j < SYSCALL_MAX; ++j) {
			    if (//sctab[j].num != 0 
				!strcmp(sctab[j].name,token2))
				break;
			}
			if (j == SYSCALL_MAX) {
			    error("no such syscall %s to filter on!\n",token2);
			    exit(2);
			}
			filter->syscallnum = j;
			break;
		    case 1:
			if (!strcmp("*",token2)) {
			    filter->argnum = -1;
			    break;
			}
			if (filter->syscallnum == -1) {
			    error("cannot specify argname when syscallname is wildcard!\n");
			    exit(1);
			}
			for (j = 0; j < sctab[filter->syscallnum].argc; ++j) {
			    if (!strcmp(sctab[filter->syscallnum].args[j].name,token2))
				break;
			}
			if (j == sctab[filter->syscallnum].argc) {
			    error("no such syscall arg %s to filter on!\n",token2);
			    exit(2);
			}
			filter->argnum = j;
			break;
		    case 2:
			if (!strcmp("*",token2)) {
			    filter->preg = NULL;
			    filter->strfrag = "*";
			    break;
			}
			filter->strfrag = token2;
			filter->preg = (regex_t *)malloc(sizeof(regex_t));
			if ((rc = regcomp(filter->preg,token2,REG_EXTENDED))) {
			    regerror(rc,filter->preg,errbuf,sizeof(errbuf));
			    error("regcomp(%s): %s\n",token2,errbuf);
			    exit(4);
			}
			break;
		    case 3:
			filter->abort_retval = atoi(token2);
			break;
		    case 4:
			filter->pid = atoi(token2);
			break;
		    case 5:
			if (*token2 == '^') {
			    ++token2;
			    filter->ppid_search = 1;
			}
			if (*token2 == '\0') {
			    error("parent process search must have a parent pid!\n");
			    filter->ppid = -1;
			    filter->ppid_search = 0;
			    break;
			}
			filter->ppid = atoi(token2);
			break;
		    case 6:
			filter->uid = atoi(token2);
			break;
		    case 7:
			filter->gid = atoi(token2);
			break;
		    case 8:
			filter->dofilter = atoi(token2);
			break;
		    default:
			break;
		    }
		    ++i;
		}

		if (i < 4) {
		    error("bad filter, aborting!\n");
		    exit(1);
		}

		if (argfilter_list_alloclen == argfilter_list_len) {
		    argfilter_list_alloclen += 10;
		    if (!(argfilter_list = realloc(argfilter_list,sizeof(struct argfilter *)*argfilter_list_alloclen))) {
			error("realloc: %s\n",strerror(errno));
			exit(-6);
		    }
		}
		argfilter_list[argfilter_list_len] = filter;
		++argfilter_list_len;
	    }
	    break;
	default:
	    usage(progname);
	}
    }
    argc -= optind;
    argv += optind;

    if (configfile && (syscall_list_len || argfilter_list_len)) {
	fprintf(stderr,"ERROR: you cannot specify both a config file and syscalls/filters!\n");
	exit(7);
    }

    if (configfile) {
	if (syscall_list)
	    free(syscall_list);
	if (argfilter_list)
	    free(argfilter_list);
	if (load_config_file(configfile,&syscall_list,&syscall_list_len,
			     &argfilter_list,&argfilter_list_len,
			     &ps_list,&ps_list_len)) {
	    fprintf(stderr,"ERROR: failed to load config file %s!\n",configfile);
	    exit(8);
	}
	debug(2,"configfile: %d functions (0x%08x), %d filters (0x%08x).\n",
	      syscall_list_len,syscall_list,argfilter_list_len,argfilter_list);
	argfilter_list_alloclen = argfilter_list_len;
    }

    domainname = argv[0];
    if (argc > 0) {
        domid = (domid_t)strtol(argv[0],&endptr,0);
	if (!isdigit((int)(argv[0][0])) || endptr == argv[0]) {
	    fprintf(stderr,"Looking up domain %s... ",argv[0]);
	    domid = domain_lookup(argv[0]);
	    if (domid == 0) {
		fprintf(stderr,"not found!\n");
		exit(1);
	    }
	    fprintf(stderr," %d.\n",domid);
	}

	if (!domain_exists(domid)) {
	    error("no such domain id %d\n",domid);
	    exit(3);
	}
    }

    signal(SIGUSR1,usrsighandle);
    signal(SIGUSR2,hupsighandle);

    // for memory debugging, arrange to wind up here on SIGINT
    signal(SIGINT,cleanup);

    if (send_a3_events && web_init()) {
	error("could not connect to A3 monitor!\n");
	exit(-6);
    }

    // update symaddrs that we care about, if possible
    if (sysmapfile) {
	int updated = 0;

	//domain_init(domid,sysmapfile);

	sysmapfh = fopen(sysmapfile,"r");
	if (!sysmapfh) {
	    error("could not fopen %s: %s",optarg,strerror(errno));
	    exit(2);
	}

	while ((rc = fscanf(sysmapfh,"%x %c %s255",&addr,&symtype,sym)) != EOF) {
	    if (rc < 0) {
		error("while reading %s: fscanf: %s\n",
		      sysmapfile,strerror(errno));
		exit(5);
	    }
	    else if (rc != 3)
		continue;
	    else if (strcmp("init_task",sym) == 0) {
		init_task_addr = addr;
		continue;
	    }

	    for (i = 0; i < SYSCALL_MAX; ++i) {
		if (sctab[i].name == NULL)
		    continue;

		/*
		 * If we found a syscall symbol, update the address
		 */
		if (!strcmp(sym, sctab[i].name)) {
		    /*
		     * This is the magic function that most (all?)
		     * Linux syscalls seem to pass through. We use it to
		     * enable catching syscall return values by stopping
		     * at <syscall_call+7> which is the return point of the
		     * call to the syscall-specific function.
		     */
		    if (!strcmp(sym, "syscall_call")) {
			addr += 7;
			debug(1, "setting magic syscall return address to 0x%x.\n",
			      addr);
		    }

		    if (sctab[i].addr != addr) {
			debug(1, "updating %s address to 0x%x.\n",
			      sctab[i].name, addr);
			sctab[i].addr = addr;
			updated++;
		    }

		    // first match wins; there won't be more.
		    //break;
		}
	    }		
	}
	if (updated)
	    fprintf(stderr, "Updated addresses for %d symbols\n", updated);
    }
    fclose(sysmapfh);

    for (i = 0; i < SYSCALL_MAX; ++i) {
	schandles[i] = -1;
	vaddrlist[i] = 0;
    }

    for (i = 0; i < SYSCALL_MAX; ++i) {
	if (sctab[i].name == NULL)
	    continue;

	found = 0;
	for (j = 0; j < syscall_list_len; ++j) {
	    if (!strcmp(sctab[i].name,syscall_list[j])) {
		found = 1;
		break;
	    }
	}
	if (syscall_list_len && !found)
	    continue;

	vaddrlist[i] = sctab[i].addr;
    }

#ifdef STATIC_RET_PROBE
    /*
     * If someone wants a "post" probe, insert the magic probe.
     * XXX should do this dynamically to mitigate the impact on others.
     */
    for (j = 0; j < argfilter_list_len; ++j) {
	if (argfilter_list[j]->when == WHEN_POST) {
		vaddrlist[SYSCALL_RET_IX] = sctab[SYSCALL_RET_IX].addr;
		debug(1, "installing syscall return probe at 0x%x\n",
		      vaddrlist[SYSCALL_RET_IX]);
		break;
	}
    }
#endif

    if ((rc = register_vmprobe_batch(domid,vaddrlist,SYSCALL_MAX,
				     on_fn_pre,on_fn_post,
				     schandles,1))) {
	for (i = 0; i < SYSCALL_MAX; ++i) {
	    if (vaddrlist[i] && schandles[i] == -1)
		break;
	}
	if (i == SYSCALL_MAX)
	    error("Failed to register probes!\n");
	else
	    error("Failed to register probe for %s\n",sctab[i].name);
	exit(-128);
    }
    else {
	for (i = 0; i < SYSCALL_MAX; ++i) {
	    if (vaddrlist[i] && schandles[i] > -1)
		fprintf(stderr,"Registered probe %d for %s\n",
			schandles[i],sctab[i].name);
	}
    }

    while (1) {
	run_vmprobes();
	if (reloadconfigfile) {
	    fprintf(stderr,"Reloading config file.\n");
	    struct argfilter **newalist;
	    int newalistlen;
	    char **newflist;
	    int newflistlen;
	    char **newpslist;
	    int newpslistlen;

	    if (load_config_file(configfile,&newflist,&newflistlen,
				 &newalist,&newalistlen,
				 &newpslist,&newpslistlen)) {
		fprintf(stderr,"ERROR: failed to load config file %s; not replacing current config!\n",configfile);
		continue;
	    }

	    // unregister all probes
	    if ((rc = unregister_vmprobe_batch(domid,schandles,SYSCALL_MAX))) {
		fprintf(stderr,"ERROR: failed to unregister some probes; bad!!\n");
	    }
	    else {
		for (i = 0; i < SYSCALL_MAX; ++i) {
		    vaddrlist[i] = 0;
		    if (schandles[i] == -1)
			continue;
			    
		    schandles[i] = -1;
		    fprintf(stderr,"Unregistered probe for %s.\n",sctab[i].name);
		}
	    }

	    // stop the library fully!
	    stop_vmprobes();

	    // free up current data structures
	    cleanup(0);

	    // replace the argfilter list
	    argfilter_list = newalist;
	    argfilter_list_len = newalistlen;

	    // replace the function list
	    syscall_list = newflist;
	    syscall_list_len = newflistlen;

	    // replace the process name list
	    ps_list = newpslist;
	    ps_list_len = newpslistlen;

	    // re-register probes
	    for (i = 0; i < SYSCALL_MAX; ++i) {
		if (sctab[i].name == NULL)
		    continue;

		found = 0;
		for (j = 0; j < syscall_list_len; ++j) {
		    if (!strcmp(sctab[i].name,syscall_list[j])) {
			found = 1;
			break;
		    }
		}
		if (syscall_list_len && !found)
		    continue;

		vaddrlist[i] = sctab[i].addr;
	    }

#ifdef STATIC_RET_PROBE
	    /*
	     * If someone wants a "post" probe, insert the magic probe.
	     * XXX should do this dynamically to mitigate the impact on others.
	     */
	    for (j = 0; j < argfilter_list_len; ++j) {
		if (argfilter_list[j]->when == WHEN_POST) {
		    vaddrlist[SYSCALL_RET_IX] = sctab[SYSCALL_RET_IX].addr;
		    debug(1, "installing syscall return probe at 0x%x\n",
			  vaddrlist[SYSCALL_RET_IX]);
		    break;
		}
	    }
#endif

	    if ((rc = register_vmprobe_batch(domid,vaddrlist,SYSCALL_MAX,
					     on_fn_pre,on_fn_post,
					     schandles,1))) {
		for (i = 0; i < SYSCALL_MAX; ++i) {
		    if (vaddrlist[i] && schandles[i] == -1)
			break;
		}
		if (i == SYSCALL_MAX)
		    error("Failed to register probes!\n");
		else
		    error("Failed to register probe for %s\n",sctab[i].name);
		exit(-128);
	    }
	    else {
		for (i = 0; i < SYSCALL_MAX; ++i) {
		    if (vaddrlist[i] && schandles[i] > -1)
			fprintf(stderr,"Registered probe %d for %s\n",
				schandles[i],sctab[i].name);
		}
	    }

	    fprintf(stderr,"Reloaded config file successfully.\n");
	    if (filtered_events_fd != NULL) {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		fprintf(filtered_events_fd, "%u.%03u: config file reloaded\n",
			(unsigned)tv.tv_sec, (unsigned)(tv.tv_usec/1000));
	    }
	    reloadconfigfile = 0;

	    restart_vmprobes();
	}
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
