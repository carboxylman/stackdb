#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>

#include <xenctrl.h>
#include <xs.h>
#include <xenaccess/xenaccess.h>
#include <vmprobes/vmprobes.h>
#include <vmprobes/private.h>

#include "vmtap.h"
#include "private.h"

#ifdef VMTAP_DEBUG
static inline
void dbgprint(char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}
#else
#define dbgprint(format, args...) ((void)0)
#endif

static struct vmtap_probe *probe_list[VMTAP_PROBE_MAX];

static int xc = -1;
static struct xs_handle *xs;

static void cleanup_vmtap(void);

static void
signal_handler(int sig)
{
    cleanup_vmtap();
    fprintf(stderr, "vmtap forcefully discarded\n");
    
    signal(sig, SIG_DFL);
    raise(sig);
}

static void
signal_interrupt(void)
{
    if (signal(SIGINT, signal_handler) == SIG_IGN)
        signal(SIGINT, SIG_IGN);
    if (signal(SIGABRT, signal_handler) == SIG_IGN)
        signal(SIGABRT, SIG_IGN);
    if (signal(SIGHUP, signal_handler) == SIG_IGN)
        signal(SIGHUP, SIG_IGN);
    if (signal(SIGILL, signal_handler) == SIG_IGN)
        signal(SIGILL, SIG_IGN);
    if (signal(SIGFPE, signal_handler) == SIG_IGN)
        signal(SIGFPE, SIG_IGN);
    if (signal(SIGSEGV, signal_handler) == SIG_IGN)
        signal(SIGSEGV, SIG_IGN);
    if (signal(SIGTERM, signal_handler) == SIG_IGN)
        signal(SIGTERM, SIG_IGN);
}

static inline struct vmtap_probe *
find_probe(int p)
{
    if (p < 0 || p >= VMPROBE_MAX)
        return NULL;
    
    return probe_list[p];
}

static struct vmtap_probe *
add_probe(char *domain, 
          char *symbol, 
          unsigned long offset,
          vmtap_handler_t handler, 
          vmprobe_handle_t vp_handle)
{
    struct vmtap_probe *probe;
    int p;
    
    probe = (struct vmtap_probe *) malloc( sizeof(*probe) );
    if (!probe)
    {
        perror("failed to allocate a new vmtap probe");
        return NULL;
    }

    probe->domain = domain;
    probe->symbol = symbol;
    probe->offset = offset;
    probe->handler = handler;
    p = probe->vp_handle = vp_handle; /* vp_handle is used as vmtap probe id */
    probe->regs = NULL;
    
    probe_list[p] = probe;
    
    dbgprint("vmtap probe %d added\n", p);
    return probe;
}

static void
remove_probe(struct vmtap_probe *probe)
{
    int p;

    p = probe->vp_handle;
    probe_list[p] = NULL;
    
    dbgprint("vmtap probe %d removed\n", p);
    free(probe);
}

static int
vmtap_handler(vmprobe_handle_t vp_handle, struct cpu_user_regs *regs)
{
    int p = vp_handle;
    struct vmtap_probe *probe;
    
    probe = find_probe(p);
    assert(probe && probe->handler);

    /* save registers so that user can obtain the values in their handler */
    probe->regs = regs;
    
    /* call user handler */
    /* FIXME: pass python function object instead of NULL */
    probe->handler(p, NULL);
    
    return 0;
}

static int
vmtap_domid(const char *domain)
{
    xs_transaction_t xt = XBT_NULL;
    char **domains;
    char *tmp, *idstr, *name;
    unsigned int i, size = 0;
    int domid = 0;

    domains = xs_directory(xs, xt, "/local/domain", &size);
    for (i = 0; i < size; i++)
    {
        tmp = malloc(100);
        if (!tmp)
        {
            perror("failed to allocate memory for domain name");
            return 0;
        }
        idstr = domains[i];
        sprintf(tmp, "/local/domain/%s/name", idstr);
        name = xs_read(xs, xt, tmp, NULL);

        if (strncmp(domain, name, 100) == 0)
        {
            domid = atoi(idstr);
            break;
        }

        if (name) free(name);
        free(tmp);
    }

    if (domains) free(domains);
    return domid;
}

static char *
vmtap_dompath(int domid)
{
    xs_transaction_t xt = XBT_NULL;
    char *tmp, *dompath;

    tmp = malloc(100);
    if (!tmp)
    {
        perror("failed to allocate memory for domain path");
        return NULL;
    }

    memset(tmp, 0, 100);
    sprintf(tmp, "/local/domain/%d/vm", domid);
    dompath = xs_read(xs, xt, tmp, NULL);

    free(tmp);

    return dompath;
}

static char *
vmtap_kernel(int domid)
{
    xs_transaction_t xt = XBT_NULL;
    char *dompath, *kernel, *tmp;

    dompath = vmtap_dompath(domid);
    if (!dompath)
        return NULL;

    tmp = malloc(100);
    if (!tmp)
    {
        perror("failed to allocate memory for kernel name");
        return NULL;
    }
    memset(tmp, 0, 100);
    sprintf(tmp, "%s/image/kernel", dompath);
    kernel = xs_read(xs, xt, tmp, NULL);

    free(tmp);
    free(dompath);

    return kernel;
}

static char *
vmtap_sysmap(int domid)
{
    char *kernel, *sysmap;
    unsigned int i, length;

    kernel = vmtap_kernel(domid);
    if (!kernel)
        return NULL;
    
    if (strcmp(kernel, "/usr/lib/xen/boot/hvmloader") == 0)
    {
        /* we can't predict for hvm domains */
        fprintf(stderr, "cannot predict the name of a hvm domain\n");
        free(kernel);
        return NULL;
    }

    /* replace 'vmlinuz' with 'System.map' */
    length = strlen(kernel) + 4;
    sysmap = malloc(length);
    if (!sysmap)
    {
        perror("failed to allocate memory for system map");
        free(kernel);
        return NULL;
    }
    memset(sysmap, 0, length);
    for (i = 0; i < length; i++)
    {
        if (strncmp(kernel + i, "vmlinu", 6) == 0)
        {
            strcat(sysmap, "System.map");
            strcat(sysmap, kernel + i + 7);
            break;
        }
        else
            sysmap[i] = kernel[i];
    }

    free(kernel);
   
    return sysmap;
}

static bool
vmtap_sysmap_row(FILE *f, char *row, const char *symbol, int position)
{
    char *token;
    int curpos, position_copy;

    while (fgets(row, 200, f))
    {
        /* find the correct token to check */
        curpos = 0;
        position_copy = position;
        while (position_copy > 0 && curpos < 200)
        {
            if (isspace(row[curpos]))
            {
                while (isspace(row[curpos]))
                {
                    row[curpos] = '\0';
                    curpos++;
                }
                position_copy--;
                continue;
            }
            curpos++;
        }

        if (position_copy == 0)
        {
            token = row + curpos;
            while (curpos < 200)
            {
                if (isspace(row[curpos]))
                {
                    row[curpos] = '\0';
                    break;
                }
                curpos++;
            }
        }
        else
        {
            /* some went wrong in the loop above */
            memset(row, 0, 200);
            return false;
        }

        /* check the token */
        if (strncmp(token, symbol, 200) == 0)
            return true;
    }

    return false;    
}

static unsigned long
vmtap_vaddr(int domid, const char *symbol, unsigned long offset)
{
    char *sysmap;
    FILE *f;
    char *row;
    unsigned long vaddr;

    sysmap = vmtap_sysmap(domid);
    if (!sysmap)
        return 0;
    
    row = malloc(200);
    if (!row)
    {
        perror("failed to allocate memory for a symbol row");
        free(sysmap);
        return 0;
    }

    f = fopen(sysmap, "r");
    if (!f)
    {
        fprintf(stderr, "could not find System.map file after checking: %s\n", 
            sysmap);
        free(sysmap);
        return 0;
    }

    free(sysmap);

    if (!vmtap_sysmap_row(f, row, symbol, 2))
        return 0;

    fclose(f);

    vaddr = strtoul(row, NULL, 16);
    
	return (vaddr + offset);
}

static bool
parse_probepoint(char **domain, 
                 char **symbol, 
                 unsigned long *offset)
{
    *domain = "a3guest";
    *symbol = "sys_open";
    *offset = 0;
    return true;
}

static void
cleanup_vmtap(void)
{
    struct vmtap_probe *probe;
    int i;

    for (i = 0; i < VMTAP_PROBE_MAX; i++)
    {
        probe = probe_list[i];
        if (probe)
        {
            /* unregister probes in vmprobes */
            unregister_vmprobe(probe->vp_handle);
            dbgprint("vmprobe %d unregistered\n", probe->vp_handle);
			remove_probe(probe);
        }
    }

    xs_daemon_close(xs);
    xs = NULL;

    xc_interface_close(xc);
    xc = -1;

    dbgprint("vmtap uninitialized\n");
}

static bool
init_vmtap(void)
{
    signal_interrupt();

    xc = xc_interface_open();
    if (xc < 0)
    {
        perror("failed to open xc interface");
        return false;
    }

    xs = xs_domain_open();
    if (!xs)
    {
        xc_interface_close(xc);
        xc = -1;
        perror("failed to open xs domain");
        return false;
    }
    
    dbgprint("vmtap initialized\n");
    return true;
}

bool
probe(const char *probepoint, vmtap_handler_t handler)
{
    struct vmtap_probe *probe;
    char *domain = NULL;
    char *symbol = NULL;
    unsigned long offset = 0;
    int domid = 0;
    unsigned long vaddr = 0;
    vmprobe_handle_t vp_handle;

    if (xc < 0)
    {
        if (init_vmtap() < 0)
            return false;
    }
    
    /* parse the probepoint expression */
    if (!parse_probepoint(&domain, &symbol, &offset))
        return false;
    
    domid = vmtap_domid(domain);
    if (!domid)
		return false;
	dbgprint("domid %d obtained from %s\n", domid, domain);
	
	vaddr = vmtap_vaddr(domid, symbol, offset);
	if (!vaddr)
		return false;
	dbgprint("address %x obtained from %s+%x\n", vaddr, symbol, offset);

    /* register probe in vmprobes */
    vp_handle = register_vmprobe(domid, vaddr, vmtap_handler, NULL);
    if (vp_handle < 0)
        return false;
   	dbgprint("vmprobe %d registered\n", vp_handle);

    probe = add_probe(domain, symbol, offset, handler, vp_handle);
    if (!probe)
        return false;

    return true;
}

void
run(void)
{
    /* run all registered probes ins vmprobes */
    /* NOTE: this function does not return until stop_vmprobes() is called */
    run_vmprobes();

    /* uninitialize vmtap here since it's the last function that user calls */
    cleanup_vmtap();
}

void
stop(void)
{
    /* stop all running probes in vmprobes */
    stop_vmprobes();
}

bool
disable(int p)
{
    struct vmtap_probe *probe;

    probe = find_probe(p);
    assert(probe);

    if (disable_vmprobe(probe->vp_handle) < 0)
        return false;
    
    return true;    
}

bool
enable(int p)
{
    struct vmtap_probe *probe;

    probe = find_probe(p);
    assert(probe);

    if (enable_vmprobe(probe->vp_handle) < 0)
        return false;
    
    return true;    
}

int
domid(int p)
{
    struct vmtap_probe *probe;

    probe = find_probe(p);
    assert(probe);

    return (vmprobe_domid(probe->vp_handle));
}

const char *
domain(int p)
{
    struct vmtap_probe *probe;

    probe = find_probe(p);
    assert(probe);

    return probe->domain;
}

unsigned long
address(int p)
{
    struct vmtap_probe *probe;
    
    probe = find_probe(p);
    assert(probe);

    return (vmprobe_vaddr(probe->vp_handle));
}

const char *
symbol(int p)
{
    struct vmtap_probe *probe;

    probe = find_probe(p);
    assert(probe);

    return probe->symbol;
}

unsigned long
offset(int p)
{
    struct vmtap_probe *probe;

    probe = find_probe(p);
    assert(probe);

    return probe->offset;
}

unsigned long
arg(int p, int n)
{
    struct vmtap_probe *probe;

    probe = find_probe(p);
    assert(probe);

    // TODO:

    return 0;
}

const char *
argstr(int p, int n)
{
    struct vmtap_probe *probe;

    probe = find_probe(p);
    assert(probe);

    // TODO:

    return NULL;    
}
