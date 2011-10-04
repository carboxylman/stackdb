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
#include <xenaccess/xa_private.h>
#include <vmprobes/vmprobes.h>

#include "vmtap.h"
#include "private.h"

#define VMTAP_DOMAIN_MAX (100)
#define VMTAP_SYMBOL_MAX (100)

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
static int probe_min, probe_max;

static vmtap_callback_t vmtap_callback;

static int xc = -1;
static struct xs_handle *xs;

static void
cleanup_vmtap(void);

static void
signal_handler(int sig)
{
    stop_vmprobes();
    dbgprint("vmtap forcefully stopped\n");
    if (sig != SIGINT) cleanup_vmtap();
    signal(sig, SIG_DFL);
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
          void *pyhandler, 
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
    probe->pyhandler = pyhandler;
    p = probe->vp_handle = vp_handle; /* vp_handle is used as vmtap probe id */
    probe->xa_instance = vmprobe_xa_instance(vp_handle);
    probe->regs = NULL;
    
    probe_list[p] = probe;

    /* optimize cleanup_vmtap() reducing number of iterations through probes */
    if (probe_max < p) probe_max = p;
    if (probe_min > p) probe_min = p;
    
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
    assert(vmtap_callback);
    assert(probe);
    assert(probe->pyhandler);

    dbgprint("vmtap probe %d triggered at %s[+%lx] in %s\n", p, probe->symbol,
        probe->offset, probe->domain);

    /* save registers so that user can obtain the values in their handler */
    probe->regs = regs;
    
    /* call user handler in python */
    vmtap_callback(p, probe->pyhandler);
    
    return 0;
}

static domid_t
vmtap_domid(const char *domain)
{
    return (xa_get_domain_id((char *)domain));
}

static unsigned long
vmtap_vaddr(size_t domid, const char *symbol, unsigned long offset)
{
    char *sysmap;
    FILE *f;
    char *row;
    unsigned long vaddr;

    sysmap = linux_predict_sysmap_name(domid);
    if (!sysmap)
        return 0;
    
    row = malloc(MAX_ROW_LENGTH);
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

    if (get_symbol_row(f, row, (char *)symbol, 2) == XA_FAILURE)
        return 0;

    fclose(f);

    vaddr = strtoul(row, NULL, 16);
    
    return (vaddr + offset);
}

static bool
parse_probepoint(const char *probepoint, /* in */
                 char *domain, /* out */
                 char *symbol, /* out */
                 unsigned long *offset, /* out */
                 domid_t *domid, /* out */
                 unsigned long *vaddr) /* out */
{
    domid_t tmp_domid;
    unsigned long tmp_vaddr;

    if (!__parse_probepoint(probepoint, domain, symbol, offset, &tmp_domid))
        return false;
    dbgprint("probepoint \"%s\" parsed\n", probepoint);
	if (tmp_domid) dbgprint(" - domain: dom%d\n", tmp_domid);
	else dbgprint(" - domain: %s\n", domain);
	dbgprint(" - symbol: %s[+%lx]\n", symbol, *offset);

    if (tmp_domid == 0)
    {
        /* convert domain name to id */
        tmp_domid = vmtap_domid(domain);
        if (!tmp_domid)
            return false;
        dbgprint("domid %d obtained from %s\n", tmp_domid, domain);
    }

    /* convert symbol[+offset] to virtual address */
    tmp_vaddr = vmtap_vaddr(tmp_domid, symbol, *offset);
    if (!tmp_vaddr)
        return false;
    dbgprint("address %x obtained from %s[+%lx]\n", tmp_vaddr, symbol, *offset);

    *domid = tmp_domid;
    *vaddr = tmp_vaddr;
    return true;
}

static void
cleanup_vmtap(void)
{
    struct vmtap_probe *probe;
    int p;

    for (p = probe_min; p <= probe_max; p++)
    {
        probe = probe_list[p];
        if (probe)
        {
            /* unregister probes in vmprobes */
            unregister_vmprobe(probe->vp_handle);
            dbgprint("vmprobe %d unregistered\n", probe->vp_handle);
            free(probe->domain);
            free(probe->symbol);
            remove_probe(probe);
        }
    }

    if (xs)
    {
        xs_daemon_close(xs);
        xs = NULL;
    }

    if (xc != -1)
    {
        xc_interface_close(xc);
        xc = -1;
    }

    dbgprint("vmtap uninitialized\n");
}

static bool
init_vmtap(vmtap_callback_t callback)
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

    vmtap_callback = callback;
    
    dbgprint("vmtap initialized\n");
    return true;
}

static unsigned char *
mmap_pages(struct vmtap_probe *probe, 
           unsigned long vaddr, 
           unsigned long size, 
           unsigned long *offset,
           int prot)
{
    xa_instance_t *xa_instance;
    unsigned char *pages;
    unsigned long page_size, tmp_offset;
    const int pid = 0; /* pid 0 indicates kernel - vmtap supports kernel only */

    xa_instance = probe->xa_instance;
    page_size = xa_instance->page_size;
    tmp_offset = vaddr - (vaddr & ~(page_size - 1));

    if ((size - tmp_offset) < page_size)
    {
        /* let xenaccess use its memory cache for small size */
        pages = xa_access_user_va(xa_instance, vaddr, (unsigned int *)offset, 
            pid, prot);
    }
    else
    {
        /* xenaccess can't map multiple pages properly, use our own function */
        pages = xa_access_user_va_range(xa_instance, vaddr, size, offset, 
            pid, prot);
    }

    if (!pages)
        return NULL;

    dbgprint("%ld bytes at %lx in %s mapped\n", size, vaddr, probe->domain);
    return pages; /* munmap it later */
}

bool
__probe(const char *probepoint, vmtap_callback_t callback, void *pyhandler)
{
    struct vmtap_probe *probe;
    char *domain, *symbol;
    unsigned long offset = 0;
    domid_t domid = 0;
    unsigned long vaddr = 0;
    vmprobe_handle_t vp_handle;

    if (!probepoint || !callback)
        return -1;

    if (getuid())
    {
        fprintf(stderr, "vmtap needs a root access.\n");
        return false;
    }

    if (xc < 0)
    {
        if (init_vmtap(callback) < 0)
            return false;
    }
    
    domain = malloc(VMTAP_DOMAIN_MAX);
    symbol = malloc(VMTAP_SYMBOL_MAX);
    if (!domain || !symbol)
    {
        perror("failed to allocate memory for domain and symbol names");
        return false;
    }

    /* parse the probepoint expression */
    if (!parse_probepoint(probepoint, domain, symbol, &offset, &domid, &vaddr))
        return false;

    /* register probe in vmprobes */
    vp_handle = register_vmprobe(domid, vaddr, vmtap_handler, NULL);
    if (vp_handle < 0)
        return false;

    probe = add_probe(domain, symbol, offset, pyhandler, vp_handle);
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

domid_t
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
    struct cpu_user_regs *regs;
    unsigned long arg;

    probe = find_probe(p);
    assert(probe);

    regs = probe->regs;
    assert(regs);

    switch (n)
    {
    case 0: arg = regs->ebx; break;
    case 1: arg = regs->ecx; break;
    case 2: arg = regs->edx; break;
    /* FIXME: read values from the stack for more than three arguments */
    default: assert(false);
    }

    dbgprint("arg%d from %s[+%lx] in %s obtained: %08lx\n", n, probe->symbol, 
        probe->offset, probe->domain, arg);
    return arg;
}

const char *
arg_string(int p, int n)
{
    unsigned long _arg = arg(p, n);
    if (!_arg) return NULL;
    return (read_string(p, _arg));
}

char
read_char(int p, unsigned long vaddr)
{
    struct vmtap_probe *probe;
    xa_instance_t *xa_instance;
    /* FIXME: size of char depends on the guest's architecture */
    unsigned char *page;
    unsigned long offset = 0;
    const unsigned long size = sizeof(char);
    float value;
    
    probe = find_probe(p);
    assert(probe);

    xa_instance = probe->xa_instance;
    assert(xa_instance);

    page = (unsigned char *)mmap_pages(probe, vaddr, size, &offset, PROT_READ);
    if (!page)
        return '\0';

    memcpy(&value, page + offset, size);
    munmap(page, xa_instance->page_size);
    
    return value;
}

int
read_int(int p, unsigned long vaddr)
{
    struct vmtap_probe *probe;
    xa_instance_t *xa_instance;
    /* FIXME: size of int depends on the guest's architecture */
    unsigned char *page;
    unsigned long offset = 0;
    const unsigned long size = sizeof(int);
    int value;
    
    probe = find_probe(p);
    assert(probe);

    xa_instance = probe->xa_instance;
    assert(xa_instance);

    page = (unsigned char *)mmap_pages(probe, vaddr, size, &offset, PROT_READ);
    if (!page)
        return 0;

    memcpy(&value, page + offset, size);
    munmap(page, xa_instance->page_size);

    return value;
}

long
read_long(int p, unsigned long vaddr)
{
    struct vmtap_probe *probe;
    xa_instance_t *xa_instance;
    /* FIXME: size of long depends on the guest's architecture */
    unsigned char *page;
    unsigned long offset = 0;
    const unsigned long size = sizeof(long);
    long value;

    probe = find_probe(p);
    assert(probe);

    xa_instance = probe->xa_instance;
    assert(xa_instance);

    page = (unsigned char *)mmap_pages(probe, vaddr, size, &offset, PROT_READ);
    if (!page)
        return 0;

    memcpy(&value, page + offset, size);
    munmap(page, xa_instance->page_size);
    
    return value;
}

float
read_float(int p, unsigned long vaddr)
{
    struct vmtap_probe *probe;
    xa_instance_t *xa_instance;
    /* FIXME: size of float depends on the guest's architecture */
    unsigned char *page;
    unsigned long offset = 0;
    const unsigned long size = sizeof(float);
    float value;
    
    probe = find_probe(p);
    assert(probe);

    xa_instance = probe->xa_instance;
    assert(xa_instance);

    page = (unsigned char *)mmap_pages(probe, vaddr, size, &offset, PROT_READ);
    if (!page)
        return 0.0f;

    memcpy(&value, page + offset, size);
    munmap(page, xa_instance->page_size);
    
    return value;
}

double
read_double(int p, unsigned long vaddr)
{
    struct vmtap_probe *probe;
    xa_instance_t *xa_instance;
    /* FIXME: size of double depends on the guest's architecture */
    unsigned char *page;
    unsigned long offset = 0;
    const unsigned long size = sizeof(double);
    float value;
    
    probe = find_probe(p);
    assert(probe);

    xa_instance = probe->xa_instance;
    assert(xa_instance);

    page = (unsigned char *)mmap_pages(probe, vaddr, size, &offset, PROT_READ);
    if (!page)
        return 0.0;

    memcpy(&value, page + offset, size);
    munmap(page, xa_instance->page_size);
    
    return value;
}

const char *
read_string(int p, unsigned long vaddr)
{
    struct vmtap_probe *probe;
    xa_instance_t *xa_instance;
    char *pages;
    unsigned long offset = 0;
    unsigned long len, size = 0;
    unsigned long inc_size, page_size, no_pages;
    char *value;

    probe = find_probe(p);
    assert(probe);

    xa_instance = probe->xa_instance;
    assert(xa_instance);

    page_size = xa_instance->page_size;

    /* we will increase the mapping size by this much if the string is longer 
       than we expect at first attempt. */
    inc_size = (page_size - 1);

    while (true)
    {
        size += inc_size;
        
        pages = (char *)mmap_pages(probe, vaddr, size, &offset, PROT_READ);
        if (!pages)
            return NULL;
        
        no_pages = size / page_size + 1;
        
        len = strnlen(pages + offset, size - offset);
        if (len < (size - offset))
            break;
        
        munmap(pages, no_pages * page_size);
    }

    /* FIXME: this way, there's no way to free the memory later. */
    value = strdup(pages + offset);
    munmap(pages, no_pages * page_size);
    
    return value;
}
