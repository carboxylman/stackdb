#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <vmprobes/vmprobes.h>
#include "vmtap.h"

static struct vmprobe __p;
static struct pt_regs __regs;

static VMTAP_CALLBACK __callback;
static void *__prefunc;
static void *__postfunc;

static int pre_handler(struct vmprobe *p, 
                       struct pt_regs *regs)
{
	int res;
	memcpy(&__regs, regs, sizeof(struct pt_regs));
	res = (__callback)(__prefunc);
	return (!res);
}

static int post_handler(struct vmprobe *p,
                        struct pt_regs *regs,
                        unsigned long flags)
{
	int res;
	memcpy(&__regs, regs, sizeof(struct pt_regs));
	res = (__callback)(__postfunc);
	return (!res);
}

int __register_vmtap(const char *domain,
                     const char *symbol,
			         VMTAP_CALLBACK callback,
			         void *prefunc,
			         void *postfunc)
{
	int res = 0;

	if (!callback)
		return res;

	if (!prefunc && !postfunc)
		return res;
	
	__callback = callback;
	__prefunc = prefunc;
	__postfunc = postfunc;

	__p.domain_name = strdup(domain);
	__p.symbol_name = strdup(symbol);
	__p.pre_handler = (prefunc) ? pre_handler : NULL;
	__p.post_handler = (postfunc) ? post_handler : NULL;

	res = register_vmprobe(&__p);

	return (!res);
}

int loop_vmtap(void)
{
	int res = loop_vmprobe(&__p);
	return (!res);
}

void unregister_vmtap(void)
{
	unregister_vmprobe(&__p);
	
	free((void *) __p.domain_name);
	free((void *) __p.symbol_name);
}

const char *domain_name(void)
{
	return (__p.domain_name);
}

unsigned int *domain_id(void)
{
	return ((unsigned int) __p.domain_id);
}

const char *symbol_name(void)
{
	return (__p.symbol_name);
}

unsigned long symbol_addr(void)
{
	return ((unsigned long) __p.addr);
}

unsigned long arg(int num)
{
	unsigned long arg = 0;

	switch (num)
	{
	case 0: arg = (unsigned long) __regs.ebx; break;
	case 1: arg = (unsigned long) __regs.ecx; break;
	case 2: arg = (unsigned long) __regs.edx; break;
	}

	return arg;
}

const char *read_path(unsigned long addr)
{
	char *path = malloc(PATH_MAX+1);
	memset(path, 0, PATH_MAX+1);

	if (read_vmprobe(&__p, (uint32_t)addr, path, PATH_MAX))
		return NULL;

	return path;
}
