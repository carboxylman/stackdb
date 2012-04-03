/*
 * Copyright (c) 2011, 2012 The University of Utah
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin St, Suite 500, Boston, MA 02110-1335, USA.
 * 
 *  examples/context-aware-probes/private.c
 * 
 *  Private helper functions that simpify the main workflow of 
 *  context-aware probes.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#include <stdio.h>
#include <stdlib.h>

#include <log.h>
#include <dwdebug.h>
#include <target_api.h>
#include <target.h>
#include <target_xen_vm.h>

#include <probe_api.h>
#include <probe.h>
#include <alist.h>

#include "ctxprobes.h"
#include "private.h"
#include "debug.h"

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

#define THREAD_SIZE (8192)
#define current_thread_ptr(esp) ((esp) & ~(THREAD_SIZE - 1))

/* FIXME: remove this and get size and offsets from debug-info. */
#define TASK_STRUCT_SIZE (1312)
#define TASK_PID_OFFSET (168)
#define TASK_TGID_OFFSET (172)
#define TASK_REAL_PARENT_OFFSET (176)
#define TASK_PARENT_OFFSET (180)
#define TASK_UID_OFFSET (336)
#define TASK_EUID_OFFSET (340)
#define TASK_SUID_OFFSET (344)
#define TASK_FSUID_OFFSET (348)
#define TASK_GID_OFFSET (352)
#define TASK_EGID_OFFSET (356)
#define TASK_SGID_OFFSET (360)
#define TASK_FSGID_OFFSET (364)
#define TASK_COMM_OFFSET (396)

extern struct target *t;
extern GHashTable *probes;

int register_call_probe(int raw, /* 0:use symbol, 1:use addr (raw address) */
                        char *symbol, 
                        ADDR addr, 
                        probe_handler_t handler,
                        struct probe_ops *ops,
                        probepoint_whence_t whence,
                        symbol_type_flag_t ftype,
                        void *data)
{
    struct bsymbol *bsymbol = NULL;
    struct probe *probe;

    //struct dump_info udn = {
    //    .stream = stderr,
    //    .prefix = "",
    //    .detail = 1,
    //    .meta = 1,
    //};

    if (!raw)
    {
        bsymbol = target_lookup_sym(t, symbol, ".", NULL, ftype);
        if (!bsymbol)
        {
            ERR("Could not find symbol %s!\n", symbol);
            return -1;
        }
    }

    //bsymbol_dump(bsymbol, &udn);

    probe = probe_create(t, ops,
                         (raw) ? symbol : bsymbol->lsymbol->symbol->name,
                         handler, 
                         NULL, /* post_handler */
                         data, 
                         0); /* autofree */
    if (!probe)
    {
        ERR("Could not create call probe on '%s'\n",
            (raw) ? symbol : bsymbol->lsymbol->symbol->name);
        return -1;
    }

    if (raw)
    {
        if (!probe_register_addr(probe,
                                 addr, PROBEPOINT_BREAK, PROBEPOINT_FASTEST,
                                 whence, PROBEPOINT_LAUTO, 
                                 NULL)) /* bsymbol */
        {
            ERR("Could not register call probe on 0x%08x\n", addr);
            probe_free(probe, 1);
            return -1;
        }
    }
    else
    {
        if (!probe_register_symbol(probe,
                                   bsymbol, PROBEPOINT_FASTEST,
                                   whence, PROBEPOINT_LAUTO))
        {
            ERR("Could not register call probe on '%s'\n",
                bsymbol->lsymbol->symbol->name);
            probe_free(probe, 1);
            return -1;
        }
    }

    g_hash_table_insert(probes,
                        (gpointer)probe->probepoint->addr,
                        (gpointer)probe);

    return 0;
}

/* FIXME: remove this after fixing the bug in probing function returns. */
static int cprobe_handler(struct probe *probe,
                          void *data,
                          struct probe *trigger)
{
    DBG("CPROBE HANDLER CALLED!\n");
    return 0;
}

int register_return_probe(char *symbol, 
                          probe_handler_t handler,
                          probepoint_whence_t whence,
                          symbol_type_flag_t ftype,
                          void *data)
{
    struct bsymbol *bsymbol = NULL;
    struct probe *rprobe;
    int len;
    char *name;
    struct probe *cprobe;
    
    //struct dump_info udn = {
    //    .stream = stderr,
    //    .prefix = "",
    //    .detail = 1,
    //    .meta = 1,
    //};

    bsymbol = target_lookup_sym(t, symbol, ".", NULL, ftype);
    if (!bsymbol)
    {
        ERR("Could not find symbol %s!\n", symbol);
        return -1;
    }

    //bsymbol_dump(bsymbol, &udn);

    /* Dissasemble the function and grab a list of
     * RET instrs, and insert more child
     * breakpoints.
     */

    /* FIXME: remove this after fixing the bug in probing function returns. */
    len = strlen(bsymbol->lsymbol->symbol->name)+1+4+1+2+1;
    name = (char *)malloc(len);
    snprintf(name, len, "call_in_%s", bsymbol->lsymbol->symbol->name);
    cprobe = probe_create(t, NULL,
                          name,
                          NULL, /* pre_handler */
                          cprobe_handler, /* post_handler */
                          NULL,
                          0);
    free(name);
    if (!cprobe)
    {
        ERR("Could not create call probe on '%s'\n",
            bsymbol->lsymbol->symbol->name);
        return -1;
    }

    len = strlen(bsymbol->lsymbol->symbol->name)+1+3+1+2+1;
    name = (char *)malloc(len);
    snprintf(name, len, "ret_in_%s", bsymbol->lsymbol->symbol->name);
    rprobe = probe_create(t, NULL,
                         name,
                         handler, /* pre_handler */
                         NULL, /* post_handler */
                         NULL, //data,
                         0);
    free(name);
    if (!rprobe)
    {
        ERR("Could not create return probe on '%s'\n",
            bsymbol->lsymbol->symbol->name);
        return -1;
    }

    /* FIXME: remove this after fixing the bug in probing function returns. */
    if (!probe_register_function_instrs(bsymbol,
                                        PROBEPOINT_SW, 1,
                                        INST_RET, rprobe,
                                        INST_CALL, cprobe,
                                        INST_NONE))
    {
        probe_free(cprobe, 1);
        probe_free(rprobe, 1);
        ERR("Could not register call and return probes on '%s'\n",
            bsymbol->lsymbol->symbol->name);
        return -1;
    }

    /* FIXME: remove this after fixing the bug in probing function returns. */
    if (probe_num_sources(cprobe) == 0)
    {
        probe_free(cprobe, 1);
        ERR("No call sites in %s.\n",
            bsymbol->lsymbol->symbol->name);
        return -2;
    }

    /* FIXME: remove this after fixing the bug in probing function returns. */
    g_hash_table_insert(probes,
                        (gpointer)cprobe,
                        (gpointer)cprobe);
    
    /* FIXME: remove this after fixing the bug in probing function returns. */
    DBG("Registered %d call probes in function %s.\n",
        probe_num_sources(cprobe),
        bsymbol->lsymbol->symbol->name);

    if (probe_num_sources(rprobe) == 0)
    {
        probe_free(rprobe, 1);
        ERR("No return sites in %s.\n",
            bsymbol->lsymbol->symbol->name);
        return -2;
    }
    
    g_hash_table_insert(probes,
                        (gpointer)rprobe,
                        (gpointer)rprobe);
    
    DBG("Registered %d return probes in function %s.\n",
        probe_num_sources(rprobe),
        bsymbol->lsymbol->symbol->name);

    return 0;
}

void unregister_probes()
{
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;

    g_hash_table_iter_init(&iter, probes);
    while (g_hash_table_iter_next(&iter,
           (gpointer)&key,
           (gpointer)&probe))
    {
        probe_unregister(probe, 1);
    }
}

unsigned long current_task_addr(void)
{
    unsigned long esp = target_read_reg(t, 4);
    unsigned long thread_info_ptr = current_thread_ptr(esp);
    unsigned long task_addr = 0;
    
    if (!target_read_addr(t,
                          thread_info_ptr,
                          sizeof(unsigned long),
                          (unsigned char *)&task_addr,
                          NULL))
    {
        return 0;
    }

    return task_addr;
}

int load_task_info(task_t **ptask, unsigned long task_struct_addr)
{
    unsigned char *task_struct_buf;
    unsigned long parent_addr;
    unsigned long real_parent_addr;
    task_t *task, *current, *parent;

    task_struct_buf = (unsigned char *)malloc(TASK_STRUCT_SIZE);
    if (!task_struct_buf)
        return -1;
    memset(task_struct_buf, 0, TASK_STRUCT_SIZE);

    if (!target_read_addr(t, 
                          task_struct_addr, 
                          TASK_STRUCT_SIZE, 
                          task_struct_buf, 
                          NULL))
    {
        free(task_struct_buf);
        return -1;
    }

    task = (task_t *)malloc(sizeof(task_t));
    if (!task)
    {
        free(task_struct_buf);
        return -1;
    }
    memset(task, 0, sizeof(task_t));

    current = task;

    while (1)
    {
        task->pid = *((unsigned int *)(task_struct_buf + TASK_PID_OFFSET));
        task->tgid = *((unsigned int *)(task_struct_buf + TASK_TGID_OFFSET));
        task->uid = *((unsigned int *)(task_struct_buf + TASK_UID_OFFSET));
        task->euid = *((unsigned int *)(task_struct_buf + TASK_EUID_OFFSET));
        task->suid = *((unsigned int *)(task_struct_buf + TASK_SUID_OFFSET));
        task->fsuid = *((unsigned int *)(task_struct_buf + TASK_FSUID_OFFSET));
        task->gid = *((unsigned int *)(task_struct_buf + TASK_GID_OFFSET));
        task->egid = *((unsigned int *)(task_struct_buf + TASK_EGID_OFFSET));
        task->sgid = *((unsigned int *)(task_struct_buf + TASK_SGID_OFFSET));
        task->fsgid = *((unsigned int *)(task_struct_buf + TASK_FSGID_OFFSET));
        if ((char *)(task_struct_buf + TASK_COMM_OFFSET) != NULL)
        {
            task->comm = 
                strndup((char *)(task_struct_buf + TASK_COMM_OFFSET), 16);
        }
        task->vaddr = task_struct_addr;
        real_parent_addr = 
            *((unsigned long *)(task_struct_buf + TASK_REAL_PARENT_OFFSET));
        parent_addr = 
            *((unsigned long *)(task_struct_buf + TASK_PARENT_OFFSET));

        if (parent_addr == task_struct_addr || task->pid == 0)
        {
            task->real_parent = NULL;
            task->parent = NULL;
            break;
        }

        memset(task_struct_buf, 0, TASK_STRUCT_SIZE);

        if (!target_read_addr(t, 
                              parent_addr, 
                              TASK_STRUCT_SIZE, 
                              task_struct_buf, 
                              NULL))
        {
            free(task_struct_buf);
            unload_task_info(current);
            return -1;
        }

        parent = (task_t *)malloc(sizeof(task_t));
        if (!parent)
        {
            free(task_struct_buf);
            unload_task_info(current);
            return -1;
        }
        memset(parent, 0, sizeof(task_t));

        task->parent = parent;
        task = parent;
        task_struct_addr = parent_addr;
    }

    free(task_struct_buf);

    *ptask = current;

    return 0;
}

void unload_task_info(task_t *task)
{
    task_t *parent;
    
    while (task)
    {
        parent = task->parent;
        if (task->comm)
            free(task->comm);
        free(task);
        task = parent;
    }
}


int load_func_args(var_t **arg_list, int *arg_count, struct probe *probe)
{
    int ret = 0;
    struct value *value;
    struct symbol_instance *tsym_instance;
    struct symbol *tsym;
    struct array_list *tmp;
    int len, i = 0;
    var_t *args;
    int arglen;

    if (!probe->bsymbol->lsymbol->chain || 
        array_list_len(probe->bsymbol->lsymbol->chain) == 0)
    {
        tmp = array_list_clone(probe->bsymbol->lsymbol->chain, 2);
        array_list_add(tmp, probe->bsymbol->lsymbol->symbol);
    }
    else
    {
        tmp = array_list_clone(probe->bsymbol->lsymbol->chain, 1);
    }
    len = tmp->len;

    struct lsymbol tlsym = {
        .chain = tmp
    };
    struct bsymbol tbsym = {
        .lsymbol = &tlsym,
        .region = probe->probepoint->range->region
    };

    arglen = probe->bsymbol->lsymbol->symbol->s.ii->d.f.count;
    DBG("Function %s has %d args\n", probe->name, arglen);

    args = (var_t *)malloc(sizeof(var_t) * arglen);
    if (!args)
    {
        ret = -4;
        ERR("Cannot allocate memory for function arg!\n");
        goto error_exit;
    }
    memset(args, 0, sizeof(var_t) * arglen);

    ++tmp->len;
    list_for_each_entry(tsym_instance,
                        &probe->bsymbol->lsymbol->symbol->s.ii->d.f.args,
                        d.v.member)
    {
        tsym = tsym_instance->d.v.member_symbol;

        array_list_item_set(tmp, len, tsym);
        tlsym.symbol = tsym;

        value = bsymbol_load(&tbsym,
                             LOAD_FLAG_AUTO_DEREF |
                             LOAD_FLAG_AUTO_STRING |
                             LOAD_FLAG_NO_CHECK_VISIBILITY |
                             LOAD_FLAG_NO_CHECK_BOUNDS);
        if (!value)
        {
            ret = -1;
            ERR("Cannot load function arg symbol!\n");
            goto error_exit;
        }

        args[i].size = value->bufsiz;

        args[i].name = strdup(tsym->name);
        if (!args[i].name)
        {
            value_free(value);
            ret = -4;
            ERR("Cannot duplicate function arg name!\n");
            goto error_exit;
        }

        args[i].buf = (char *)malloc(args[i].size);
        if (!args[i].buf)
        {
            value_free(value);
            ret = -4;
            ERR("Cannot allocate memory for function arg buf!\n");
            goto error_exit;
        }
        memcpy(args[i].buf, value->buf, args[i].size);

        value_free(value);

        i++;
    }

    *arg_list = args;
    *arg_count = arglen;

error_exit:
    array_list_free(tmp);
    return ret;
}

void unload_func_args(var_t *arg_list, int arg_count)
{
    int i;
    if (arg_list)
    {
        for (i = 0; i < arg_count; i++)
        {
            if (arg_list[i].name)
                free(arg_list[i].name);
            if (arg_list[i].buf)
                free(arg_list[i].buf);
        }
        free(arg_list);
    }
}

int load_func_retval(var_t *retval, struct probe *probe)
{
    return 0;
}
