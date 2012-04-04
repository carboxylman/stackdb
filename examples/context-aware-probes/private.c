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

extern struct target *t;
extern FILE *sysmap_handle;
extern GHashTable *probes;

int register_call_probe(char *symbol, 
                        probe_handler_t handler,
                        struct probe_ops *ops,
                        probepoint_whence_t whence,
                        symbol_type_flag_t ftype,
                        void *data)
{
    struct bsymbol *bsymbol = NULL;
    struct probe *probe;
    unsigned long addr = 0;

    //struct dump_info udn = {
    //    .stream = stderr,
    //    .prefix = "",
    //    .detail = 1,
    //    .meta = 1,
    //};

    bsymbol = target_lookup_sym(t, symbol, ".", NULL, ftype);
    if (!bsymbol)
    {
        WARN("Could not find symbol '%s' in debuginfo. Trying sysmap...\n", 
             symbol);
        
        addr = sysmap_symbol_addr(symbol);
        if (!addr)
        {
            ERR("Could not find symbol '%s' in both debuginfo and sysmap!\n", 
                symbol);
            return -1;
        }
    }

    //if (bsymbol)
    //    bsymbol_dump(bsymbol, &udn);

    probe = probe_create(t, 
                         ops,
                         (bsymbol) ? bsymbol->lsymbol->symbol->name : symbol,
                         handler, /* pre_handler */
                         NULL, /* post_handler */
                         data, 
                         0); /* autofree */
    if (!probe)
    {
        ERR("Could not create call probe on '%s'\n",
            bsymbol->lsymbol->symbol->name);
        bsymbol_release(bsymbol);
        return -1;
    }

    if (!bsymbol)
    {
        if (!probe_register_addr(probe, addr, 
                                 PROBEPOINT_BREAK, 
                                 PROBEPOINT_FASTEST, whence, 
                                 PROBEPOINT_LAUTO,
                                 NULL))
        {
            ERR("Could not register call probe on 0x%08lx\n", addr);
            probe_free(probe, 1);
            return -1;
        }
    }
    else if (symbol_is_inlined(bsymbol_get_symbol(bsymbol)))
    {
        if (!probe_register_inlined_symbol(probe, bsymbol, 
                                           1,
                                           PROBEPOINT_FASTEST, whence, 
                                           PROBEPOINT_LAUTO))
        {
            ERR("Could not register inlined call probe on '%s'\n",
                bsymbol->lsymbol->symbol->name);
            probe_free(probe, 1);
            bsymbol_release(bsymbol);
            return -1;
        }
    }
    else
    {
        if (!probe_register_symbol(probe, bsymbol, 
                                   PROBEPOINT_FASTEST, whence, 
                                   PROBEPOINT_LAUTO))
        {
            ERR("Could not register call probe on '%s'\n",
                bsymbol->lsymbol->symbol->name);
            probe_free(probe, 1);
            bsymbol_release(bsymbol);
            return -1;
        }
    }

    g_hash_table_insert(probes,
                        (gpointer)probe->probepoint->addr,
                        (gpointer)probe);

    if (bsymbol)
        bsymbol_release(bsymbol);

    return 0;
}

int register_return_probe(char *symbol, 
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

    probe = probe_create(t, 
                         ops,
                         bsymbol->lsymbol->symbol->name,
                         NULL, /* pre_handler */
                         handler, /* post_handler */
                         data,
                         0);
    if (!probe)
    {
        ERR("Could not create return probe on '%s'\n",
            bsymbol->lsymbol->symbol->name);
        return -1;
    }

    if (!probe_register_function_instrs(bsymbol,
                                        PROBEPOINT_SW, 1,
                                        INST_RET, probe,
                                        INST_NONE))
    {
        probe_free(probe, 1);
        ERR("Could not register return probe on '%s'\n",
            bsymbol->lsymbol->symbol->name);
        return -1;
    }

    if (probe_num_sources(probe) == 0)
    {
        probe_free(probe, 1);
        ERR("No return sites in %s.\n",
            bsymbol->lsymbol->symbol->name);
        return -2;
    }
    
    g_hash_table_insert(probes,
                        (gpointer)probe,
                        (gpointer)probe);
    
    DBG("Registered %d return probes in function %s.\n",
        probe_num_sources(probe),
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


unsigned long sysmap_symbol_addr(char *symbol)
{
    int rc;
    unsigned long addr;
    char sym[256];
    char symtype;

    while ((rc = fscanf(sysmap_handle,
                        "%lx %c %s255", 
                        &addr, 
                        &symtype, 
                        sym)) != EOF)
    {
        if (rc < 0)
        {
            ERR("Could not fscanf Systemp.map\n");
            return -5;
        }
        else if (rc != 3)
            continue;
        
        if (strcmp(symbol, sym) == 0) 
            return addr;
    }

    return 0;
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

int load_func_retval(var_t **retval, struct probe *probe)
{
    var_t *value;
    unsigned long eax;
    
    value = (var_t *)malloc(sizeof(var_t));
    if (!value)
    {
        ERR("Cannot allocate memory for function retval!\n");
        return -4;
    }
    memset(value, 0, sizeof(var_t));
    
    value->size = sizeof(eax);
    
    value->name = (char *)malloc(strlen(probe->name)+1+6+1);
    if (!value->name)
    {
        ERR("Cannot allocate memory for function retval name!\n");
        unload_func_retval(value);
        return -4;
    }
    sprintf(value->name, "%s.return", probe->name);
    
    value->buf = (char *)malloc(value->size);
    if (!value->buf)
    {
        ERR("Cannot allocate memory for function retval buf!\n");
        unload_func_retval(value);
        return -4;
    }
    eax = target_read_reg(t, 0);
    memcpy(value->buf, &eax, value->size);

    *retval = value;
    
    return 0;
}

void unload_func_retval(var_t *retval)
{
    if (retval)
    {
        if (retval->name)
            free(retval->name);
        if (retval->buf)
            free(retval->buf);
        free(retval);
    }
}
