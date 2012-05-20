/*
 * Copyright (c) 2012 The University of Utah
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
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 *  examples/null-deref-analysis/util.c
 *
 *  Utility functions shared by all NULL-dereference analysis passes.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>

#include <list.h>
#include <alist.h>

#include "debug.h"
#include "util.h"

void kill_everything(char *domain_name)
{
    char cmd[128];

    sprintf(cmd, "xm destroy %s", domain_name);
    system(cmd);

    sleep(1);

    system("killall -9 ttd-deviced");

    kill(getpid(), SIGINT);
}

void capitalize(char *str)
{
    while (*str != '\0')
    {
        *str = toupper((unsigned char )*str);
        ++str;
    }
}

void array_list_parse(struct array_list *list, char *str)
{
    char *obj_str = NULL;
    char *ptr = NULL;
    unsigned int item;

    while ((obj_str = strtok_r(!ptr ? str : NULL, ",", &ptr))) 
    {
        item = atoi(obj_str);
        array_list_prepend(list, (void *)item);
    }
}

int array_list_contains(struct array_list *list, void *item)
{
    int i;
    void *tmp;

    for (i = 0; i < array_list_len(list); i++)
    {
        tmp = array_list_item(list, i);
        if (tmp == item)
            return 1;
    }

    return 0;
}

