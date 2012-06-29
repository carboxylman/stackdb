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
 *  examples/local-dos-analysis/util.c
 *
 *  Utility functions shared by all local denial-of-service analysis
 *  passes.
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
#include "ctxprobes.h"

void kill_everything(char *domain_name)
{
    char cmd[128];

    ctxprobes_cleanup();

    sprintf(cmd, "/usr/sbin/xm destroy %s", domain_name);
    system(cmd);

    sleep(1);

    system("/usr/bin/killall -9 ttd-deviced");

    kill(getpid(), SIGINT);
}
