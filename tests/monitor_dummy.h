/*
 * Copyright (c) 2013 The University of Utah
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

#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>

#include "common.h"
#include "log.h"
#include "evloop.h"
#include "monitor.h"

#define MONITOR_DUMMY_OBJTYPE 0xc

struct dummy {
    int id;
    int cmd;
    short seqno_limit;

    int fd;
    char *stdin_buf;
    int stdin_bufsiz;
    char *stdout_logfile;
    char *stderr_logfile;
};

struct monitor_dummy_msg_obj {
    char *msg;
    int msg_id;
};

// parent sends to child; child incrs seqno and echos back (logs to
// stdout/err too)
#define DUMMY_ECHO   1
// parent sends to child; child incrs seqno and echos all caps (also logs)
#define DUMMY_MUTATE 2
// parent sends to force child to exit; child responds and exits.
#define DUMMY_EXIT   3

int monitor_dummy_evh(int fd,int fdtype,void *state);
int monitor_dummy_evloop_attach(struct evloop *evloop,void *obj);
int monitor_dummy_evloop_detach(struct evloop *evloop,void *obj);
int monitor_dummy_error(monitor_error_t error,void *obj);
int monitor_dummy_fatal_error(monitor_error_t error,void *obj);
int monitor_dummy_child_recv_msg(struct monitor *monitor,struct monitor_msg *msg);
int monitor_dummy_recv_msg(struct monitor *monitor,struct monitor_msg *msg);
