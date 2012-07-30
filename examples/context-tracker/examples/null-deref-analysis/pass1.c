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
 *  examples/context-tracker/examples/null-deref-analysis/pass1.c
 *
 *  PASS-1: Detect the password file opened in write mode.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <ctype.h>

#include <target.h>
#include <target_api.h>
#include <target_xen_vm.h>
#include <probe_api.h>
#include <probe.h>

#include <ctxtracker.h>
#include <private.h>

#include "util.h"
#include "debug.h"

#define O_WRONLY (00000001)
#define O_RDWR   (00000002)

extern char *optarg;
extern int optind, opterr, optopt;

static char *domain_name;
static int debug_level = -1;

static struct target *t;
static GHashTable *probes;

static struct bsymbol *bsymbol_open_filename;
static struct bsymbol *bsymbol_open_flags;

static int probe_open_entry(struct probe *probe, void *data,
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	struct value *value_task;
	struct value *value_parent;
	struct value *value_filename;
	struct value *value_flags;
	int task_pid;
	char task_name[PATH_MAX];
	char filename[PATH_MAX];
	int flags;

	static const char *member_task_pid = "pid";
	static const char *member_task_name = "comm";
	static const char *member_task_parent = "parent";

	context = (ctxtracker_context_t *)probe_summarize(probe);
	if (!context)
	{
		ERR("Could not load summarizing context data\n");
		return -1;
	}

	/* Load system call arguments. */

	value_filename = bsymbol_load(bsymbol_open_filename, 
			LOAD_FLAG_AUTO_DEREF | LOAD_FLAG_AUTO_STRING | 
			LOAD_FLAG_NO_CHECK_VISIBILITY | LOAD_FLAG_NO_CHECK_BOUNDS);
	if (!value_filename)
		WARN("Could not load 'filename' argument\n");
	strncpy(filename, value_filename->buf, value_filename->bufsiz);
	value_free(value_filename);

	value_flags = bsymbol_load(bsymbol_open_flags, 
			LOAD_FLAG_AUTO_DEREF | LOAD_FLAG_AUTO_STRING | 
			LOAD_FLAG_NO_CHECK_VISIBILITY | LOAD_FLAG_NO_CHECK_BOUNDS);
	if (!value_flags)
		WARN("Could not load 'flags' argument\n");
	flags = v_i32(value_flags);
	value_free(value_flags);

	/* Filter out information we are not interested in. */

	if (context->flags == TRACK_NONE) // not handling an interrupt or a trap
	{
		if (strcmp(filename, "/etc/passwd") == 0) // the password file
		{
			if ((flags & O_WRONLY) || (flags & O_RDWR)) // write access
			{
				/* Load task information. */

				value_task = context->task.cur;
				value_parent = NULL;

				while (true)
				{
					ret = get_member_i32(probe->target, value_task, 
							member_task_pid, &task_pid);
					if (ret)
					{
						ERR("Could not load task pid\n");
						return ret;
					}

					ret = get_member_string(probe->target, value_task, 
							member_task_name, task_name);
					if (ret)
					{
						ERR("Could not load task name\n");
						return ret;
					}

					LOG("%d (%s)\n", task_pid, task_name);

					/* TODO: stop iteration when you find the swaper process. */

					if (value_parent)
					{
						value_free(value_parent);
						value_parent = NULL;
					}

					value_parent = target_load_value_member(probe->target, 
							value_task, member_task_parent,	NULL /* delim */, 
							LOAD_FLAG_AUTO_DEREF | LOAD_FLAG_AUTO_STRING | 
							LOAD_FLAG_NO_CHECK_VISIBILITY | 
							LOAD_FLAG_NO_CHECK_BOUNDS);
					if (!value_parent)
					{
						ERR("Could not load task parent\n");
						return ret;
					}

					value_task = value_parent;
				}

				if (value_parent)
				{
					value_free(value_parent);
					value_parent = NULL;
				}
			}
		}
	}

	return 0;
}

static int probe_open_init(struct probe *probe)
{
	static const char *symbol_open_filename = "sys_open.filename";
	static const char *symbol_open_flags = "sys_open.flags";

	bsymbol_open_filename = target_lookup_sym(probe->target,
			(char *)symbol_open_filename, ".", NULL /* srcfile */,
			SYMBOL_TYPE_NONE);
	if (!bsymbol_open_filename)
	{
		ERR("Could not find symbol '%s'\n", symbol_open_filename);
		return -1;
	}

	bsymbol_open_flags = target_lookup_sym(probe->target,
			(char *)symbol_open_flags, ".", NULL /* srcfile */,
			SYMBOL_TYPE_NONE);
	if (!bsymbol_open_flags)
	{
		ERR("Could not find symbol '%s'\n", symbol_open_flags);
		return -1;
	}

	return 0;
}

static int probe_open_fini(struct probe *probe)
{
	if (bsymbol_open_filename)
	{
		bsymbol_release(bsymbol_open_filename);
		bsymbol_open_filename = NULL;
	}

	if (bsymbol_open_flags)
	{
		bsymbol_release(bsymbol_open_flags);
		bsymbol_open_flags = NULL;
	}

	return 0;
}

static int register_probes(struct target *t)
{
	static const char *symbol = "sys_open";
	static const probe_handler_t handler = probe_open_entry;
	static const struct probe_ops ops = {
		.gettype = NULL,
		.init = probe_open_init,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = ctxtracker_summarize,
		.fini = probe_open_fini
	};

	struct probe *probe;

	probe = register_probe_function_entry(t, symbol, handler, &ops, NULL);
	if (!probe)
		return -1;

	g_hash_table_insert(probes, (gpointer)probe /* key */,
			(gpointer)probe /* value */);

	return 0;
}

static void sigh(int signo)
{
	if (t)
	{
		target_pause(t);

		WARN("Ending trace\n");
		cleanup_probes(probes);
		ctxtracker_cleanup();
		WARN("Ended trace\n");

		target_close(t);
		target_free(t);

		if (probes)
			g_hash_table_destroy(probes);
	}

	exit(0);
}

static void signals(sighandler_t handler)
{
	signal(SIGHUP, handler);
	signal(SIGINT, handler);
	signal(SIGQUIT, handler);
	signal(SIGABRT, handler);
	signal(SIGKILL, handler);
	signal(SIGSEGV, handler);
	signal(SIGPIPE, handler);
	signal(SIGALRM, handler);
	signal(SIGTERM, handler);
	signal(SIGUSR1, handler);
	signal(SIGUSR2, handler);
}

static void parse_opt(int argc, char *argv[])
{
	char ch;
	log_flags_t debug_flags;

	while ((ch = getopt(argc, argv, "dl:")) != -1)
	{
		switch(ch)
		{
			case 'd':
				++debug_level;
				break;

			case 'l':
				if (vmi_log_get_flag_mask(optarg, &debug_flags))
				{
					ERR("Bad debug flag in '%s'\n", optarg);
					exit(-1);
				}
				vmi_set_log_flags(debug_flags);
				break;

			default:
				ERR("Unknown option %c\n", ch);
				exit(-1);
		}
	}

	if (argc <= optind)
	{
		printf("Usage: %s [option] <domain>\n", argv[0]);
		exit(-1);
	}

	domain_name = argv[optind];
}

int main(int argc, char *argv[])
{
	int ret;

	parse_opt(argc, argv);

	if (!domain_name)
	{
		ERR("Must specify the target domain name\n");
		return -1;
	}

	probes = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (!probes)
	{
		ERR("Could not create probe table for target %s\n", domain_name);
		return -ENOMEM;
	}

	LOG("Initializing target...\n");

	t = init_probes(domain_name, debug_level);
	if (!t)
		return -1;

	LOG("Initializing context tracker...\n");

	ret = ctxtracker_init(t);
	if (ret)
	{
		ERR("Could not initialize ctxtracker for target %s\n", domain_name);
		kill(getpid(), SIGINT);
		return ret;
	}

	ret = ctxtracker_track(TRACK_TASKSWITCH, true);
	if (ret)
	{
		ERR("Could not track contexts for target %s\n", domain_name);
		kill(getpid(), SIGINT);
		return ret;
	}

	ret = register_probes(t);
	if (ret)
	{
		kill(getpid(), SIGINT);
		return ret;
	}

	signals(sigh);

	LOG("Monitoring started:\n");

	ret = run_probes(t, probes);
	if (ret)
	{
		kill(getpid(), SIGINT);
		return ret;
	}

	return 0;
}
