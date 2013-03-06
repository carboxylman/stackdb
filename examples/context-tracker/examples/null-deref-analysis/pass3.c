/*
 * Copyright (c) 2012, 2013 The University of Utah
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
 *  examples/context-tracker/examples/null-deref-analysis/pass3.c
 *
 *  PASS-3: Find out in which system call, called by the task of a 
 *  given PID, modified the UID bit.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#ifndef CONFIG_DETERMINISTIC_TIMETRAVEL
#error "Program runs only on Time Travel enabled Xen"
#endif

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

#include <debug.h>
#include <util.h>
#include <perf.h>

/* Input to the analysis pass */
struct input {
	// the task who escalated privilege.
	struct {
		int pid;
	} task;

	// instruction counter at which privilege was escalated.
	unsigned long long instr_count;
};

/* Result of the analysis pass */
struct output {
};

extern char *optarg;
extern int optind, opterr, optopt;

static char *domain_name;
static int debug_level = -1;

static struct target *t;
static GHashTable *probes;

static const char *member_task_pid = "pid";
static const char *member_task_name = "comm";

static struct input in;
static struct output out;

static int register_probes(struct target *t)
{
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

	while ((ch = getopt(argc, argv, "dl:i:p:")) != -1)
	{
		switch(ch)
		{
			case 'd':
				++debug_level;
				break;

			case 'l':
				if (vmi_set_log_area_flaglist(optarg, NULL))
				{
					ERR("Bad debug flag in '%s'\n", optarg);
					exit(-1);
				}
				break;

			case 'i':
				in.instr_count = atoll(optarg);
				break;

			case 'p':
				in.task.pid = atoi(optarg);
				break;

			default:
				ERR("Unknown option %c\n", ch);
				exit(-1);
		}
	}

	if (argc <= optind)
	{
		printf("Usage: sudo %s [OPTION] <DOMAIN>\n", argv[0]);
		printf("PASS-3: Find out in which system call privilege was "
				"escalated.\n");
		printf("\n");
		printf("Options:\n");
		printf("  -d                          Increase debug level. Multiple "
				"d's can be specified.\n");
		printf("  -l <log flags>              Show more logs by adding log "
				"flags.\n");
		printf("  -i <instruction counter>    End analysis at this "
				"instruction counter.\n");
		printf("  -p <suspected PID>          Find which system call, called "
				"by the task of the\n"
				"                              specified PID, escalated "
				"privilege.\n");
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

	ret = perf_init();
	if (ret)
	{
		ERR("Could not initialize replay performance module for target %s\n",
				domain_name);
		return -1;
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
