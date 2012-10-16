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
 *  examples/context-tracker/examples/null-deref-analysis/pass2.c
 *
 *  PASS-2: Find out which task of the given suspected PIDs escalated 
 *  privilege.
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

#include <debug.h>
#include <util.h>
#include <perf.h>

#define O_WRONLY (00000001)
#define O_RDWR   (00000002)

/* Input to the analysis pass */
struct input {
	// the chain of tasks who might have escalated privilege.
	struct {
		int pid;
	} task_chain[128];

	// number of the suspected tasks.
	int task_count;

	// instruction counter at which the password file was open in write mode.
	unsigned long long instr_count;
};

/* Result of the analysis pass */
struct output {
	
	// the set of tasks who have escalated privilege.
	struct {
		int pid;
		char name[PATH_MAX];
		int old_uid;
		int new_uid;
	} task_chain[128];

	// number of the guilty tasks.
	int task_count;
	
	// instruction counter at which privilege was escalated.
	unsigned long long instr_counts[128];
};

extern char *optarg;
extern int optind, opterr, optopt;

static char *domain_name;
static int debug_level = -1;

static struct target *t;
static GHashTable *probes;

static const char *member_task_pid = "pid";
static const char *member_task_name = "comm";
static const char *member_task_uid = "uid";

static struct input in;
static struct output out;

static bool examined[128];
static int old_uids[128];

static int probe_watchpoint(struct probe *probe, void *data,
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	struct value *value_task;
	int task_pid;
	int task_old_uid;
	int task_new_uid;
	char task_name[PATH_MAX];
	unsigned long long instr_count;
	int i, j;

	context = (ctxtracker_context_t *)probe_summarize(probe);
	if (!context)
	{
		ERR("Could not load summarizing context data\n");
		return -1;
	}

	i = (int)data;

	/* Load task information. */

	value_task = context->task.cur;

	ret = get_member_i32(probe->target, value_task, member_task_pid, &task_pid);
	if (ret)
	{
		ERR("Could not load task pid\n");
		return ret;
	}

	ret = get_member_i32(probe->target, value_task, member_task_uid, 
			&task_new_uid);
	if (ret)
	{
		ERR("Could not load task uid\n");
		return ret;
	}

	ret = get_member_string(probe->target, value_task, member_task_name, 
			task_name);
	if (ret)
	{
		ERR("Could not load task name\n");
		return ret;
	}

	task_old_uid = old_uids[i];

	if (task_new_uid != task_old_uid) // uid modified?
	{
		j = out.task_count;

		/* Read instruction counter. */

		instr_count = perf_get_brctr(probe->target);

		/* Record the result in memory. */

		out.task_chain[j].pid = task_pid;
		strcpy(out.task_chain[j].name, task_name);
		out.task_chain[j].old_uid = task_old_uid;
		out.task_chain[j].new_uid = task_new_uid;
		out.instr_counts[j] = instr_count;
		out.task_count++;

		/* Log the result. */

		LOG("USER ID MODIFIED!\n");
		LOG("Instruction counter: %lld (0x%08llx)\n", 
				out.instr_counts[j], out.instr_counts[j]);
		LOG("Task: %d (%s)\n", out.task_chain[j].pid, out.task_chain[j].name);
		LOG("User ID: %d -> %d\n", out.task_chain[j].old_uid, 
				out.task_chain[j].new_uid);
	}

	return 0;
}

static int task_index(int pid)
{
	int i;

	for (i = 0; i < in.task_count; i++)
	{
		if (in.task_chain[i].pid == pid)
			return i;
	}

	return -1;
}

static int taskswitch(struct probe *probe, void *data,
		struct probe *trigger)
{
	static const struct probe_ops ops = {
		.gettype = NULL,
		.init = NULL,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = ctxtracker_summarize,
		.fini = NULL
	};

	int ret;
	ctxtracker_context_t *context;
	struct value *value_task;
	struct value *value_task_uid;
	unsigned long long instr_count;
	int task_pid;
	int task_uid;
	int i;

	context = (ctxtracker_context_t *)probe_summarize(probe);
	if (!context)
	{
		ERR("Could not load summarizing context data\n");
		return -1;
	}

	/* Check if the analysis should finish. */

	instr_count = perf_get_brctr(probe->target);

	if (instr_count >= in.instr_count)
		kill_everything(domain_name);

	value_task = context->task.cur;

	ret = get_member_i32(probe->target, value_task, member_task_pid, &task_pid);
	if (ret)
	{
		ERR("Could not load task pid\n");
		return ret;
	}

	/* Filter out innocent tasks. */

	i = task_index(task_pid);
	if (i >= 0) // suspected task?
	{
		if (!examined[i]) // not examined yet?
		{
			value_task_uid = target_load_value_member(probe->target, 
					value_task, member_task_uid, NULL /* delim */, 
					LOAD_FLAG_NONE);
			if (!value_task_uid)
			{
				ERR("Could not load task uid\n");
				return ret;
			}
			task_uid = v_i32(value_task_uid);

			if (task_uid != 0) // non-root?
			{
				/* Set up a readwrite watchpoint on the UID. */
				
				probe = register_watchpoint(probe->target, value_task_uid, 
						"" /* name */, probe_watchpoint, &ops /* ops */, 
						(void *)i /* data */, true /* readwrite */);
				if (!probe)
				{
					value_free(value_task_uid);
					return ret;
				}

				g_hash_table_insert(probes, (gpointer)probe /* key */,
						(gpointer)probe /* value */);

				old_uids[i] = task_uid;
			}

			value_free(value_task_uid);

			examined[i] = true;
		}
	}

	return 0;
}

static int register_probes(struct target *t)
{
	int ret;

	ret = ctxtracker_register_handler(TRACK_TASKSWITCH, taskswitch, 
			NULL, true);
	if (ret)
	{
		ERR("Could not register handler on task switches\n");
		return ret;
	}

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

	while ((ch = getopt(argc, argv, "dl:i:p:")) != -1)
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

			case 'i':
				in.instr_count = atoll(optarg);
				break;

			case 'p':
				in.task_chain[in.task_count++].pid = atoi(optarg);
				break;

			default:
				ERR("Unknown option %c\n", ch);
				exit(-1);
		}
	}

	if (argc <= optind)
	{
		printf("Usage: sudo %s [OPTION] <DOMAIN>\n", argv[0]);
		printf("PASS-2: Find out which task of the given suspected PIDs "
				"escalated privilege.\n");
		printf("\n");
		printf("Options:\n");
		printf("  -d                          Increase debug level. Multiple "
				"d's can be specified.\n");
		printf("  -l <log flags>              Show more logs by adding log "
				"flags.\n");
		printf("  -i <instruction counter>    End analysis at this "
				"instruction counter.\n");
		printf("  -p <suspected PIDs>         Find which task escalated "
				"privilege among those of the\n"
				"                              specified PIDs.\n");
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

	if (!in.task_count)
	{
		ERR("Must specify at least one suspected PID\n");
		return -1;
	}

	if (!in.instr_count)
	{
		ERR("Must specify the instruction counter at which analysis will "
				"finish.\n");
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
