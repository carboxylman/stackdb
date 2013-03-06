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
 *  examples/context-tracker/examples/dumpcontext/dumpcontext.c
 *
 *  A sample application built on top of context tracker that dumps all 
 *  context change information for a Linux guest VM.
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
//#include <private.h>

#include <debug.h>
#include <util.h>

extern char *optarg;
extern int optind, opterr, optopt;

static char *domain_name;
static int debug_level = -1;
static int xa_debug_level = -1;
static ctxtracker_track_t track = TRACK_NONE;

static struct target *t;

static const char *member_task_pid = "pid";
static const char *member_task_name = "comm";
static const char *member_regs_eip = "eip";

static result_t taskswitch(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	struct value *value_prev, *value_next;
	int prev_pid, next_pid;
	char prev_name[PATH_MAX], next_name[PATH_MAX];

	context = (ctxtracker_context_t *)probe_summarize(probe);
	if (!context)
	{
		ERR("Could not load summarizing context data\n");
		return -1;
	}

	value_prev = context->task.prev;
	value_next = context->task.cur;

	ret = get_member_i32(probe->target, value_prev, member_task_pid, &prev_pid);
	if (ret)
	{
		ERR("Could not load member int32 '%s.%s'\n",
				value_prev->lsymbol->symbol->name, member_task_pid);
		return ret;
	}

	ret = get_member_string(probe->target, value_prev, member_task_name,
			prev_name);
	if (ret)
	{
		ERR("Could not load member string '%s.%s'\n",
				value_prev->lsymbol->symbol->name, member_task_name);
		return ret;
	}

	ret = get_member_i32(probe->target, value_next, member_task_pid, &next_pid);
	if (ret)
	{
		ERR("Could not load member int32 '%s.%s'\n", 
				value_next->lsymbol->symbol->name, member_task_pid);
		return ret;
	}

	ret = get_member_string(probe->target, value_next, member_task_name, 
			next_name);
	if (ret)
	{
		ERR("Could not load member string '%s.%s'\n", 
				value_next->lsymbol->symbol->name, member_task_name);
		return ret;
	}

	LOG("TASK SWITCH: %d (%s) -> %d (%s)\n", 
			prev_pid, prev_name, next_pid, next_name);

	return 0;
}

static result_t interrupt_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	struct value *value_regs;
	REGVAL eip;
	int irq_num;
	int task_pid;
	char task_name[PATH_MAX];

	context = (ctxtracker_context_t *)probe_summarize(probe);
	if (!context)
	{
		ERR("Could not load summarizing context data\n");
		return -1;
	}

	irq_num = context->interrupt.irq_num;
	value_regs = context->interrupt.regs;

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		ERR("Could not load member regval '%s.%s'\n",
				value_regs->lsymbol->symbol->name, member_regs_eip);
		return ret;
	}

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid,
				&task_pid);
		if (ret)
		{
			ERR("Could not load member int32 '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur,
				member_task_name, task_name);
		if (ret)
		{
			ERR("Could not load member string '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_name);
			return ret;
		}

		LOG("%d (%s): Interrupt %d (0x%02x) requested (eip = 0x%08x)\n", 
				task_pid, task_name, irq_num, irq_num, eip);
	}
	else
	{
		LOG("UNKNOWN TASK: Interrupt %d (0x%02x) requested (eip = 0x%08x)\n", 
				irq_num, irq_num, eip);
	}

	return 0;
}

static result_t interrupt_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	int irq_num;
	int task_pid;
	char task_name[PATH_MAX];

	context = (ctxtracker_context_t *)probe_summarize(probe);
	if (!context)
	{
		ERR("Could not load summarizing context data\n");
		return -1;
	}

	irq_num = context->interrupt.irq_num;

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid,
				&task_pid);
		if (ret)
		{
			ERR("Could not load member int32 '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur,
				member_task_name, task_name);
		if (ret)
		{
			ERR("Could not load member string '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_name);
			return ret;
		}

		LOG("%d (%s): Interrupt %d (0x%02x) handled\n", 
				task_pid, task_name, irq_num, irq_num);
	}
	else
	{
		LOG("UNKNOWN TASK: Interrupt %d (0x%02x) handled\n", irq_num, irq_num);
	}

	return 0;
}

static result_t pagefault_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	struct value *value_regs;
	REGVAL eip;
	ADDR addr;
	bool protection_fault;
	bool write_access;
	bool user_mode;
	bool reserved_bit;
	bool instr_fetch;
	char str_error_code[128];
	int task_pid;
	char task_name[PATH_MAX];

	context = (ctxtracker_context_t *)probe_summarize(probe);
	if (!context)
	{
		ERR("Could not load summarizing context data\n");
		return -1;
	}

	addr = context->pagefault.addr;
	value_regs = context->pagefault.regs;
	protection_fault = context->pagefault.protection_fault;
	write_access = context->pagefault.write_access;
	user_mode = context->pagefault.user_mode;
	reserved_bit = context->pagefault.reserved_bit;
	instr_fetch = context->pagefault.instr_fetch;

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		ERR("Could not load member regval '%s.%s'\n",
				value_regs->lsymbol->symbol->name, member_regs_eip);
		return ret;
	}

	strcpy(str_error_code, protection_fault ?
			"protection-fault, " : "no-page-found, ");
	strcat(str_error_code, write_access ?
			"write, " : "read, ");
	strcat(str_error_code, user_mode ?
			"user, " : "kernel, ");
	strcat(str_error_code, reserved_bit ?
			"reserved-bit, " : "");
	strcat(str_error_code, instr_fetch ?
			"instr-fetch, " : "");
	str_error_code[strlen(str_error_code)-2] = '\0';

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid,
				&task_pid);
		if (ret)
		{
			ERR("Could not load member int32 '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur,
				member_task_name, task_name);
		if (ret)
		{
			ERR("Could not load member string '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_name);
			return ret;
		}

		LOG("%d (%s): Page fault 0x%08x occurred (eip = 0x%08x, %s)\n",
				task_pid, task_name, addr, eip, str_error_code);
	}
	else
	{
		LOG("UNKNOWN TASK: Page fault 0x%08x occurred (eip = 0x%08x, %s)\n",
				addr, eip, str_error_code);
	}

	return 0;
}

static result_t pagefault_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	ADDR addr;
	int task_pid;
	char task_name[PATH_MAX];

	context = (ctxtracker_context_t *)probe_summarize(probe);
	if (!context)
	{
		ERR("Could not load summarizing context data\n");
		return -1;
	}

	addr = context->pagefault.addr;

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid,
				&task_pid);
		if (ret)
		{
			ERR("Could not load member int32 '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur,
				member_task_name, task_name);
		if (ret)
		{
			ERR("Could not load member string '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_name);
			return ret;
		}

		LOG("%d (%s): Page fault 0x%08x handled\n", task_pid, task_name, addr);
	}
	else
	{
		LOG("UNKNOWN TASK: Page fault 0x%08x handled\n", addr);
	}

	return 0;
}

static result_t exception_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	char exception_name[128];
	struct value *value_regs;
	REGVAL eip;
	uint32_t error_code;
	int task_pid;
	char task_name[PATH_MAX];

	context = (ctxtracker_context_t *)probe_summarize(probe);
	if (!context)
	{
		ERR("Could not load summarizing context data\n");
		return -1;
	}

	strcpy(exception_name, context->exception.name);
	exception_name[0] = toupper(exception_name[0]);
	value_regs = context->exception.regs;
	error_code = context->exception.error_code;

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		ERR("Could not load member regval '%s.%s'\n",
				value_regs->lsymbol->symbol->name, member_regs_eip);
		return ret;
	}

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid,
				&task_pid);
		if (ret)
		{
			ERR("Could not load member int32 '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur,
				member_task_name, task_name);
		if (ret)
		{
			ERR("Could not load member string '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_name);
			return ret;
		}

		LOG("%d (%s): %s exception occurred: "
				"(eip = 0x%08x, error-code = 0x%08x)\n",
				task_pid, task_name, exception_name, eip, error_code);
	}
	else
	{
		LOG("UNKNOWN TASK: %s exception occurred: "
				"(eip = 0x%08x, error-code = 0x%08x)\n", 
				exception_name, eip, error_code);
	}

	return 0;
}

static result_t exception_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	char exception_name[128];
	int task_pid;
	char task_name[PATH_MAX];

	context = (ctxtracker_context_t *)probe_summarize(probe);
	if (!context)
	{
		ERR("Could not load summarizing context data\n");
		return -1;
	}

	strcpy(exception_name, context->exception.name);
	exception_name[0] = toupper(exception_name[0]);

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid,
				&task_pid);
		if (ret)
		{
			ERR("Could not load member int32 '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur,
				member_task_name, task_name);
		if (ret)
		{
			ERR("Could not load member string '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_name);
			return ret;
		}

		LOG("%d (%s): %s exception handled\n", 
				task_pid, task_name, exception_name);
	}
	else
	{
		LOG("UNKNOWN TASK: %s exception handled\n", exception_name);
	}

	return 0;
}

static result_t syscall_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	int sc_num;
	int task_pid;
	char task_name[PATH_MAX];

	context = (ctxtracker_context_t *)probe_summarize(probe);
	if (!context)
	{
		ERR("Could not load summarizing context data\n");
		return -1;
	}

	sc_num = context->syscall.sc_num;

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid,
				&task_pid);
		if (ret)
		{
			ERR("Could not load member int32 '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur,
				member_task_name, task_name);
		if (ret)
		{
			ERR("Could not load member string '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_name);
			return ret;
		}

		LOG("%d (%s): System call %d (0x%02x) called\n", 
				task_pid, task_name, sc_num, sc_num);
	}
	else
	{
		LOG("UNKNOWN TASK: System call %d (0x%02x) called\n", sc_num, sc_num);
	}

	return 0;
}

static result_t syscall_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	int sc_num;
	int task_pid;
	char task_name[PATH_MAX];

	context = (ctxtracker_context_t *)probe_summarize(probe);
	if (!context)
	{
		ERR("Could not load summarizing context data\n");
		return -1;
	}

	sc_num = context->syscall.sc_num;

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid,
				&task_pid);
		if (ret)
		{
			ERR("Could not load member int32 '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur,
				member_task_name, task_name);
		if (ret)
		{
			ERR("Could not load member string '%s.%s'\n",
					context->task.cur->lsymbol->symbol->name, member_task_name);
			return ret;
		}

		LOG("%d (%s): System call %d (0x%02x) returned\n",
				task_pid, task_name, sc_num, sc_num);
	}
	else
	{
		LOG("UNKNOWN TASK: System call %d (0x%02x) returned\n", sc_num, sc_num);
	}

	return 0;
}

static void sigh(int signo)
{
	if (t)
	{
		target_pause(t);

		WARN("Ending trace\n");
		ctxtracker_cleanup();
		WARN("Ended trace\n");

		target_close(t);
		target_free(t);
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

	while ((ch = getopt(argc, argv, "dxl:c:")) != -1)
	{
		switch(ch)
		{
			case 'd':
				++debug_level;
				break;

			case 'x':
				++xa_debug_level;
				break;

			case 'l':
				if (vmi_set_log_area_flaglist(optarg,NULL))
				{
					ERR("Bad debug flag in '%s'\n", optarg);
					exit(-1);
				}
				break;

			case 'c':
				if (strcasecmp(optarg, "all") == 0)
					track = TRACK_ALL;
				else if (strcasecmp(optarg, "taskswitch") == 0)
					track |= TRACK_TASKSWITCH;
				else if (strcasecmp(optarg, "interrupt") == 0)
					track |= TRACK_INTERRUPT;
				else if (strcasecmp(optarg, "pagefault") == 0)
					track |= TRACK_PAGEFAULT;
				else if (strcasecmp(optarg, "exception") == 0)
					track |= TRACK_EXCEPTION;
				else if (strcasecmp(optarg, "syscall") == 0)
					track |= TRACK_SYSCALL;
				break;

			default:
				ERR("Unknown option %c\n", ch);
				exit(-1);
		}
	}

	if (argc <= optind)
	{
		printf("Usage: sudo %s [OPTION] <DOMAIN>\n", argv[0]);
		printf("Dump context change information for a Linux guest VM.\n");
		printf("\n");
		printf("Options:\n");
		printf("  -d:                    Increase debug level. Multiple d's "
				"can be specified.\n");
		printf("  -l <log flags>:        Show more logs by adding log "
				"flags.\n");
		printf("  -c <context flags>:    Dump context information by "
				"specifying flags.\n");
		printf("  Context flags:\n");
		printf("    all:           Dump all context information.\n");
		printf("    taskswitch:    Dump information about task switches.\n");
		printf("    interrupt:     Dump information about interrupts.\n");
		printf("    pagefault:     Dump information about page faults.\n");
		printf("    exception:     Dump information about exceptions.\n");
		printf("    syscall:       Dump information about system calls.\n");
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

	if (track == TRACK_NONE)
	{
		ERR("Must specify -c "
				"<all|taskswitch|interrupt|pagefault|exception|syscall>\n");
		return -1;
	}

	LOG("Initializing target...\n");

	t = init_probes(domain_name, debug_level, xa_debug_level);
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

	ret = ctxtracker_track(track, true);
	if (ret)
	{
		ERR("Could not track contexts for target %s\n", domain_name);
		kill(getpid(), SIGINT);
		return ret;
	}

	if (track & TRACK_TASKSWITCH)
	{
		ret = ctxtracker_register_handler(TRACK_TASKSWITCH, taskswitch, 
				NULL, true);
		if (ret)
		{
			ERR("Could not register handler on task switches for target %s\n", 
					domain_name);
			kill(getpid(), SIGINT);
			return ret;
		}
	}

	if (track & TRACK_INTERRUPT)
	{
		ret = ctxtracker_register_handler(TRACK_INTERRUPT, 
				interrupt_entry, NULL, true);
		if (ret)
		{
			ERR("Could not register handler on interrupt entries for "
					"target %s\n", domain_name);
			kill(getpid(), SIGINT);
			return ret;
		}

		ret = ctxtracker_register_handler(TRACK_INTERRUPT, 
				interrupt_exit, NULL, false);
		if (ret)
		{
			ERR("Could not register handler on interrupt exits for "
					"target %s\n", domain_name);
			kill(getpid(), SIGINT);
			return ret;
		}
	}

	if (track & TRACK_PAGEFAULT)
	{
		ret = ctxtracker_register_handler(TRACK_PAGEFAULT, 
				pagefault_entry, NULL, true);
		if (ret)
		{
			ERR("Could not register handler on page fault entries for "
					"target %s\n", domain_name);
			kill(getpid(), SIGINT);
			return ret;
		}

		ret = ctxtracker_register_handler(TRACK_PAGEFAULT, 
				pagefault_exit, NULL, false);
		if (ret)
		{
			ERR("Could not register handler on page fault exits for "
					"target %s\n", domain_name);
			kill(getpid(), SIGINT);
			return ret;
		}
	}

	if (track & TRACK_EXCEPTION)
	{
		ret = ctxtracker_register_handler(TRACK_EXCEPTION, 
				exception_entry, NULL, true);
		if (ret)
		{
			ERR("Could not register handler on exception entries for "
					"target %s\n", domain_name);
			kill(getpid(), SIGINT);
			return ret;
		}

		ret = ctxtracker_register_handler(TRACK_EXCEPTION, 
				exception_exit, NULL, false);
		if (ret)
		{
			ERR("Could not register handler on exception exits for "
					"target %s\n", domain_name);
			kill(getpid(), SIGINT);
			return ret;
		}
	}

	if (track & TRACK_SYSCALL)
	{
		ret = ctxtracker_register_handler(TRACK_SYSCALL, syscall_entry, 
				NULL, true);
		if (ret)
		{
			ERR("Could not register handler on system call entries for "
					"target %s\n", domain_name);
			kill(getpid(), SIGINT);
			return ret;
		}

		ret = ctxtracker_register_handler(TRACK_SYSCALL, syscall_exit, 
				NULL, false);
		if (ret)
		{
			ERR("Could not register handler on system call exits for "
					"target %s\n", domain_name);
			kill(getpid(), SIGINT);
			return ret;
		}
	}

	signals(sigh);

	LOG("Monitoring started:\n");

	ret = run_probes(t, NULL);
	if (ret)
	{
		kill(getpid(), SIGINT);
		return ret;
	}

	return 0;
}
