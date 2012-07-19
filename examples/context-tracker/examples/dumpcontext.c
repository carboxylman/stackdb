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
 *  examples/context-tracker/examples/dumpcontext.c
 *
 *  A sample application built on top of context tracker that dumps all 
 *  context change information for a Linux guest VM.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <target_api.h>
#include <target_xen_vm.h>
#include <probe_api.h>
#include <ctxtracker.h>

#include "util.h"
#include "debug.h"

extern char *optarg;
extern int optind, opterr, optopt;

char *domain_name;
int debug_level = -1;
char *sysmap_file;

struct target *t;
GHashTable *probes;

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

	while ((ch = getopt(argc, argv, "dl:m:")) != -1)
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

			case 'm':
				sysmap_file = optarg;
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

	if (!sysmap_file)
	{
		ERR("Must specify -m <System.map file name> option\n");
		return -1;
	}

	probes = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (!probes)
	{
		ERR("Could not create probe table for target %s\n", domain_name);
		return -ENOMEM;
	}

	LOG("Initializing VMI...\n");
	
	t = init_probes(domain_name, debug_level);
	if (!t)
		return -1;

	ret = ctxtracker_init(t, sysmap_file);
	if (ret)
	{
		ERR("Could not initialize ctxtracker for target %s\n", domain_name);
		return ret;
	}

    ret = ctxtracker_track(TRACK_ALL, true);

	if (ret)
	{
		ERR("Could not start tracking contexts for target %s\n", domain_name);
		return ret;
	}

	// TODO: register probes here.

	signals(sigh);

	LOG("Monitoring started:\n");
	//asm("int $3");

	ret = run_probes(t, probes);
	if (ret)
		return ret;

	return 0;
}
