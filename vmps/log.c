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
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <string.h>
#include <limits.h>

FILE* logfile;
char conf_logfile[PATH_MAX];

int log_init(void)
{
    if (strlen(conf_logfile) == 0)
        return -1;

    logfile = fopen(conf_logfile, "a");
    if (!logfile)
        return -1;
	
	printf("Log file at \"%s\"\n", conf_logfile);
    return 0;
}

void log_cleanup(void)
{
    if (logfile)
        fclose(logfile);
}
