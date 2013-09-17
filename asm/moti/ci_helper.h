/*
 * Copyright (c) 2011, 2012, 2013 The University of Utah
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

#include <string.h>

int read_system_map(char *key , int *address) {

    char filepath[] = "/boot/System.map-2.6.18-xenU";
    FILE *fd;
    char addr[20];
    char perm[20];
    char func[40];
    ci_error_t ret = CI_SUCCESS;

    /*
     * Need a way to figure out how to read values dynamically
     * from the correct system.map table. As of now hardcoding
     * the path to the file.
     */
    fd = fopen(filepath,"r");
    if(fd == NULL) {
	fprintf(stdout, 
		"ERROR: Failed to open the file %s. \n",filepath);
	ret = CI_LOOKUP_ERR;
	goto read_system_map_out;
    }

    while((fscanf(fd,"%x %s %s", addr,perm,func)) != EOF) {
	if(!strcmp(func,key)) {
	    *address = (void *)addr;
	    fprintf(stdout,"%x\n",*address);
	    ret = CI_SUCCESS;
	    goto read_system_map_out;
	}
    }

    fprintf(stdout,"ERROR: Could not find the requested entry.\n");
    ret = CI_ERROR;

read_system_map_out:
    fclose(fd);
    return ret;
}

int read_unistd(char *key , int *value) {

    char filepath[] = "/usr/include/asm/unistd.h";
    FILE *fd;
    char str1[20]; /* to store the #define line read from file */
    int enum_value;
    ci_error_t ret = CI_SUCCESS;

    /*
     * Need a way to figure out how to read values dynamically
     * from the correct file. As of now hardcoding
     * the path to the file.
     */
    fd = fopen(filepath,"r");
    if(fd == NULL) {
	fprintf(stdout, 
		"ERROR: Failed to open the file %s. \n",filepath);
	ret = CI_LOOKUP_ERR;
	goto read_unistd_out;
    }
    while((fscanf(fd,"%s", str1)) !=EOF) {
	fprintf(stdout,"%s %s\n",key+4, str1+5);
	if(!strcmp(key +4,str1+5)) {
	    fscanf(fd,"%d",enum_value);
	    *value = enum_value;
	    fprintf(stdout,"%s %s %d\n",key ,str1, *value);
	    ret = CI_SUCCESS;
	    goto read_unistd_out;
	}
    }

    fprintf(stdout,"ERROR: Could not find the requested entry.\n");
    ret = CI_ERROR;

read_unistd_out:
    fclose(fd);
    return ret;
}


