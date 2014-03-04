/*
 * Copyright (c) 2011, 2012, 2013, 2014 The University of Utah
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

int function_name_to_id(char * function_name, int* function_id, int* submodule_id){

    if(!strncmp(function_name, "kill_process",12)) {
	*function_id = 0;
	*submodule_id = 0;
	return 0;
    }
    else if(!strncmp(function_name, "reset_credentials", 17)) {
	*function_id = 0;
	*submodule_id = 1;
	return 0;
    }
    else if(!strncmp(function_name,"fix_syscall_entry", 17)) {
	*function_id = 0;
	*submodule_id = 2;
	return 0;
    }
    else if(!strncmp(function_name,"fix_hooked_entry", 16)) {
	*function_id = 1;
	*submodule_id = 2;
	return 0;
    }
    else if(!strncmp(function_name,"close_tcp_socket", 16)) {
	*function_id = 0;
	*submodule_id = 3;
	return 0;
    }
    else if(!strncmp(function_name,"close_udp_socket", 16)) {
	*function_id = 1;
	*submodule_id = 3;
	return 0;
    }
    else if(!strncmp(function_name,"unload_module", 13)) {
	*function_id = 0;
	*submodule_id = 4;
	return 0;
    } 
    else if(!strncmp(function_name,"unload_object", 12)) {
	*function_id = 0;
	*submodule_id = 5;
	return 0;
    } 
    else if(!strncmp(function_name,"close_open_files", 16)) {
	*function_id = 0;
	*submodule_id = 5;
	return 0;
    } 

    return 1;
}

int parse_recovery_action() {

    FILE *fp;
    char fact[1024];
    char function_name[50];
    int ret, i ,argc;
    int function_id;
    int submodule_id;
    char args[128][50];
    char delim[] = " \t()\"";
    char *cur_token =NULL;
    void *arguments = NULL;

    /* Open the recovey_action file */
    fp = fopen("state_information/recovery_action.fac", "r");
    if(fp == NULL) {
	fprintf(stdout,"WARINING: Failed to open the recovery action file, continuing.\n");
	return 1;
    }

    /* now read one fact at a time and parse it */
    while(fgets(fact,1024,fp) != NULL) {
	fprintf(stdout,"INFO: Fact read : %s\n",fact);

	/* Tokenize the fact */
	i = 0;
	argc = 0;
	cur_token = (char *)strtok(fact, delim );
	if( cur_token == NULL) continue;
	cur_token = (char *) strtok(NULL, delim);
	cur_token = (char *) strtok(NULL, delim);

	strcpy(function_name, cur_token); 
	fprintf(stdout,"INFO: function invoked is %s\n",function_name);
	cur_token = (char *) strtok(NULL, delim);

	/* Now parse all the arguments that are to be passed to that function */
	while((cur_token = (char *) strtok(NULL, delim))) {
	    if(cur_token == NULL) break;
	    argc++;
	    strcpy(args[i],cur_token);
	    printf("INFO: args[%d] = %s\n",i,args[i]);
	    i++;
	}

	/* Map funtion name to appropriate funtion ID */
	ret = function_name_to_id (function_name, &function_id, &submodule_id);
	if(ret) {
	    fprintf(stdout,"ERROR: Invalid function name : %s\n", function_name);
	    continue;
	}

	arguments = (void *)malloc(128 * sizeof(unsigned long));
	if(!arguments) {
	    fprintf(stdout,"ERROR: Failed to allocate memory for the arguments buffer.\n");
	    continue;
	}
	bzero(arguments, 128*sizeof(unsigned long));

	/* Now based on the function invoked parse the arguments appropriately
	 * and load the command into the ring buffer
	 */

	int *int_ptr = NULL;
	char *char_ptr = NULL;
	switch(submodule_id) 
	{
	    case 0 :        /* Function to kill a process */
		int_ptr = (int *) arguments;
		int pid = atoi(args[1]);
		memcpy((void *)int_ptr, (void *) &pid, sizeof(int));
		fprintf(stdout,"INFO: Invoking function to kill process %s : %d \n",
			args[0], *int_ptr);
		int_ptr++;
		/*
		   ret = load_command_func(function_id,submodule_id,args,argc);
		   if(ret) {
		   fprintf(stdout,"ERROR: load_comand_func call failed.\n");
		   return 1;
		   }
		 */
		break;
	    default: 
		fprintf(stdout,"ERROR: Invalid function called.\n");
	}

	free(arguments);
    }
    fclose(fp);
    /* cleanup the recovery_action file */
    fp = fopen("state_information/recovery_action.fac", "w");
    fclose(fp);
    return 0;
}




