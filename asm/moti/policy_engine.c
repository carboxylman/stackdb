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

/*  Policy_engine outline: 
 *   Step1: Initialize  the CLIPS environment.
 *   Step2: Load the rules file into the framework: both application levl rules
 *	    and recovery rules
 *   Step3: Repeat the following steps at periodic intrrvals.
 *	Step3.1: Makes a call to the VMI based tools to gather system snapshot: base facts
 *	Step3.2: Loads the facts file generated by VMI into the clips framework
 *	Step3.3: The application level rules activated generate a set of anomaly facts.
 *	Step3.4: The anomaly facts active a bunch of recvery facts.
 *	Step3.5: The activated recovery facts generate a set of recovery facts which 
 *		 trigger the recovery action.
 *  
 *  Input:
 *	1. Loop repeat interval
 *	2. The .clp file which encodes application level knowledge
 *	3. The .clp file which encodes the recovey rules
 *  
 *  Output:
 *	1. A fact file which represent the state of the Virtual appliance
 *
 * Dependencies and Interactions
 *	1. Capability to interact with VMI tools to gather base facts
 *	2. Capability to interact with the the command_interface to drive 
 *	   recovery actions
 */


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <inttypes.h>
#include <signal.h>
#include <argp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "log.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"
#include "target_xen_vm.h"
#include "probe_api.h"
#include "probe.h"
#include "alist.h"
#include "list.h"
#include "policy_engine.h"
#include "repair_engine.h"
#include "clips.h"

struct target *target = NULL;
char base_fact_file[100];
unsigned long *sys_call_table = NULL;
char **sys_call_names = NULL;
unsigned char **function_prologue = NULL;
char *res = NULL;



int save_sys_call_table_entries() {

    int i, max_num;
    struct target_os_syscall *sc;
    unsigned char prologue[6];

    fprintf(stdout,"INFO: Saving the state of the initial system call table.\n");
    /* Load the syscall table */
    fprintf(stdout,"INFO: Loading the syscall table.\n");
    if(target_os_syscall_table_load(target)) {
	fprintf(stdout,"ERROR: Failed to load the syscall table.\n");
	return 1;
    }

    max_num = target_os_syscall_table_get_max_num(target);
    if(max_num < 0) {
	fprintf(stdout,"ERROR: Failed to get the max number of target sysscalls.\n");
	return 1;
    }
    fprintf(stdout,"INFO: maximum number of system calls %d \n",max_num);

    /* Allocate memory for the sys_call_table and sys_call_names */

    sys_call_table  = (unsigned long *) malloc(max_num * sizeof(unsigned long));
    if(sys_call_table == NULL) {
	fprintf(stdout,"ERROR: Failed to allocate memory for sys_call_table.\n");
	exit(0);
    }
    sys_call_names = (char *) malloc(max_num * sizeof(char *));
    if(sys_call_names == NULL) {
	fprintf(stdout,"ERROR: Failed to allocate memmory for sys_call_names.\n");
	exit(0);
    }
    
    function_prologue = (char *) malloc(max_num * sizeof(char *));
    if(function_prologue == NULL) {
	fprintf(stdout,"ERROR: Failed to allocate memory for function prologue.\n");
	exit(0);
    }


    for(i = 0; i < max_num; i++) {
	sc = target_os_syscall_lookup_num(target, i);
	if(!sc) {
	    continue;
	}
	if(sc->bsymbol) {
	    /*
	    fprintf(stdout,"%d\t %"PRIxADDR"\t%s\n", sc->num, sc->addr, 
					    bsymbol_get_name(sc->bsymbol));
	    */
	    sys_call_table[sc->num] = sc->addr;
	    sys_call_names[sc->num] =  (char *) malloc(100* sizeof(char));
	    if(sys_call_names[sc->num] == NULL) {
		fprintf(stdout,"ERROR: Failed to allocate memory for the string.\n");
		exit(0);
	    }
	    strcpy(sys_call_names[sc->num], bsymbol_get_name(sc->bsymbol));


	    /* now to detect inline hooking of system calls, we capture store the 
	     * intructions at the first 6 bytes of the function address
	     */
            function_prologue[sc->num] = (char *)malloc(6*sizeof(char));
	    if(function_prologue[sc->num] == NULL) {
		fprintf(stdout,"ERROR: Failed to alloacate memory to store the function prologue.\n");
		exit(0);
	    }
	    
	    res = target_read_addr(target, sc->addr, 6, prologue);
	    if(!res) {
		fprintf(stdout, "ERROR: Could not read 6 bytes at 0x%"PRIxADDR"!\n",sc->addr);
		exit(0);
	    }
	    //fprintf(stdout,"INFO: prologue : %02X%02X%02X%02X%02X%02X\n",prologue[0],prologue[1],prologue[2],prologue[3],prologue[4],prologue[5]);
	    memcpy(function_prologue[sc->num], prologue,6);
	    
	}
    }
    return 0;
}

target_status_t cleanup() {

    target_status_t retval;
    retval = target_close(target);
    target_free(target);
    return retval;
}

int generate_timestamp(char *date) {

    time_t t;
    struct tm *tm;
    int result = 0;

    time(&t);
    tm = localtime(&t);
    result = strftime(date,100, "state_information/%Y_%m_%d_%H_%M_%S.fac", tm);

    return result;
}

int generate_snapshot() {

    int result = 0;
    target_status_t status;
	
    static struct timeval tm1;
    gettimeofday(&tm1, NULL);

    /* Pause the target */
    if ((status = target_status(target)) != TSTATUS_PAUSED) {
	//fprintf(stdout,"INFO: Pausing the target\n");
	if (target_pause(target)) {
		fprintf(stderr,"Failed to pause the target \n");
		result = 1;
		goto resume;
	 }
    }
    static struct timeval tm2;
    gettimeofday(&tm2, NULL);
    unsigned long long t = (1000 * (tm2.tv_sec - tm1.tv_sec)) + ((tm2.tv_usec - tm1.tv_usec)/1000);
    //fprintf(stdout,"INFO: Time taken to pause the target is %llu ms\n", t); 
		    
    /* Start making calls to each of the VMI function */ 
    
    gettimeofday(&tm1, NULL);
    result = process_info();
    if(result) {
	fprintf(stdout,"ERROR: process_info function failed\n");
	result = 1;
	goto resume;
    }
    gettimeofday(&tm2, NULL);
    t = (1000 * (tm2.tv_sec - tm1.tv_sec)) + ((tm2.tv_usec - tm1.tv_usec)/1000);
    //fprintf(stdout,"INFO: Time taken to get process info is %llu ms\n", t); 

    gettimeofday(&tm1, NULL);
    result =  file_info();
    if(result) {
	fprintf(stdout,"ERROR: file_info function failed.\n");
	result = 1;
	goto resume;
    }
    gettimeofday(&tm2, NULL);
    t = (1000 * (tm2.tv_sec - tm1.tv_sec)) + ((tm2.tv_usec - tm1.tv_usec)/1000);
    //fprintf(stdout,"INFO: Time taken to get file info is %llu ms\n", t); 

    
    gettimeofday(&tm1, NULL);
    result = module_info();
    if(result) {
	fprintf(stdout,"ERRROR: module_info function failed.\n");
	result = 1;
	goto resume;
    }
    gettimeofday(&tm2, NULL);
    t = (1000 * (tm2.tv_sec - tm1.tv_sec)) + ((tm2.tv_usec - tm1.tv_usec)/1000);
    //fprintf(stdout,"INFO: Time taken to get module info is %llu ms\n", t); 
   
    
    gettimeofday(&tm1, NULL);
    result = cpu_load_info();
    if(result) {
	fprintf(stdout,"ERROR: cpu_load_info failed.\n");
	result = 1;
	goto resume;
    }
    gettimeofday(&tm2, NULL);
    t = (1000 * (tm2.tv_sec - tm1.tv_sec)) + ((tm2.tv_usec - tm1.tv_usec)/1000);
    //fprintf(stdout,"INFO: Time taken to get cpu load info is %llu ms\n", t); 

   /*
    result = process_cpu_utilization();
    if(result) {
	fprintf(stdout,"ERROR: process_cpu_utilization failed.\n");
	result = 1;
	goto resume;
    }
    */
    
    gettimeofday(&tm1, NULL);
    result = object_info();
    if(result) {
	fprintf(stdout,"ERROR: object_info failed.\n");
	result  = 1;
	goto resume;
    }
    gettimeofday(&tm2, NULL);
    t = (1000 * (tm2.tv_sec - tm1.tv_sec)) + ((tm2.tv_usec - tm1.tv_usec)/1000);
    //fprintf(stdout,"INFO: Time taken to get object file info is %llu ms\n", t);  
    
    gettimeofday(&tm1, NULL);
    result = syscalltable_info();
    if(result) {
	fprintf(stdout,"ERROR: syscallcalltable_info failed.\n");
	result = 1;
	goto resume;
    }
    gettimeofday(&tm2, NULL);
    t = (1000 * (tm2.tv_sec - tm1.tv_sec)) + ((tm2.tv_usec - tm1.tv_usec)/1000);
    //fprintf(stdout,"INFO: Time taken to get syscalltable info is %llu ms\n", t); 
   
    gettimeofday(&tm1, NULL);
    result = commandline_info();
    if( result) {
	fprintf(stdout,"ERROR: commandline_info failed.\n");
	goto resume;
    }
    gettimeofday(&tm2, NULL);
    t = (1000 * (tm2.tv_sec - tm1.tv_sec)) + ((tm2.tv_usec - tm1.tv_usec)/1000);
    //fprintf(stdout,"INFO: Time taken to get commandline info is %llu ms\n", t); 
    
    gettimeofday(&tm1, NULL);
    result = syscall_hooking_info();
    if( result) {
	fprintf(stdout,"ERROR: syscall_hooking_info failed.\n");
	goto resume;
    }
    gettimeofday(&tm2, NULL);
    t = (1000 * (tm2.tv_sec - tm1.tv_sec)) + ((tm2.tv_usec - tm1.tv_usec)/1000);
    //fprintf(stdout,"INFO: Time taken to check for hooked system calls is %llu ms\n", t); 
    

resume:
    gettimeofday(&tm1, NULL);
    if ((status = target_status(target)) == TSTATUS_PAUSED) {
	//fprintf(stdout,"INFO: Resuming the target\n");
	if (target_resume(target)) {
	    fprintf(stdout, "ERROR: Failed to resume target.\n ");
	    result = 1;
	}
    }
    gettimeofday(&tm2, NULL);
    t = (1000 * (tm2.tv_sec - tm1.tv_sec)) + ((tm2.tv_usec - tm1.tv_usec)/1000);
    //fprintf(stdout,"INFO: Time taken to resume the target is %llu ms\n", t); 

    return result;
}



struct psa_argp_state {
    int argc;
    char **argv;
    /* Grab this from the child parser. */
    struct target_spec *tspec;
};

struct psa_argp_state opts;

struct argp_option psa_argp_opts[] = {
        { 0,0,0,0,0,0 },
};



error_t psa_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct psa_argp_state *opts = \
	(struct psa_argp_state *)target_argp_driver_state(state);
	    
    switch (key) {
    case ARGP_KEY_ARG:
	return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_ARGS:
	/* Eat all the remaining args. */
	if (state->quoted > 0)
	    opts->argc = state->quoted - state->next;
	else
	    opts->argc = state->argc - state->next;
	if (opts->argc > 0) {
	    opts->argv = calloc(opts->argc,sizeof(char *));
	    memcpy(opts->argv,&state->argv[state->next],opts->argc*sizeof(char *));
	    state->next += opts->argc;
	}
	return 0;
    case ARGP_KEY_INIT:
	target_driver_argp_init_children(state);
	return 0;
    case ARGP_KEY_END:
    case ARGP_KEY_NO_ARGS:
    case ARGP_KEY_SUCCESS:
	opts->tspec = target_argp_target_spec(state);
	return 0;
    case ARGP_KEY_ERROR:
    case ARGP_KEY_FINI:
	return 0;

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp psa_argp = {
        psa_argp_opts,psa_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};


int main( int argc, char** argv) {

    int wait_time = 0;
    char *app_file_path = NULL;
    char * recovery_rules_file = NULL;
    char recovery_fact_file[100];
    int result = 0;
    char targetstr[80];
    struct target_spec *tspec = NULL;
    target_status_t tstat;
    int iteration = 1;
    FILE *fp;
    struct stat st = {0};


    memset(&opts,0,sizeof(opts));
    tspec = target_argp_driver_parse(NULL,NULL,argc,argv,TARGET_TYPE_XEN,1);
    if (!tspec) {
	fprintf(stdout,"ERROR: Could not parse target arguments!\n");
	exit(-1);
    }
	        
    /*if (opts.argc != 2) {
	fprintf(stderr,"ERROR: Must supply the 2 arguments.\n 1. Application knowlege file\n 2. Wait time.\n");
	exit(0);
    }
   */
    app_file_path = "application_knowledge.cls"; //opts.argv[0];
    recovery_rules_file = "recovery_contructs.cls";
    wait_time = 5; //atoi(opts.argv[1]);
    
    dwdebug_init();
    target_init();
    atexit(target_fini);
    atexit(dwdebug_fini);


     target = target_instantiate(tspec,NULL);
     if (!target) {
	fprintf(stdout,"ERROR: Could not instantiate target!\n");
	exit(0);
     }
     //target_snprintf(target,targetstr,sizeof(targetstr));
    if (target_open(target)) {
	fprintf(stdout,"ERROR: Could not open %s!\n",targetstr);
	exit(0);
    }


    fprintf(stdout,"INFO: Initializing the CLIPS environment.\n");
    // Initialize the CLIPS environment
    InitializeEnvironment();

    // Create a directory  with files to keep track of state information.
    if(stat("state_information", &st) == 1) {
	mkdir("state_information",0700);
    }
    
    fp = fopen("state_information/cpu_state_info.fac", "w");
    fp = fopen("state_information/module_state_info.fac", "w");
    fp = fopen("state_information/process_priv_state_info.fac", "w");
    fp = fopen("state_information/process_state_info.fac", "w");
    fp = fopen("state_information/tcp_state_info.fac", "w");
    fp = fopen("state_information/udp_state_info.fac", "w");
    fp = fopen("state_information/recovery_action.fac", "w");





    
    /* Copy the initil system_call_table contents */
      result = save_sys_call_table_entries();
    if(result) {
	fprintf(stdout,"ERROR: Failed to save the initial system call table entries.\n");
	exit(0);
    }
	
    // Start an infinite loop to periodically execute steps 3.1 to 3.5 
    while(1) {

	fprintf(stdout,"============================ITERATION %d ============================\n",iteration++);
        fprintf(stdout,"INFO: Loading the application level rules\n");
	result = Load(app_file_path);
	    if(result != 1) {
	    fprintf(stdout,"ERROR: Failed to load the application rules file\n");
	    exit(0);
	}	
 

	// Generate a time stamp for the base facts file name
	result = generate_timestamp(base_fact_file);
	if(!result) {
	    fprintf(stdout,"Failed to generate timestamp");
	    exit(0);
	}
	fprintf(stdout," INFO: Base fact file name  = %s\n",base_fact_file);

	// Make call to the base VMI  base function. This function invokes all the 
	// VMI tools that gather state information of the virtual appliance/
	

	static struct timeval tm1;
	gettimeofday(&tm1, NULL);

	result = generate_snapshot();

	static struct timeval tm2;
	gettimeofday(&tm2, NULL);
	if( result) {
	    fprintf(stdout,"ERROR: Failed to generate the system snapshot.\n \
		    Trying again...\n");
	    continue;
	}
	unsigned long long t = (1000 * (tm2.tv_sec - tm1.tv_sec)) + ((tm2.tv_usec - tm1.tv_usec)/1000);
	fprintf(stdout,"INFO: Time taken to generate the snapshot is %llu ms\n", t); 


	fprintf(stdout,"INFO: Resetting the CLIPS environemnt\n");
	Reset();

	/*
	result = Watch("all");
	if(!result) {
	    fprintf(stdout,"Error: Faild to watch \n");
	}
	*/
	fprintf(stdout,"INFO: Loading the base facts file\n");
	result = LoadFacts(base_fact_file);
	if(!result) {
	   fprintf(stdout,"ERROR: Failed to load the base facts file.\n");
	   exit(0);
	}
	// Load previous cpu utilization state
	result = LoadFacts("state_information/cpu_state_info.fac");
	if(!result) {
	   fprintf(stdout,"ERROR: Failed to load the tcp_state_info file.\n");
	   exit(0);
	}

	fprintf(stdout,"INFO: Parsing the base facts through the application rules\n");
	result = Run(-1L);
	fprintf(stdout,"INFO : %d application rules were fired\n",result);
	// At this time the anomaly facts are generated.
	
	fprintf(stdout,"INFO: Loading the state information of recovery facts from the previous execution \n");
	result = LoadFacts("state_information/process_state_info.fac");
	if(!result) {
	   fprintf(stdout,"ERROR: Failed to load the process_state_info file.\n");
	   exit(0);
	}
	
	result = LoadFacts("state_information/module_state_info.fac");
	if(!result) {
	   fprintf(stdout,"ERROR: Failed to load the module_state_info file.\n");
	   exit(0);
	}

	result = LoadFacts("state_information/udp_state_info.fac");
	if(!result) {
	   fprintf(stdout,"ERROR: Failed to load the base udp_state_info file.\n");
	   exit(0);
	}
	
	result = LoadFacts("state_information/tcp_state_info.fac");
	if(!result) {
	   fprintf(stdout,"ERROR: Failed to load the tcp_state_info file.\n");
	   exit(0);
	}
	result = LoadFacts("state_information/process_priv_state_info.fac");
	if(!result) {
	   fprintf(stdout,"ERROR: Failed to load the process_priv_info file.\n");
	   exit(0);
	}
    

	// We have to run them through the recovery rules now.
	fprintf(stdout,"INFO: Loading the  recovery rules file\n");
	result = Load(recovery_rules_file);
	if(!result) {
	   fprintf(stdout,"ERROR: Failed to load the base facts file.\n");
	   exit(0);
	}

	result = Run(-1L);
	fprintf(stdout,"INFO : %d recovery rules were fired\n",result);

	fprintf(stdout,"INFO: Parsing the recovery action file.\n");

	result = parse_recovery_action();
	if(result) {
	    fprintf(stdout,"ERROR: parse_recovery_action function call failed.\n");
	    exit(0);
	}
	
	Clear();
	fprintf(stdout,"INFO: Clearing up all the facts and rules\n");
	fprintf(stdout," Sleeping for %d seconds\n", wait_time);
	sleep(wait_time);
    }

exit:
    fflush(stderr);
    fflush(stdout);
    tstat = cleanup();
    if(tstat == TSTATUS_DONE) {
	printf(" Monitoring finished.\n");
	return 0;
    }
    else if (tstat == TSTATUS_ERROR) {
	printf("Monitoring failed!\n");
	return 1;
    }
    else {
	printf("Monitoring failed with %d!\n",tstat);
	return 1;
    }

}



