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
#include "clips.h"

struct target *target = NULL;
char base_fact_file[100];

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
    result = strftime(date,100, "%Y_%m_%d_%H_%M_%S.fac", tm);

    return result;
}

int generate_snapshot() {

    int result = 0;
    target_status_t status;

    /* Pause the target */
    if ((status = target_status(target)) != TSTATUS_PAUSED) {
	fprintf(stdout,"INFO: Pausing the target\n");
	if (target_pause(target)) {
		fprintf(stderr,"Failed to pause the target \n");
		result = 1;
		goto resume;
	 }
    }

			    
    // start making calls to each of the VMI function 
    result = process_info();
    if(result) {
	fprintf(stdout,"ERROR: process_info function failed\n");
	result = 1;
	goto resume;
    }
    
    
    
    result =  file_info();
    if(result) {
	fprintf(stdout,"ERROR: file_info function failed.\n");
	result = 1;
	goto resume;
    } 
    
   
    result = module_info();
    if(result) {
	fprintf(stdout,"ERRROR: module_info function failed.\n");
	result = 1;
	goto resume;
    }

resume:

    if ((status = target_status(target)) == TSTATUS_PAUSED) {
	fprintf(stdout,"INFO: Resuming the target\n");
	if (target_resume(target)) {
	    fprintf(stdout, "ERROR: Failed to resume target.\n ");
	    result = 1;
	}
    }
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
    char recovery_fact_file[100];
    int result = 0;
    char targetstr[80];
    struct target_spec *tspec = NULL;
    target_status_t tstat;


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
    app_file_path = "test.cls"; //opts.argv[0];
    wait_time = 300; //atoi(opts.argv[1]);
    
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


    // Initialize the CLIPS environment
    InitializeEnvironment();
    fprintf(stdout,"INFO: Loading the application level rules\n");
    result = Load(app_file_path);
    if(result != 1) {
	fprintf(stdout,"ERROR: Failed to load the application rules file\n");
	exit(0);
    }
    fprintf(stdout,"INFO: Loading the recovery rules.\n");
      //result = Load("recovery_rules.clp");
      //if(result != 1) {
	//fprintf(stdout," ERROR: Failed to load the recovery rules file\n");
	//exit(0);
      //}
     

    // Start an infinite loop to periodically execute steps 3.1 to 3.5 
    while(1) {

	// Generate a time stamp for the base facts file name
	result = generate_timestamp(base_fact_file);
	if(!result) {
	    fprintf(stdout,"Failed to generate timestamp");
	    exit(0);
	}
	fprintf(stdout," INFO: Base fact file name  = %s\n",base_fact_file);

	// Make call to the base VMI  base function. This function invokes all the 
	// VMI tools that gather state information of the virtual appliance/

	result = generate_snapshot();
	if( result) {
	    fprintf(stdout,"ERROR: Failed to generate the system snapshot.\n \
		    Trying again...\n");
	    continue;
	}
	
	fprintf(stdout,"INFO: Loading the base facts file\n");
	result = LoadFacts(base_fact_file);
	if(!result) {
	   fprintf(stdout,"ERROR: Failed to load the base facts file.\n");
	   exit(0);
	}
	fprintf(stdout,"INFO: Resetting the CLIPS environemnt\n");
	Reset();
	fprintf(stdout,"INFO: Parsing the base facts through the application rules\n");
	result = Run(-1L);
	fprintf(stdout,"INFO : %d application rules were fired\n",result);
	// At this time the anomaly facts are generated.
	// We have to run them through the recovery rules now.

	result = Run(-1L);
	fprintf(stdout,"INFO : %d recovery rules were fired\n",result);

	//result = generate_timestamp(recovery_fact_file);
	//if(!result){
	    //fprintf(stdout,"ERROR: Failed to generate a timestamp\n");
	    //exit(0);
	//}
	//result = SaveFacts(recovery_fact_file,  VISIBLE_SAVE, NULL);
	//if(!result) {
	//fprintf(stdout,"ERROR: Failed to save the recovery facts\n");
	//exit(0);
	//}
	// Now based on the recovery facts that are generated we trigger recovery actions.
	// how do we do this ?
	 
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



