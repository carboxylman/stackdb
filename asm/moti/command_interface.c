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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
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

volatile int probe_active = 0;
/* struct to store the parsed command */
struct TOKEN {
	char cmd[128];
	int argc;
	char argv[128][128];
};

/* command structure similar to the one used in the repair drivers */
struct cmd_rec {
	unsigned int cmd_id;       /* unique identifier for each command */
	unsigned int submodule_id; /* submodule in which the command is implemented*/
	int argc;                  /* command argument count */
	int argv[128];             /* array to store the arguments*/
};

/* acknowledgment struct similar to the one s used in the repair driver */
struct ack_rec {
	unsigned int submodule_id; /* submodule in which the command is implemented*/
	unsigned int cmd_id;       /* unique identifier for each command */
	int exec_status;           /* 1 = success , 0 = error */
	int argc;                  /* result argument count */
	int argv[128];             /* array to store result data*/
};

struct target *t = NULL;
struct probe *p;

struct psa_argp_state {
	int argc;
	char ** argv;
	struct target_spec *tspec;
};
struct psa_argp_state opts;
struct argp_option psa_argp_opts[] = { { 0, 0, 0, 0, 0, 0 }, };

/* get the producer address in the request ring channel */

ADDR get_prod_or_cons_addr(const char *symbol_name, const char *index_name) {

	struct bsymbol *bs;
	struct value *v, *value;
	unsigned int index;
	unsigned int size_in_recs;
	unsigned int size_of_a_rec;
	//void *rec_base_ptr, *addr;
	ADDR rec_base_ptr, addr;

    /*first get the value stored in req_ring_channel.recs in the module.*/
	bs = target_lookup_sym(t, symbol_name, NULL, "repair_driver",
			SYMBOL_TYPE_FLAG_VAR);
	if (!bs) {
		fprintf(stderr, "Error: Could not lookup symbol req_ring_channel.\n");
		return 0;
	}

	value = target_load_symbol(t, TID_GLOBAL, bs, LOAD_FLAG_NONE);
	if (!value) {
		fprintf(stderr, "ERROR: could not load value of symbol req_ring_channel\n");
		goto fail;
	}

	/* read the base address of the record */
	v = target_load_value_member(t, value, "recs", NULL, LOAD_FLAG_NONE);
	if(!v){
		fprintf(stderr,"Failed to load the value of member recs\n");
		goto fail;
	}
	rec_base_ptr = v_addr(v);
	value_free(v);

	/* read the producer index value */
	v = target_load_value_member(t, value, index_name, NULL, LOAD_FLAG_NONE);
	if(!v){
		fprintf(stderr,"Failed to load the value of member index \n");
		goto fail;
	}
	index = v_u32(v);
	value_free(v);

	/* read the size of the ring buffer in terms of record */
	v = target_load_value_member(t, value, "size_in_recs", NULL,LOAD_FLAG_NONE);
	if(!v){
			fprintf(stderr,"Failed to load the value of member size_in_recs\n");
			goto fail;
	}
	size_in_recs = v_u32(v);
	value_free(v);

	/* read the size of each record */
	v = target_load_value_member(t, value, "size_of_a_rec", NULL,
			LOAD_FLAG_NONE);
	if(!v){
			fprintf(stderr,"Failed to load the value of member size_of_recs\n");
			goto fail;
	}
	size_of_a_rec = v_u32(v);
	value_free(v);

	value_free(value);

	/* now do the pointer math to compute the address where the next command must be inserted */
	addr = rec_base_ptr + (index % size_in_recs) * size_of_a_rec;
	return addr;

	fail: if(bs) {
		bsymbol_release(bs);
	}
	if(v) {
		value_free(v);
	}
	return 0;

}

int load_command_func(struct TOKEN *token,int cmd_id, int submodule_id) {

	ADDR cmd_ptr;
	struct bsymbol *ack_struct_type=NULL, *bs=NULL;
	struct symbol *command_struct_type=NULL;
	struct value *v=NULL, *value=NULL;
	int result;
	int argv[128],i;
	target_status_t status;

	/* need to pause the target */

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
    	fprintf(stdout,"Pausing the target\n");
    	if (target_pause(t)) {
    		fprintf(stderr,"Failed to pause the target \n");
    		goto failure;
    	}
    }



	/*get the address within the req_ring_channel page where the
	 * command needs to be inserted.
	 */
	//cmd_ptr = ((ADDR *) get_prod_or_cons_addr("req_ring_channel","prod"));
    cmd_ptr = get_prod_or_cons_addr("req_ring_channel","prod");
	if (!cmd_ptr) {
		fprintf(stderr, "ERROR : get_prod_or_cons_addr failed \n");
		goto failure;
	}
	/* get the type for the command structure  and load it*/
	command_struct_type = bsymbol_get_symbol(target_lookup_sym(t, "struct cmd_rec", NULL,
			"repair_driver", SYMBOL_TYPE_FLAG_TYPE));
	if(!command_struct_type){
		fprintf(stderr,"target_lookup_symbol failed for struct cmd_rec. \n");
		goto failure;
	}
	value = target_load_type(t, command_struct_type, cmd_ptr, LOAD_FLAG_NONE);
	if(!value){
		fprintf(stderr,"Failed to load type of struct cmd_rec. \n");
		goto failure;
	}

	/* set the submodule id */

	v = target_load_value_member(t, value, "submodule_id", NULL,
			LOAD_FLAG_NONE);
	if(!v){
		fprintf(stderr,"Failed to load the value of memeber submodule_id \n");
		goto failure;
	}
	result = value_update_u32(v, submodule_id);
	if (result == -1) {
		fprintf(stderr, "Error: failed to load value of submodule_id\n");
		goto failure;;
	}
	result = target_store_value(t, v);
	if (result == -1) {
		fprintf(stderr, "Error: failed to write submodule_id\n");
		goto failure;
	}
	value_free(v);

	/* set the command id */
	v = target_load_value_member(t, value, "cmd_id", NULL, LOAD_FLAG_NONE);
	if(!v){
		fprintf(stderr,"Failed to load the value of memeber cmd_id \n");
		goto failure;
	}
	result = value_update_u32(v, cmd_id);
	if (result == -1) {
		fprintf(stderr, "Error: failed to update value of cmd_id\n");
		goto failure;
	}
	result = target_store_value(t, v);
	if (result == -1) {
		fprintf(stderr, "Error: failed to write cmd_id\n");
		goto failure;
	}
	value_free(v);

	/*set the argument count */
	v = target_load_value_member(t, value, "argc", NULL, LOAD_FLAG_NONE);
	if(!v){
		fprintf(stderr,"Failed to load the value of memeber argc \n");
		goto failure;
	}
	result = value_update_u32(v, token->argc);
	if (result == -1) {
		fprintf(stderr, "Error: failed to update value of argc\n");
		goto failure;
	}
	result = target_store_value(t, v);
	if (result == -1) {
		fprintf(stderr, "Error: failed to write argc\n");
		goto failure;
	}
	value_free(v);

	/* set the entire argv array*/
	for(i=0; i<128; i++) {
		argv[i] = atoi(token->argv[i]);
	}
	v = target_load_value_member(t, value, "argv", NULL,
			LOAD_FLAG_NONE);
	if(!v){
		fprintf(stderr,"Failed to load the value of memeber argv \n");
		goto failure;
	}
	memcpy(v->buf,argv,128*sizeof(int));
	result = target_store_value(t, v);
	if (result == -1) {
		fprintf(stderr, "Error: failed to write argv\n");
		goto failure;
	}
	value_free(v);
	symbol_release(command_struct_type);

	/* now that we have written all the command paramaters, increment prod index */
	bs = target_lookup_sym(t, "req_ring_channel", NULL, "repair_driver",
			SYMBOL_TYPE_FLAG_VAR);
	if (!bs) {
		fprintf(stderr, "Error: could not lookup symbol req_ring_channel.\n");
		goto failure;
	}

	value = target_load_symbol(t, TID_GLOBAL, bs, LOAD_FLAG_NONE);
	if (!value) {
		fprintf(stderr,
				"ERROR: could not load value of symbol req_ring_channel\n");
		goto failure;
	}

	v = target_load_value_member(t, value, "prod", NULL, LOAD_FLAG_NONE);
	if(!v){
		fprintf(stderr,"Failed to load the value of memeber prod \n");
		goto failure;
	}
	result = value_update_u32(v, v_u32(v) + 1);
	if (result == -1) {
		fprintf(stderr, "Error: failed to update prod index\n");
		goto failure;
	}

	result = target_store_value(t, v);
	if (result == -1) {
		fprintf(stderr, "Error: failed to set the prod index\n");
		goto failure;
	}
	value_free(v);
	bsymbol_release(bs);

	/*unpause the target */
    if ((status = target_status(t)) == TSTATUS_PAUSED) {
    	fprintf(stderr,"Unpausing the target,\n");
    	if (target_resume(t)) {
    		fprintf(stderr, "Failed to resume target.\n ");
    		return 0;
    	}
    }


	/* at this stage we have successfully passed the command to the driver module.
	 * Once the appropriate submodule is executed the result gets written to the
	 * res_ring_channel which is indexed by cons. We need to read out the contents of
	 * ack_rec and update the cons index to complete the request response cycle.
	 */
	return 1;

	failure: if (v) {
		value_free(v);
	}
	if (bs) {
		bsymbol_release(bs);
	}
	if (command_struct_type) {
		symbol_release(command_struct_type);
	}
	if (ack_struct_type) {
		bsymbol_release(ack_struct_type);
	}

    if ((status = target_status(t)) == TSTATUS_PAUSED) {
    	fprintf(stdout,"Un-Pausing the target\n");
    	if (target_resume(t)) {
    		fprintf(stderr, "Failed to resume target.\n ");
    	}
    }

	return 0;

}



result_t _target_probe_posthandler(struct probe *probe, void *handler_data, struct probe *trigger) {

	probe_active = 0;
	fprintf(stdout,"In probe posthandler\n");
    return RESULT_SUCCESS;
}




result_t _target_probe_prehandler(struct probe *probe, void *handler_data , struct probe *trigger) {

	struct ack_rec result;
	ADDR ack_ptr;
	struct bsymbol  *bs=NULL;
	struct symbol *ack_struct_type = NULL;
	struct value *v=NULL , *value=NULL;
	result_t retval = RESULT_SUCCESS;
	int res;

	probe_active = 1;
	fprintf(stdout,"In probe prehandler\n");
	/*get the address within the res_ring_channel page from where the result needs to be read */
	ack_ptr = get_prod_or_cons_addr("res_ring_channel","cons");
	if (!ack_ptr) {
		fprintf(stderr, "get_prod_or_cons_addr failed \n");
		retval = RESULT_ERROR;
		goto failure1;
	}

	/* get the type for the acknowledgment structure  and load it*/
	ack_struct_type = bsymbol_get_symbol( target_lookup_sym(t, "struct ack_rec", NULL,
			"repair_driver", SYMBOL_TYPE_FLAG_VAR));
	value = target_load_type(t, ack_struct_type, ack_ptr, LOAD_FLAG_NONE);
	if(!value){
			fprintf(stderr,"Failed to load type of struct ack_rec\n");
			retval = RESULT_ERROR;
			goto failure1;
	}

	/* get the submodule id */
	v = target_load_value_member(t, value, "submodule_id", NULL,
			LOAD_FLAG_NONE);
	if(!v){
			fprintf(stderr,"Failed to load the value of memeber submodule_id\n");
			retval = RESULT_ERROR;
			goto failure1;
	}
	result.submodule_id = v_u32(v);
	value_free(v);

	/* get the command id */
	v = target_load_value_member(t, value, "cmd_id", NULL, LOAD_FLAG_NONE);
	if(!v){
			fprintf(stderr,"Failed to load the value of memeber cmd_id\n");
			retval = RESULT_ERROR;
			goto failure1;
	}
	result.cmd_id = v_u32(v);
	value_free(v);

	/* get the command execution status */
	v = target_load_value_member(t, value, "exec_status", NULL,
			LOAD_FLAG_NONE);
	if(!v){
			fprintf(stderr,"Failed to load the value of memeber exec_status\n");
			retval = RESULT_ERROR;
			goto failure1;
	}
	result.exec_status = v_u32(v);
	value_free(v);

	/* get the argc */
	v = target_load_value_member(t, value, "argc", NULL,
			LOAD_FLAG_NONE);
	if(!v){
			fprintf(stderr,"Failed to load the value of memeber argc\n");
			retval = RESULT_ERROR;
			goto failure1;
	}
	result.argc = v_u32(v);
	value_free(v);

	/* Readout the values stored in argv */
	v = target_load_value_member(t, value, "argv", NULL,
			LOAD_FLAG_NONE);
	if(!v){
			fprintf(stderr,"Failed to load the value of memeber argv\n");
			retval = RESULT_ERROR;
			goto failure1;
	}

	memcpy(result.argv,v->buf,128*sizeof(int));
	value_free(v);

	symbol_release(ack_struct_type);

	/* Now display the result of command execution */
	switch(result.submodule_id) {
		case 0:  /*psaction_module*/
			switch(result.cmd_id) {
					case 0: /*__ps_kill function */
						if(result.exec_status) {
							fprintf(stdout, "SUCCESS: Process with PID %d successfully killed\n",result.argv[0]);
						}
						else{
							fprintf(stdout,"FAILURE: Failed to kill process with PID %d \n.",result.argv[0]);
						}
						break;
					default:
						fprintf(stderr,"Invalid value for cmd_id in result.\n");
						break;
			}
			break;
		default:
			fprintf(stderr,"Invalid value for submodule_id in the result.\n");
			break;
	}

	/* now increment the cons index in the res_ring_channel */
	bs = target_lookup_sym(t, "res_ring_channel", NULL, "repair_driver",
			SYMBOL_TYPE_FLAG_VAR);
	if (!bs) {
		fprintf(stderr, "Error: could not lookup symbol res_ring_channel.\n");
		retval = RESULT_ERROR;
		goto failure1;
	}

	value = target_load_symbol(t, TID_GLOBAL, bs, LOAD_FLAG_NONE);
	if (!value) {
		fprintf(stderr,
				"ERROR: could not load value of symbol req_ring_channel\n");
		retval = RESULT_ERROR;
		goto failure1;
	}

	v = target_load_value_member(t, value, "cons", NULL, LOAD_FLAG_NONE);
	if(!v){
			fprintf(stderr,"Failed to load the value of memeber cons\n");
			retval = RESULT_ERROR;
			goto failure1;
	}
	res = value_update_u32(v, v_u32(v) + 1);
	if (res == -1) {
		fprintf(stderr, "Error: failed to update cons index\n");
		retval = RESULT_ERROR;
		goto failure1;
	}
	res = target_store_value(t, v);
	if (res == -1) {
		fprintf(stderr, "Error: failed to set the cons index\n");
		retval = RESULT_ERROR;
		goto failure1;
	}
	value_free(v);
	bsymbol_release(bs);
	return retval;

	failure1:
	if(v){
		value_free(v);
	}
	if(bs){
		bsymbol_release(bs);
	}
	if(ack_struct_type){
		symbol_release(ack_struct_type);
	}
	return retval;


}


int enable_probe() {

    target_status_t status;

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
    	if (target_pause(t)) {
    		fprintf(stderr,"Failed to pause the target \n");
    		return 0;
    	}
    }

   // p = probe_simple(t,TID_GLOBAL,"load_submodules",_target_probe_prehandler, _target_probe_posthandler,NULL);
//    p = probe_create(t,TID_GLOBAL,NULL,"breakpoint_func",_target_probe_prehandler,
//    		_target_probe_posthandler,NULL,0,1);
//    if (!p)
//    	return NULL;
//
//    p = probe_register_symbol_name(p,"load_submodules",DWDEBUG_DEF_DELIM,
//				      PROBEPOINT_SW,PROBEPOINT_WAUTO,
//			      PROBEPOINT_LAUTO);
//
//    if(!p) {
//    	fprintf(stderr,"Failed to setup the probe on breakpoint_func\n");
//    	return 0;
//    }
//    else {
//    	fprintf(stdout,"Breakpoint set succesfully\n");
//    }


    if ((status = target_status(t)) == TSTATUS_PAUSED) {
    	if (target_resume(t)) {
    		fprintf(stderr, "Failed to resume target.\n ");
    		return 0;
    	}
    }

    return 1;

}

error_t psa_argp_parse_opt(int key, char *arg, struct argp_state *state) {
	struct psa_argp_state *opts =
			(struct psa_argp_state *) target_argp_driver_state(state);

	switch (key) {
	case ARGP_KEY_ARG:
		return ARGP_ERR_UNKNOWN;
	case ARGP_KEY_ARGS:
		if (state->quoted > 0)
			opts->argc = state->quoted - state->next;
		else
			opts->argc = state->argc - state->next;
		if (opts->argc > 0) {
			opts->argv = calloc(opts->argc, sizeof(char *));
			memcpy(opts->argv, &state->argv[state->next],
					opts->argc * sizeof(char *));
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

struct argp psa_argp = { psa_argp_opts, psa_argp_parse_opt, NULL, NULL, NULL,
		NULL, NULL, };

int main(int argc, char **argv) {

	int i;
	int result;
	char *command, *cur_token;
	char delim = ' ';
	struct target_spec *tspec;
	target_status_t tstat;
	struct TOKEN token;
	target_status_t status;
	int cmd_id, submodule_id;

	memset(&opts, 0, sizeof(opts));

	/* parse the command line arguments and get the
	 * tspec struct variable.
	 */
	tspec = target_argp_driver_parse(&psa_argp, &opts, argc, argv,
			TARGET_TYPE_XEN, 1);

	if (!tspec) {
		verror("Could not parse target arguments!\n");
		exit(-1);
	}

	dwdebug_init();
	target_init();
	atexit(target_fini);
	atexit(dwdebug_fini);

	/* now initialize the target */
	t = target_instantiate(tspec,NULL);
	if (!t) {
		verror("Count not instantiate target\n");
		exit(-1);
	}

	/* Open connection to the target.*/
	if (target_open(t)) {
		fprintf(stderr, "Could not open the target\n");
		exit(-1);
	}


	/*set up a probe on the breakpoint_func() in repair_driver */
	result = enable_probe();
	if(!result){
		fprintf(stderr,"Cound not set probe on reakpoint_func\n");
		goto exit;
	}


	/* Allocate memory for the command */
	command = (char*) malloc(128 * sizeof(char));
	if (!command) {
		fprintf(stdout, "Failed to allocate memory for the command\n");
		goto exit;
	}
	/* now  start a infinite while loop that waits for user to input commands */
	while (1) {

		/*check if the probe is active, in that case we don't want to accepts user inputs */
		if(probe_active) {
			continue;

		}

		fprintf(stdout, "\n- ");
		fflush(stdin);
		gets(command);
		if(!(strcmp(command, ""))) continue;

		/* Tokenize command */
		i = 0;
		token.argc = 0;
		cur_token = strtok(command, &delim);
		strcpy(token.cmd, cur_token); /* token.cmd has command name */
		do {
			cur_token = strtok(NULL, &delim);
			if (cur_token == NULL)
				break;
			token.argc++;
			strcpy(token.argv[i], cur_token);
			i++;
		} while (cur_token != NULL);

		/* Now based on the command make appropriate function call */
		if(!(strcmp(token.cmd, "exit"))) {
			goto exit;
		}
		else if(!(strcmp(token.cmd, "pskill")))
		{
			cmd_id = 0;
			submodule_id = 0;
			result = load_command_func(&token,cmd_id,submodule_id);
			if (!result) {
				fprintf(stderr, "ERROR : load_command_func function call failed \n");
			}
		}
		else if(!(strcmp(token.cmd,"pssetuid"))){
			cmd_id = 0;
			submodule_id = 1;
			result = load_command_func(&token,cmd_id,submodule_id);
			if (!result) {
				fprintf(stderr, "ERROR : load_command_func function call failed \n");
			}
		}
		/* else if ()
		 *
		 * else if()
		 *
		 *  . . . and so on for each feature implementation
		 */

	}

	/* Clean exit code */
	exit: fflush(stderr);
	fflush(stdout);

	/* Free the probe that was created */
	if(p){

		if ((status = target_status(t)) != TSTATUS_PAUSED) {
			if (target_pause(t)) {
				fprintf(stderr,"Failed to pause the target.\n");
				return 0;
			}
		}

		if (probe_free(p,1)) {
			fprintf(stderr,"Failed to free the probe\n");
			return 0;
		}
		fprintf(stdout," Successfully freed the probe\n");
	}


	if ((status = target_status(t)) == TSTATUS_PAUSED) {
		if (target_resume(t)) {
			fprintf(stderr, "Failed to resume target.\n ");
			return 0;
		}
	}

	tstat = target_close(t);
	target_free(t);
	if (tstat == TSTATUS_DONE) {
		printf("Finished.\n");
		exit(0);
	} else if (tstat == TSTATUS_ERROR) {
		printf("Monitoring failed!\n");
		exit(-1);
	} else {
		printf("Monitoring failed with %d!\n", tstat);
		exit(-1);
	}
}
