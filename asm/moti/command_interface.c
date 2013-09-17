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

#include "command_interface.h"
#include "ci_helper.h"

struct psa_argp_state {
    int argc;
    char ** argv;
    struct target_spec *tspec;
};

struct target *t = NULL;
struct probe *p;
struct psa_argp_state opts;
struct argp_option psa_argp_opts[] = { { 0, 0, 0, 0, 0, 0 }, };

/* get the producer address in the request ring channel */

ADDR get_prod_or_cons_addr(const char *symbol_name, const char *index_name) {

    struct bsymbol *bs = NULL;
    struct value *v = NULL, *value = NULL;
    unsigned int index;
    unsigned int size_in_recs;
    unsigned int size_of_a_rec;
    //void *rec_base_ptr, *addr;
    ADDR rec_base_ptr, addr;
    ci_error_t ret = CI_SUCCESS ;

    /*first get the value stored in req_ring_channel.recs in the module.*/
    bs = target_lookup_sym(t, symbol_name, NULL, "repair_driver",
	    SYMBOL_TYPE_FLAG_VAR);
    if (!bs) {
	fprintf(stderr, "Error: Could not lookup symbol req_ring_channel.\n");
	ret = CI_LOOKUP_ERR;
	goto fail;
    }

    value = target_load_symbol(t, TID_GLOBAL, bs, LOAD_FLAG_NONE);
    if (!value) {
	fprintf(stderr, "ERROR: could not load value of symbol req_ring_channel\n");
	ret = CI_LOAD_ERR;
	goto fail;
    }

    /* read the base address of the record */
    v = target_load_value_member(t, value, "recs", NULL, LOAD_FLAG_NONE);
    if(!v){
	fprintf(stderr,"Failed to load the value of member recs\n");
	ret = CI_LOAD_ERR;
	goto fail;
    }
    rec_base_ptr = v_addr(v);
    value_free(v);

    /* read the producer index value */
    v = target_load_value_member(t, value, index_name, NULL, LOAD_FLAG_NONE);
    if(!v){
	fprintf(stderr,"Failed to load the value of member index \n");
	ret = CI_LOAD_ERR;
	goto fail;
    }
    index = v_u32(v);
    value_free(v);

    /* read the size of the ring buffer in terms of record */
    v = target_load_value_member(t, value, "size_in_recs", NULL,LOAD_FLAG_NONE);
    if(!v){
	fprintf(stderr,"Failed to load the value of member size_in_recs\n");
	ret = CI_LOAD_ERR;
	goto fail;
    }
    size_in_recs = v_u32(v);
    value_free(v);

    /* read the size of each record */
    v = target_load_value_member(t, value, "size_of_a_rec", NULL,
	    LOAD_FLAG_NONE);
    if(!v){
	fprintf(stderr,"Failed to load the value of member size_of_recs\n");
	ret = CI_LOAD_ERR;
	goto fail;
    }
    size_of_a_rec = v_u32(v);
    value_free(v);

    value_free(value);

    /* 
     * Now do the pointer math to compute the address
     * where the next command must be inserted 
     */
    addr = (rec_base_ptr + (index % size_in_recs) * size_of_a_rec);
    return addr;
fail:
    if(bs) {
	bsymbol_release(bs);
    }
    if(v) {
	value_free(v);
    }
    return 0;

}

int load_command_func(struct TOKEN *token,int cmd_id, int submodule_id, int argv[128]) {

    ADDR cmd_ptr;
    struct bsymbol *ack_struct_type=NULL, *bs=NULL;
    struct symbol *command_struct_type=NULL;
    struct value *v=NULL, *value=NULL;
    int res;
    target_status_t status;
    ci_error_t ret = CI_SUCCESS;

    /* Pause the target */
    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	fprintf(stdout,"INFO: Pausing the target\n");
	if (target_pause(t)) {
	    fprintf(stderr,"Failed to pause the target \n");
	    ret = CI_TPAUSE_ERR;
	    goto failure;
	}
    }

    /* 
     * Get the address within the req_ring_channel page where the
     * command needs to be inserted.
     */
    cmd_ptr = get_prod_or_cons_addr("req_ring_channel","prod");
    if (!cmd_ptr) {
	fprintf(stdout, "ERROR : get_prod_or_cons_addr failed \n");
	ret = res;
	goto failure;
    }
    /* Get the type for the command structure  and load it*/
   /* bs = target_lookup_sym(t,"struct cmd_rec", NULL,
	    "repair_driver", SYMBOL_TYPE_FLAG_TYPE);
    if(!bs) {
	fprintf(stdout,"ERROR: Failed to lookup symbol cmd_rec.\n");
	ret = CI_LOOKUP_ERR;
	goto failure;
    }
    */
    command_struct_type =bsymbol_get_symbol(target_lookup_sym(t,"struct cmd_rec", NULL,
	    "repair_driver", SYMBOL_TYPE_FLAG_TYPE));
    if(!command_struct_type){
	fprintf(stdout,"ERROR:Target_lookup_symbol failed for struct cmd_rec.\n");
	ret = CI_LOOKUP_ERR;
	goto failure;
    }
    value = target_load_type(t, command_struct_type, cmd_ptr, LOAD_FLAG_NONE);
    if(!value){
	fprintf(stdout,"ERROR: Failed to load type of struct cmd_rec. \n");
	ret = CI_LOAD_ERR;
	goto failure;
    }

    /* Set the submodule id */
    v = target_load_value_member(t, value, "submodule_id", NULL,
	    LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"Failed to load the value of member submodule_id \n");
	ret = CI_LOAD_ERR;
	goto failure;
    }
    res = value_update_u32(v, submodule_id);
    if (res == -1) {
	fprintf(stdout, "ERROR: failed to load value of submodule_id\n");
	ret = CI_UPDATE_ERR;
	goto failure;
    }
    res = target_store_value(t, v);
    if (res == -1) {
	fprintf(stdout, "ERROR: failed to write submodule_id\n");
	ret = CI_STORE_ERR;
	goto failure;
    }
    value_free(v);

    /* Set the command id */
    v = target_load_value_member(t, value, "cmd_id", NULL, LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of memeber cmd_id \n");
	ret = CI_LOAD_ERR;
	goto failure;
    }
    res = value_update_u32(v, cmd_id);
    if (res == -1) {
	fprintf(stdout, "ERROR: Failed to update value of cmd_id\n");
	ret = CI_UPDATE_ERR;
	goto failure;
    }
    res = target_store_value(t, v);
    if (res == -1) {
	fprintf(stdout, "ERROR: Failed to write cmd_id\n");
	ret = CI_STORE_ERR;
	goto failure;
    }
    value_free(v);

    /* Set the argument count */
    v = target_load_value_member(t, value, "argc", NULL, LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of memeber argc \n");
	ret = CI_LOAD_ERR;
	goto failure;
    }
    res = value_update_u32(v, token->argc);
    if (res == -1) {
	fprintf(stdout, "ERROR: failed to update value of argc\n");
	ret = CI_UPDATE_ERR;
	goto failure;
    }
    res = target_store_value(t, v);
    if (res == -1) {
	fprintf(stdout, "ERROR: failed to write argc\n");
	ret = CI_STORE_ERR;
	goto failure;
    }
    value_free(v);

    /* Set the entire argv array
    for(i=0; i<128; i++) {
	argv[i] = strtol(token->argv[i],NULL,0);
    }

    argv[1] = 0xc05084d8;
    argv[2] = 0xc036c50a;
    for(i =0; i< 10;i++) {
	printf("Arg %d = %lu\n",i,argv[i]);
    }
    */
    v = target_load_value_member(t, value, "argv", NULL,
	    LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of memeber argv \n");
	ret = CI_LOAD_ERR;
	goto failure;
    }
    memcpy(v->buf,argv,128*sizeof(int));
    res = target_store_value(t, v);
    if (res == -1) {
	fprintf(stdout, "ERROR: failed to write argv\n");
	ret = CI_STORE_ERR;
	goto failure;
    }
    value_free(v);
    symbol_release(command_struct_type);

    /* Increment prod index */
    bs = target_lookup_sym(t, "req_ring_channel", NULL, "repair_driver",
	    SYMBOL_TYPE_FLAG_VAR);
    if (!bs) {
	fprintf(stdout, "ERROR: could not lookup symbol req_ring_channel.\n");
	ret = CI_LOOKUP_ERR;
	goto failure;
    }

    value = target_load_symbol(t, TID_GLOBAL, bs, LOAD_FLAG_NONE);
    if (!value) {
	fprintf(stdout,
		"ERROR: Could not load value of symbol req_ring_channel\n");
	ret = CI_LOAD_ERR;
	goto failure;
    }

    v = target_load_value_member(t, value, "prod", NULL, LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of memeber prod \n");
	ret = CI_LOAD_ERR;
	goto failure;
    }
    res = value_update_u32(v, v_u32(v) + 1);
    if (res == -1) {
	fprintf(stdout,"ERROR: failed to update prod index\n");
	ret = CI_UPDATE_ERR;
	goto failure;
    }

    res = target_store_value(t, v);
    if (res == -1) {
	fprintf(stderr, "ERROR: Failed to set the prod index\n");
	ret = CI_STORE_ERR;
	goto failure;
    }
    
    /*
     * At this stage we have successfully passed the command 
     * to the driver module.Once the appropriate submodule is
     * executed the result gets written to the res_ring_channel 
     * which is indexed by cons. We need to read out the 
     * contents of ack_rec and update the cons index to 
     * complete the request response cycle.
     */

failure: 
    if (v) {
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
	fprintf(stdout,"INFO: Resuming the target\n");
	if (target_resume(t)) {
	    fprintf(stdout, "ERROR: Failed to resume target.\n ");
	}
    }
    return ret;
}



int get_result() {
    struct ack_rec result;
    ADDR ack_ptr;
    struct bsymbol  *bs=NULL;
    struct symbol *ack_struct_type = NULL;
    struct value *v=NULL , *value=NULL;
    ci_error_t ret = CI_SUCCESS;
    int res;

    fprintf(stdout,"INFO: Reading the result.\n");
    
    if ((res = target_status(t)) != TSTATUS_PAUSED) {
	if(target_pause(t)){
	    fprintf(stdout," ERROR: Failed to pause the target.\n");
	    ret = CI_TPAUSE_ERR;
	    goto get_result_fail;
	}
    }

    /* 
     * Get the address within the res_ring_channel page 
     * from where the result needs to be read 
     */
    ack_ptr = get_prod_or_cons_addr("res_ring_channel","cons");
    if (!ack_ptr) {
	fprintf(stdout, "ERROR: get_prod_or_cons_addr failed \n");
	ret = res;
	goto get_result_fail;
    }

    /* Get the type for the acknowledgment structure  and load it
    bs = target_lookup_sym(t, "struct ack_rec", NULL,
		"repair_driver", SYMBOL_TYPE_FLAG_TYPE);
    if(!bs) {
	fprintf(stdout," ERROR: Failed to lookup symbol ack_rec.\n");
	ret = CI_LOOKUP_ERR;
	goto get_result_fail;
    }
    */

    ack_struct_type = bsymbol_get_symbol(target_lookup_sym(t,
		"struct ack_rec", NULL, 
		"repair_driver", SYMBOL_TYPE_FLAG_TYPE)) ;
    value = target_load_type(t, ack_struct_type, ack_ptr, LOAD_FLAG_NONE);
    if(!value){
	fprintf(stdout,"ERROR: Failed to load type of struct ack_rec\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }

    /* get the submodule id */
    v = target_load_value_member(t, value, "submodule_id", NULL,
	    LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,
	    "ERROR: Failed to load the value of member submodule_id\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }
    result.submodule_id = v_u32(v);
    value_free(v);

    /* get the command id */
    v = target_load_value_member(t, value, "cmd_id", NULL, LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of member cmd_id\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }
    result.cmd_id = v_u32(v);
    value_free(v);

    /* get the command execution status */
    v = target_load_value_member(t, value, "exec_status", NULL,
	    LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,
		"ERROR: Failed to load the value of member exec_status\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }
    result.exec_status = v_u32(v);
    value_free(v);

    /* get the argc */
    v = target_load_value_member(t, value, "argc", NULL,
	    LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of memeber argc\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }
    result.argc = v_u32(v);
    value_free(v);

    /* Readout the values stored in argv */
    v = target_load_value_member(t, value, "argv", NULL,
	    LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of memeber argv\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
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
			fprintf(stdout, 
			"SUCCESS: Process with PID %d successfully killed\n",
			result.argv[0]);
		    }
		    else{
			fprintf(stdout,
				"FAILURE: Failed to kill process with PID %d \n."
				,result.argv[0]);
		    }
		    break;
		default:
		    fprintf(stdout,"INFO:Invalid value for cmd_id in result.\n");
	    }
	    break;
	case 1: /*ps_deescalate_module*/
	    switch(result.cmd_id) {
		case 0: /* ps_deescalate_func */
		   if(result.exec_status) {
			fprintf(stdout, 
			"SUCCESS: Credentials of process with PID %d changed successfully.\n",
			result.argv[0]);
		    }
		    else{
			fprintf(stdout,
				"FAILURE: Failed to change credentials of process with PID %d \n."
				,result.argv[0]);
		    }
		    break;
		default:
		    fprintf(stdout,"INFO:Invalid value for cmd_id in result.\n");
	    }

	    break;
	case 2: /* system_map_reset module */
	   switch(result.cmd_id) {
		case 0: /*map reset func  */
		   if(result.exec_status) {
			fprintf(stdout, 
			"SUCCESS: System map table entry reset.\n");
		    }
		    else{
			fprintf(stdout,
				"FAILURE: Failed to reset the system map table entry.\n");
		    }
		    break;
		default:
		    fprintf(stdout,"INFO:Invalid value for cmd_id in result.\n");
	    }

	    break;
	default:
	    fprintf(stdout,"INFO:Invalid value for submodule_id in the result.\n");
    }

    /* Increment the cons index in the res_ring_channel */
    bs = target_lookup_sym(t, "res_ring_channel", NULL, "repair_driver",
		    SYMBOL_TYPE_FLAG_VAR);
    if (!bs) {
	fprintf(stdout, "ERROR: could not lookup symbol res_ring_channel.\n");
	ret = CI_LOOKUP_ERR;
	goto get_result_fail;
    }

    value = target_load_symbol(t, TID_GLOBAL, bs, LOAD_FLAG_NONE);
    if (!value) {
	fprintf(stdout,
		"ERROR: could not load value of symbol req_ring_channel\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }

    v = target_load_value_member(t, value, "cons", NULL, LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of memeber cons\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }
    res = value_update_u32(v, v_u32(v) + 1);
    if (res == -1) {
	fprintf(stdout, "ERROR: Failed to update cons index\n");
	ret = CI_UPDATE_ERR;
	goto get_result_fail;
    }
    res = target_store_value(t, v);
    if (res == -1) {
	fprintf(stderr, "ERROR: Failed to set the cons index\n");
	ret = CI_STORE_ERR;
	goto get_result_fail;
    }

get_result_fail:
    if(v){
	value_free(v);
    }
    if(bs){
	bsymbol_release(bs);
    }
    if(ack_struct_type){
	symbol_release(ack_struct_type);
    }
    if ((res = target_status(t)) == TSTATUS_PAUSED) {
	if(target_resume(t)) {
		fprintf(stdout, "ERROR: Failed to resume the target.\n");
	}
    }
    return ret;

}


int result_ready() {

    target_status_t status;
    struct bsymbol *bs;
    int ready;
    int res;
    struct value *v=NULL;
    ci_error_t ret;
    
    fprintf(stdout,"INFO: Check if the result is ready to be read.\n");
    while (1) {
	if ((status = target_status(t)) != TSTATUS_PAUSED) {
	    if (target_pause(t)) {
		fprintf(stdout,"ERROR: Failed to pause the target \n");
		ret = CI_TPAUSE_ERR;
		goto result_ready_fail;
	    }
	}

	/* Look up the symbol */
	bs = target_lookup_sym(t, "ack_ready", NULL,
		"repair_driver",SYMBOL_TYPE_FLAG_VAR);
	if(!bs) {
	    fprintf(stdout,"ERROR: Failed to lookup symbol ack_ready\n");
	    ret = CI_LOOKUP_ERR;
	    goto result_ready_fail;
	}

	v = target_load_symbol(t, TID_GLOBAL, bs, LOAD_FLAG_NONE);
	if(!v) {
	    fprintf(stdout,
		    "ERROR: Failed to load the value of symbol ack_ready\n");
	    ret = CI_LOAD_ERR;
	    goto result_ready_fail;
	}

	ready = v_i32(v);

	if(ready) {
	    res = value_update_i32(v, ready--);
	    if(res== -1) {
		fprintf(stdout,"ERROR: Failed to reset the flag ack_ready.\n");
		ret = CI_UPDATE_ERR;
		goto result_ready_fail;
	    }
	    goto pass;
	}
	value_free(v);
	bsymbol_release(bs);

	if ((status = target_status(t)) == TSTATUS_PAUSED) {
	    if (target_resume(t)) {
		fprintf(stderr, "ERROR: Failed to resume target!!!\n ");
		goto result_ready_fail;
	    }
	}
	fprintf(stdout,"INFO: Waiting...\n");
	sleep(1);
    }

result_ready_fail:
    if ((status = target_status(t)) == TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    fprintf(stderr, "ERROR: Failed to resume target.\n ");
	}
    }
pass:
    if(v) {
	value_free(v);
    }
    if(bs) {
	bsymbol_release(bs);
    }
    return ret;
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
    int res, args[128];
    char *command, *cur_token;
    char delim = ' ';
    struct target_spec *tspec;
    target_status_t tstat;
    struct TOKEN token;
    target_status_t status;
    int cmd_id, submodule_id;

    memset(&opts, 0, sizeof(opts));

    /* 
     * Parse the command line arguments and get the
     * tspec struct variable.
     */
    tspec = target_argp_driver_parse(&psa_argp, &opts, argc, argv,
	    TARGET_TYPE_XEN, 1);

    if (!tspec) {
	fprintf(stdout,"ERROR: Could not parse target arguments!\n");
	exit(-1);
    }

    dwdebug_init();
    target_init();
    atexit(target_fini);
    atexit(dwdebug_fini);

    /* Initialize the target */
    t = target_instantiate(tspec,NULL);
    if (!t) {
	fprintf(stdout,"ERROR: Count not instantiate target.\n");
	exit(-1);
    }

    /* Open connection to the target.*/
    if (target_open(t)) {
	fprintf(stdout, "ERROR: Connection to target failed.\n");
	exit(-1);
    }

    /* Resume  target */
    if ((status = target_status(t)) == TSTATUS_PAUSED) {
	if(target_resume(t)){
	    fprintf(stdout,"ERROR: Failed to resume the target.\n");
	    goto exit;
	}
    }

    /* Allocate memory for the command */
    command = (char*) malloc(128 * sizeof(char));
    if (!command) {
	fprintf(stdout, "ERROR: Failed to allocate memory for the command\n");
	goto exit;
    }

    /* Start a loop that waits for user to input commands */
    while (1) {
	bzero(command, 128*sizeof(char));
	bzero(args, 128*sizeof(int));
	bzero(token.cmd, 128*sizeof(char));
	bzero(token.argv, 128*128*sizeof(char));
	fprintf(stdout, "\n- ");
	fflush(stdin);
	if((fgets(command,128,stdin)) == NULL) continue;

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

	/* Make appropriate function call */
	if(!(strncmp(token.cmd, "exit", 4))) {
	    goto exit;
	}
	else if(!(strncmp(token.cmd, "pskill",6)))
	{
	    cmd_id = 0;
	    submodule_id = 0;
	    args[0] = atoi(token.argv[0]); 
	    res = load_command_func(&token,cmd_id,submodule_id,args);
	    if (res) {
		fprintf(stderr, "ERROR : load_command_func function call failed \n");
	    }
	}
	else if(!(strncmp(token.cmd,"pssetuid",8)))
	{
	    cmd_id = 0;
	    submodule_id = 1;
	    args[0] = atoi(token.argv[0]);
	    args[1] = atoi(token.argv[1]);
	    res = load_command_func(&token,cmd_id,submodule_id,args);
	    if (res) {
		fprintf(stderr, "ERROR : load_command_func function call failed \n");
	    }
	}
	else  if(!(strncmp(token.cmd,"map_reset",9))) {
	    cmd_id = 0;
	    submodule_id = 2;

	    /* Get the address of the system call table on the machine */
	    res = read_system_map("sys_call_table",  &args[0]);
	    if(res) {
		fprintf(stdout,
			"ERROR: read_system_map function failed to lookup syscall_table.\n");
		continue;
	    }
	    /*Get the correct address of the system call */
	    res = read_system_map("sys_open", &args[1]);
	    if(res) {
		fprintf(stdout,
			"ERROR: read_system_map function failed to lookup %s.\n",
			token.argv[0]);
		continue;
	    }
	    /*Get the offset of the system call in the table */
	    res = read_unistd("sys_open",&args[2]);
	    if(res) {
		fprintf(stdout,
			"ERROR: read_unistd function failed.\n");
		continue;
	    }	  

	    res = load_command_func(&token,cmd_id, submodule_id,args);
	    if (res) {
		fprintf(stdout, "ERROR: load_command_func function call failed.\n");
	    }
	}
	else {
	    fprintf(stdout,"Command not found\n");
	    continue;
	}

	/* Get result of command execution */

	if(result_ready()){
	    if(get_result()) {
		fprintf(stdout,"ERROR: Failed to result of command execution.\n");
	    }
	}
    }

    /* Clean exit code */
exit: fflush(stderr);
      fflush(stdout);
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
