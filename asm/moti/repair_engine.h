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


/* Standard set of error codes */
typedef enum ci_error_codes {
    CI_SUCCESS     = 0,
    CI_ERROR       = 1,   /* Generic error */
    CI_LOOKUP_ERR  = 2,  /* Failed to lookup symbols */
    CI_LOAD_ERR    = 3,  /* Failed to load vales of symbols */
    CI_UPDATE_ERR  = 4,  /* Failed to update values */
    CI_STORE_ERR   = 5,  /* Failed to store values */
    CI_TPAUSE_ERR  = 6,  /* Failed to pause the target */
    CI_TRESUME_ERR = 7,  /* Failed to resume target */
    CI_EXIT        = 8,
} ci_error_t;

/* acknowledgment struct similar to the one used in the repair driver */
struct ack_rec {
    unsigned int submodule_id; /* submodule in which the command is implemented*/
    unsigned int cmd_id;       /* unique identifier for each command */
    //int exec_status;           /* 1 = success , 0 = error */
    int argc;                  /* result argument count */
    char argv[500];                /* array to store result data*/
};

extern ADDR syscall_table_vm;
extern struct pe_argp_state opts;

/* get the producer address in the request ring channel */
ADDR get_prod_or_cons_addr(const char *symbol_name, const char *index_name) {

    struct bsymbol *bs = NULL;
    struct value *v = NULL, *value = NULL;
    struct target_location_ctxt *tlctxt;
    unsigned int index;
    unsigned int size_in_recs;
    unsigned int size_of_a_rec;
    ADDR rec_base_ptr, addr;
    ci_error_t ret = CI_SUCCESS ;

    /*first get the value stored in req_ring_channel.recs in the module.*/
    bs = target_lookup_sym(target, symbol_name, NULL, "repair_driver",
	    SYMBOL_TYPE_FLAG_VAR);
    if (!bs) {
	fprintf(stderr, "ERROR: Could not lookup symbol %s.\n", symbol_name);
	ret = CI_LOOKUP_ERR;
	goto fail;
    }

    tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,bs);
    if(!tlctxt) {
	fprintf(stdout,"ERROR: Could not create the target location context.\n");
	ret = CI_LOAD_ERR;
	goto fail;
    }

    value = target_load_symbol(target, tlctxt, bs, LOAD_FLAG_NONE);
    if (!value) {
	fprintf(stderr, "ERROR: could not load value of symbol %s\n", symbol_name);
	ret = CI_LOAD_ERR;
	goto fail;
    }
fprintf(stderr, "%s@%p=%p\n", symbol_name, value_addr(value), v_addr(value));

    /* read the base address of the record */
    v = target_load_value_member(target, tlctxt,  value, "recs", NULL, LOAD_FLAG_NONE);
    if(!v){
	fprintf(stderr,"Failed to load the value of member recs\n");
	ret = CI_LOAD_ERR;
	goto fail;
    }
    rec_base_ptr = v_addr(v);
fprintf(stderr, "recs@%p=%x\n", value_addr(v), rec_base_ptr);
    value_free(v);

    /* read the producer index value */
    v = target_load_value_member(target, tlctxt, value, index_name, NULL, LOAD_FLAG_NONE);
    if(!v){
	fprintf(stderr,"Failed to load the value of member index \n");
	ret = CI_LOAD_ERR;
	goto fail;
    }
    index = v_u32(v);
fprintf(stderr, "%s@%p=%x\n", index_name, value_addr(v), index);
    value_free(v);

    /* read the size of the ring buffer in terms of record */
    v = target_load_value_member(target, tlctxt, value, "size_in_recs", NULL,LOAD_FLAG_NONE);
    if(!v){
	fprintf(stderr,"Failed to load the value of member size_in_recs\n");
	ret = CI_LOAD_ERR;
	goto fail;
    }
    size_in_recs = v_u32(v);
fprintf(stderr, "size_in_recs@%p=%x\n", value_addr(v), size_in_recs);
    if(size_in_recs == 0){
	fprintf(stderr,"Got bogus value (0) for size_in_recs\n");
	ret = CI_LOAD_ERR;
	goto fail;
    }
    value_free(v);

    /* read the size of each record */
    v = target_load_value_member(target, tlctxt, value, "size_of_a_rec", NULL,
	    LOAD_FLAG_NONE);
    if(!v){
	fprintf(stderr,"Failed to load the value of member size_of_recs\n");
	ret = CI_LOAD_ERR;
	goto fail;
    }
    size_of_a_rec = v_u32(v);
    if(size_of_a_rec == 0){
	fprintf(stderr,"Got bogus value (0) for size_of_a_rec\n");
	ret = CI_LOAD_ERR;
	goto fail;
    }
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
    if(value) {
	value_free(value);
    }
    return 0;

}

int load_command_func(int cmd_id, int submodule_id, void * argv, int argc) {

    ADDR cmd_ptr;
    struct bsymbol *ack_struct_type=NULL, *bs=NULL;
    struct symbol *command_struct_type=NULL;
    struct value *v=NULL, *value=NULL;
    struct target_location_ctxt *tlctxt;
    int res;
    target_status_t status;
    ci_error_t ret = CI_SUCCESS;


    if (opts.dump_debug)
	fprintf(stdout,"INFO: In the load_command_funtion.\n");
    
    if ((status = target_status(target)) != TSTATUS_PAUSED) {
	if (target_pause(target)) {
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
	ret = CI_LOOKUP_ERR;
	goto failure;
    }
    
    /* Get the type for the command structure  and load it*/
    bs = target_lookup_sym(target,"struct cmd_rec", NULL,
	    "repair_driver", SYMBOL_TYPE_FLAG_TYPE);
    if(!bs) {
	fprintf(stdout,"ERROR: Failed to lookup symbol cmd_rec.\n");
	ret = CI_LOOKUP_ERR;
	goto failure;
    }

    tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,bs);
    if(!tlctxt) {
	fprintf(stdout,"ERROR: Could not create the target location context.\n");
	ret = CI_LOAD_ERR;
	goto failure;
    }

    command_struct_type = bsymbol_get_symbol(bs);
    if(!command_struct_type){
	fprintf(stdout,"ERROR:Target_lookup_symbol failed for struct cmd_rec.\n");
	ret = CI_LOOKUP_ERR;
	goto failure;
    }
    value = target_load_type(target, command_struct_type, cmd_ptr, LOAD_FLAG_NONE);
    if(!value){
	fprintf(stdout,"ERROR: Failed to load type of struct cmd_rec. \n");
	ret = CI_LOAD_ERR;
	goto failure;
    }

    /* Set the submodule id */
    v = target_load_value_member(target, tlctxt,  value, "submodule_id", NULL,
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
    res = target_store_value(target, v);
    if (res == -1) {
	fprintf(stdout, "ERROR: failed to write submodule_id\n");
	ret = CI_STORE_ERR;
	goto failure;
    }
    value_free(v);

    /* Set the command id */
    v = target_load_value_member(target, tlctxt, value, "cmd_id", NULL, LOAD_FLAG_NONE);
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
    res = target_store_value(target, v);
    if (res == -1) {
	fprintf(stdout, "ERROR: Failed to write cmd_id\n");
	ret = CI_STORE_ERR;
	goto failure;
    }
    value_free(v);

    /* Set the argument count */
    v = target_load_value_member(target, tlctxt, value, "argc", NULL, LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of memeber argc \n");
	ret = CI_LOAD_ERR;
	goto failure;
    }
    res = value_update_u32(v, argc);
    if (res == -1) {
	fprintf(stdout, "ERROR: failed to update value of argc\n");
	ret = CI_UPDATE_ERR;
	goto failure;
    }
    res = target_store_value(target, v);
    if (res == -1) {
	fprintf(stdout, "ERROR: failed to write argc\n");
	ret = CI_STORE_ERR;
	goto failure;
    }
    value_free(v);

    v = target_load_value_member(target, tlctxt, value, "argv", NULL,
	    LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of memeber argv \n");
	ret = CI_LOAD_ERR;
	goto failure;
    }
    memcpy(v->buf,argv,500);
    res = target_store_value(target, v);
    if (res == -1) {
	fprintf(stdout, "ERROR: failed to write argv\n");
	ret = CI_STORE_ERR;
	goto failure;
    }
    value_free(v);
    symbol_release(command_struct_type);

    /* Increment prod index */
    bs = target_lookup_sym(target, "req_ring_channel", NULL, "repair_driver",
	    SYMBOL_TYPE_FLAG_VAR);
    if (!bs) {
	fprintf(stdout, "ERROR: could not lookup symbol req_ring_channel.\n");
	ret = CI_LOOKUP_ERR;
	goto failure;
    }

    tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,bs);
    if(!tlctxt) {
	fprintf(stdout,"ERROR: Could not create context for symbol req_ring_channel.\n");
	ret = CI_LOOKUP_ERR;
	goto failure;
    }

    value = target_load_symbol(target, tlctxt, bs, LOAD_FLAG_NONE);
    if (!value) {
	fprintf(stdout,
		"ERROR: Could not load value of symbol req_ring_channel\n");
	ret = CI_LOAD_ERR;
	goto failure;
    }

    v = target_load_value_member(target, tlctxt, value, "prod", NULL, LOAD_FLAG_NONE);
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

    res = target_store_value(target, v);
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

    if ((status = target_status(target)) == TSTATUS_PAUSED) {
	if (target_resume(target)) {
	    fprintf(stdout, "ERROR: Failed to resume target.\n ");
	}
    }
    return ret;
}


int result_ready() {

    target_status_t status;
    struct bsymbol *bs=NULL;
    struct target_location_ctxt *tlctxt;
    int ready;
    int res;
    struct value *v=NULL;
    ci_error_t ret = CI_SUCCESS;
    
    if (opts.dump_debug)
	fprintf(stdout,"INFO: Check if the result is ready to be read.\n");
    while (1) {
	if ((status = target_status(target)) != TSTATUS_PAUSED) {
	    if (target_pause(target)) {
		fprintf(stdout,"ERROR: Failed to pause the target \n");
		ret = CI_TPAUSE_ERR;
		goto result_ready_fail;
	    }
	}

	/* Look up the symbol */
	bs = target_lookup_sym(target, "ack_ready", NULL,
		"repair_driver",SYMBOL_TYPE_FLAG_VAR);
	if(!bs) {
	    fprintf(stdout,"ERROR: Failed to lookup symbol ack_ready\n");
	    ret = CI_LOOKUP_ERR;
	    goto result_ready_fail;
	}

        tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,bs);             
        if(!tlctxt) {                                                                        
	    fprintf(stdout,"ERROR: Could not create the target location context.\n");        
	    ret = CI_LOAD_ERR;
	    goto result_ready_fail;
	}

	v = target_load_symbol(target, tlctxt, bs, LOAD_FLAG_NONE);
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

	if ((status = target_status(target)) == TSTATUS_PAUSED) {
	    if (target_resume(target)) {
		fprintf(stderr, "ERROR: Failed to resume target!!!\n ");
		goto result_ready_fail;
	    }
	}
	fprintf(stdout,"INFO: Waiting...\n");
	sleep(1);
    }

result_ready_fail:
pass:
    if ((status = target_status(target)) == TSTATUS_PAUSED) {
	if (target_resume(target)) {
	    fprintf(stderr, "ERROR: Failed to resume target.\n ");
	}
    }
    if(v) {
	value_free(v);
    }
    if(bs) {
	bsymbol_release(bs);
    }
    return ret;
}


int get_result(struct ack_rec *result) {
    ADDR ack_ptr;
    struct bsymbol  *bs=NULL;
    struct symbol *ack_struct_type = NULL;
    struct target_location_ctxt *tlctxt;
    struct value *v=NULL , *value=NULL;
    ci_error_t ret = CI_SUCCESS;
    int res;
    char buf[500];

    if (opts.dump_debug)
	fprintf(stdout,"INFO: Reading the result.\n");
    
    if ((res = target_status(target)) != TSTATUS_PAUSED) {
	if(target_pause(target)){
	    fprintf(stdout,"ERROR: Failed to pause the target.\n");
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


    char *r = target_read_addr(target, ack_ptr ,500, buf);
    if(!r) {
	fprintf(stdout, "ERROR: Could not read 6 bytes at 0x%"PRIxADDR"!\n",ack_ptr);
	exit(0);
    }
    
    int *ptr = NULL;
    ptr =(int *) buf;
    if (opts.dump_debug)
	fprintf(stdout,"submodule %u\n",*ptr);
    ptr++;
    if (opts.dump_debug)
	fprintf(stdout,"cmd %u\n",*ptr);
    ptr++;
    if (opts.dump_debug)
	fprintf(stdout,"argc %u\n",*ptr);
    ptr++;
    if (opts.dump_debug)
	fprintf(stdout,"pid %u\n",*ptr);


    if (opts.dump_debug)
	fprintf(stdout,"INFO: result record address %"PRIxADDR"\n",ack_ptr); 

    /* Get the type for the acknowledgment structure  and load it */
    bs = target_lookup_sym(target, "struct ack_rec", NULL,
		"repair_driver", SYMBOL_TYPE_FLAG_TYPE);
    if(!bs) {
	fprintf(stdout," ERROR: Failed to lookup symbol ack_rec.\n");
	ret = CI_LOOKUP_ERR;
	goto get_result_fail;
    }
        
    tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,bs);             
    if(!tlctxt) {                                                                        
	fprintf(stdout,"ERROR: Could not create the target location context.\n");        
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }

    ack_struct_type = bsymbol_get_symbol(bs);
    if(!ack_struct_type){
	fprintf(stdout,"ERROR:Target_lookup_symbol failed for struct ack_rec.\n");
	ret = CI_LOOKUP_ERR;
	goto get_result_fail;
    }

    value = target_load_type(target, ack_struct_type, ack_ptr, LOAD_FLAG_NONE);
    if(!value){
	fprintf(stdout,"ERROR: Failed to load type of struct ack_rec\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }

    /* get the submodule id */
    v = target_load_value_member(target, tlctxt, value, "submodule_id", NULL,
	    LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,
	    "ERROR: Failed to load the value of member submodule_id\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }
    result->submodule_id = v_u32(v);
    value_free(v);
    if (opts.dump_debug)
	fprintf(stdout,"INFO: submodule_id  %u\n",result->submodule_id);

    /* get the command id */
    v = target_load_value_member(target, tlctxt, value, "cmd_id", NULL, LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of member cmd_id\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }
    result->cmd_id = v_u32(v);
    value_free(v);
    if (opts.dump_debug)
	fprintf(stdout,"INFO: cmd_id  %u\n",result->cmd_id);

    /* get the command execution status 
    v = target_load_value_member(target, tlctxt, value, "exec_status", NULL,
	    LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,
		"ERROR: Failed to load the value of member exec_status\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }
    result->exec_status = v_u32(v);
    value_free(v);
    */

    /* get the argc */
    v = target_load_value_member(target, tlctxt, value, "argc", NULL,
	    LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of memeber argc\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }
    result->argc = v_u32(v);
    value_free(v);

    /* Readout the values stored in argv */
    v = target_load_value_member(target, tlctxt, value, "argv", NULL,
	    LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of memeber argv\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }

    memcpy(result->argv, v->buf, 500);
    value_free(v);
    
    /* Increment cons index */ 
    bs = target_lookup_sym(target, "res_ring_channel", NULL, "repair_driver",
	    SYMBOL_TYPE_FLAG_VAR);
    if (!bs) {
	fprintf(stdout, "ERROR: could not lookup symbol res_ring_channel.\n");
	ret = CI_LOOKUP_ERR;
	goto get_result_fail;
    }

    tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,bs);
    if(!tlctxt) {
	fprintf(stdout,"ERROR: Could not create context for symbol res_ring_channel.\n");
	ret = CI_LOOKUP_ERR;
	goto get_result_fail;
    }

    value = target_load_symbol(target, tlctxt, bs, LOAD_FLAG_NONE);
    if (!value) {
	fprintf(stdout,
		"ERROR: Could not load value of symbol res_ring_channel\n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }

    v = target_load_value_member(target, tlctxt, value, "cons", NULL, LOAD_FLAG_NONE);
    if(!v){
	fprintf(stdout,"ERROR: Failed to load the value of memeber cons \n");
	ret = CI_LOAD_ERR;
	goto get_result_fail;
    }
    res = value_update_u32(v, v_u32(v) + 1);
    if (res == -1) {
	fprintf(stdout,"ERROR: failed to update cons index\n");
	ret = CI_UPDATE_ERR;
	goto get_result_fail;
    }

    res = target_store_value(target, v);
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
    if ((res = target_status(target)) == TSTATUS_PAUSED) {
	if(target_resume(target)) {
		fprintf(stdout, "ERROR: Failed to resume the target.\n");
	}
    }
    return ret;

}


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
	*function_id = 0;
	*submodule_id = 3;
	return 0;
    }
    else if(!strncmp(function_name,"unload_module", 13)) {
	*function_id = 0;
	*submodule_id = 4;
	return 0;
    } 
    else if(!strncmp(function_name,"unload_objects", 12)) {
	*function_id = 0;
	*submodule_id = 4;
	return 0;
    } 
    else if(!strncmp(function_name,"close_open_files", 16)) {
	*function_id = 0;
	*submodule_id = 5;
	return 0;
    } 
    else if(!strncmp(function_name,"start_process", 13)) {
	*function_id = 0;
	*submodule_id = 6;
	return 0;
    }
    else if (!strncmp(function_name,"trusted_restart", 15)){
	*function_id = 0;
	*submodule_id = 7;
	return 0;
    }
    else if (!strncmp(function_name,"restart_process", 15)) {
	 *function_id = 0;
	 *submodule_id = 8;
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
    char args[128][128];
    char delim[] = " \t()\"";
    char *cur_token =NULL;
    void *arguments = NULL;
    struct ack_rec result;

    if (opts.dump_debug)
	fprintf(stdout,"INFO: in parse recovery_action.\n");

    /* Open the recovey_action file */
    fp = fopen("state_information/recovery_action.fac", "r");
    if(fp == NULL) {
	fprintf(stdout,"WARINING: Failed to open the recovery action file, continuing.\n");
	return 1;
    }

    /* now read one fact at a time and parse it */
    while(fgets(fact,1024,fp) != NULL) {
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Recovery fact read : %s\n",fact);

	/* Tokenize the fact */
	i = 0;
	argc = 0;
	cur_token = (char *)strtok(fact, delim );
	if( cur_token == NULL) continue;
	cur_token = (char *) strtok(NULL, delim);
	cur_token = (char *) strtok(NULL, delim);

	strcpy(function_name, cur_token); 
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: function invoked is %s\n",function_name);
	cur_token = (char *) strtok(NULL, delim);

	/* Now parse all the arguments that are to be passed to that function */
	while((cur_token = (char *) strtok(NULL, delim))) {
	    if(cur_token == NULL) break;
	    argc++;
	    strcpy(args[i],cur_token);
	    if (opts.dump_debug)
		fprintf(stdout ,"INFO: args[%d] = %s\n",i,args[i]);
	    i++;
	}

	/* Map funtion name to appropriate funtion ID */
	ret = function_name_to_id (function_name, &function_id, &submodule_id);
	if(ret) {
	    fprintf(stdout,"ERROR: Invalid function name : %s\n", function_name);
	    continue;
	}

	arguments = (void *)malloc(500);
	if(!arguments) {
	    fprintf(stdout,"ERROR: Failed to allocate memory for the arguments buffer.\n");
	    continue;
	}
	bzero(arguments, 500);

	/* Now based on the function invoked parse the arguments appropriately
	 * and load the command into the ring buffer
	 */

	int *int_ptr = NULL;
	char *char_ptr = NULL;
	long *long_ptr = NULL;
	unsigned long base;
	long index;
	unsigned long address;
	int pid, i, length,j;
	unsigned long bytes1, bytes2;
	switch(submodule_id) 
	{
	    case 0 :        /* Function to kill a process */
		int_ptr = (int *) arguments;
		pid = atoi(args[1]);
		memcpy((void *)int_ptr, (void *) &pid, sizeof(int));
		fprintf(stdout,"INFO: Invoking function to kill process %s : %d \n",
			args[0], *int_ptr);
		int_ptr++;

		/* Only passing the pid to the recovery component */
		argc = 1;
		ret = load_command_func(function_id,submodule_id,arguments,argc);
		if(ret) {
		    fprintf(stdout,"ERROR: load_comand_func call failed.\n");
		    return 1;
		}
	    	
		/* Get result of command execution */
		result_ready();
		/*
		if(get_result(&result)) {
			fprintf(stdout,"ERROR: Failed to result of command execution.\n");
		 }
		}

		// Display the result 
		if(result.submodule_id != 0 || result.cmd_id !=0) {
		    fprintf(stdout,"ERROR: Invalid result read.\n");
		    continue;
		}
		unsigned int *int_ptr = (unsigned int*) result.argv;
		if(result.exec_status) {
		    fprintf(stdout,"INFO: Process with pid %d killed succesfully.\n", *int_ptr);
		}
		else {
		   fprintf(stdout,"ERROR: Failed to kill process with pid %u.\n",*int_ptr);
		}
		*/
		break;

	    case 1 :
		int_ptr = (int *) arguments;
		pid = atoi(args[1]);
		int uid = atoi(args[2]);
		int gid = atoi(args[3]);
		memcpy((void *)int_ptr, (void *) &pid, sizeof(int));
		int_ptr++;
		memcpy((void *)int_ptr, (void *) &uid, sizeof(int));
		int_ptr++;
		memcpy((void *)int_ptr, (void *) &gid, sizeof(int));
		int_ptr++;

		fprintf(stdout,"INFO: Invoking function to reset credentials of  process %s : %d \n",
			args[0], pid);

		/* Only passing the pid to the recovery component */
		argc = 3;
		ret = load_command_func(function_id,submodule_id,arguments,argc);
		if(ret) {
		    fprintf(stdout,"ERROR: load_comand_func call failed.\n");
		    return 1;
		}
		result_ready();

		break;

	    case 2 :
		if(function_id == 0) {
		    long_ptr = (long*) arguments;
		    base = strtoul(args[0], NULL, 16);
		    index = strtoul(args[1], NULL, 0);
		    address = strtoul(args[2], NULL, 16);
		    
		    memcpy((void *)long_ptr, (void *) &base, sizeof(long));
		    long_ptr++;
		    memcpy((void *)long_ptr, (void *) &index, sizeof(long));
		    long_ptr++;
		    memcpy((void *)long_ptr, (void *) &address, sizeof(long));
		    long_ptr = (long *) arguments;
		
		    fprintf(stdout,"INFO: Invoking funtion to reset the system call table.\n");
		    argc = 3;
		    ret = load_command_func(function_id,submodule_id,arguments,argc);
		    if(ret) {
			fprintf(stdout,"ERROR: load_comand_func call failed.\n");
			return 1;
		   }
		}
		else {
		    long_ptr = (long*) arguments;
		    address = strtoul(args[0], NULL, 16);
		    bytes1 = strtoul(args[1], NULL, 16);
		    bytes2 = strtoul(args[2], NULL, 16);
 		    memcpy((void *)long_ptr, (void *) &address, sizeof(long));
		    long_ptr++;
		    memcpy((void *)long_ptr, (void *) &bytes1, sizeof(long));
		    long_ptr++;
		    memcpy((void *)long_ptr, (void *) &bytes2, sizeof(long));
		    long_ptr++;
		    fprintf(stdout,"INFO: Invoking funtion to unhook the system call.\n");
		    argc = 3;
		    ret = load_command_func(function_id,submodule_id,arguments,argc);
		    if(ret) {
			fprintf(stdout,"ERROR: load_comand_func call failed.\n");
			return 1;
		   }
		}
		result_ready();
		break;

	    case 3 :
		int_ptr = (int *) arguments;
		pid = atoi(args[1]);
		memcpy((void *)int_ptr, (void *) &pid, sizeof(int));
		fprintf(stdout,"INFO: Invoking function to kill sockets of process %s : %d \n", 
			    args[0], *int_ptr);
		int_ptr++;

		/* Only passing the pid to the recovery component */
		argc = 1;
		ret = load_command_func(function_id,submodule_id,arguments,argc);
		if(ret) {
		    fprintf(stdout,"ERROR: load_comand_func call failed.\n");
		    return 1;
		}
		result_ready();
		break;
	    
	    case 4: /* sled loaded objects objects */
		char_ptr = (char *) arguments;
		pid = atoi(args[0]);
		//fprintf(stdout,"INFO: PID = %d\n",pid);
		/* copy the PID */
		memcpy((void*)char_ptr, (void *)&pid, sizeof( int));
		char_ptr =  char_ptr + sizeof(int);

		/* copy the object names */
		for(i= 1; i< (argc -2) ;i++) {
		    length = strlen(args[i]);
		    length++;
		    memcpy((void *)char_ptr, (void*)&length, sizeof(int));
		    char_ptr = char_ptr + sizeof(int);
		    //fprintf(stdout,"INFO: length = %d %s\n",length, args[i]);
		    memcpy((void*)char_ptr, (void*)&args[i], (length * sizeof(char)));
		    char_ptr =  char_ptr + (length * sizeof(char)) ;
		}
		argc--; /* dont pass the terminal null string */
	
		ret = load_command_func(function_id,submodule_id,arguments,argc);
		if(ret) {
		    fprintf(stdout,"ERROR: load_comand_func call failed.\n");
		    return 1;
		}
		result_ready();
		break;

	    case 5: /* close open files */
		char_ptr = (char *) arguments;
		pid = atoi(args[0]);
		//fprintf(stdout,"INFO: PID = %d\n",pid);
		/* copy the PID */
		memcpy((void*)char_ptr, (void *)&pid, sizeof( int));
		char_ptr =  char_ptr + sizeof(int);
		length = strlen(args[1]);
		length++;
		//fprintf(stdout,"INFO: Length = %d\n",length);
		
		/* copy the length of the file name */
		memcpy((void*)char_ptr, (void *)&length, sizeof( int));
		char_ptr =  char_ptr + sizeof(int);

		/* copy the file name */
		memcpy((void*)char_ptr, (void*)&args[1], (length * sizeof(char)) + 1);
		//fprintf(stdout,"INFO: File = %s\n",args[1]);

		argc = 3;
		ret = load_command_func(function_id,submodule_id,arguments,argc);
		if(ret) {
		    fprintf(stdout,"ERROR: load_comand_func call failed.\n");
		    return 1;
		}
		result_ready();
		break;
	    case 6: /*start a process */
		char_ptr = (char *) arguments;
		argc--;
		fprintf(stdout,"INFO: Starting a process.\n"); 
		/* load the command line arguments */
		for(i= 0; i< (argc - 3 ) ;i++) {
		    length = strlen(args[i]);
		    memcpy((void *)char_ptr, (void*)&length, sizeof(int));
		    char_ptr = char_ptr + sizeof(int);
		    //fprintf(stdout,"INFO: length = %d %s\n",length, args[i]);
		    memcpy((void*)char_ptr, (void*)&args[i], (length * sizeof(char)) + 1);
		    char_ptr =  char_ptr + (length * sizeof(char)) + 1; ;
		}
		i = 0;
		memcpy((void *)char_ptr, (void*)&i, sizeof(int));
		char_ptr = char_ptr + sizeof(int);

		/* load the environment */
		for( i = (argc-3) ; i < argc; i++) {
		    length = strlen(args[i]);
		    memcpy((void *)char_ptr, (void*)&length, sizeof(int));
		    char_ptr = char_ptr + sizeof(int);
		    //fprintf(stdout,"INFO: length = %d %s\n",length, args[i]);
		    memcpy((void*)char_ptr, (void*)&args[i], (length * sizeof(char))+1);
		    char_ptr =  char_ptr + ((length * sizeof(char)) + 1);

		}
		i = 0;
		memcpy((void *)char_ptr, (void*)&i, sizeof(int));
		char_ptr = char_ptr + sizeof(int);
		
		ret = load_command_func(function_id,submodule_id,arguments,argc);
		if(ret) {
		    fprintf(stdout,"ERROR: load_comand_func call failed.\n");
		    return 1;
		}
		result_ready();
		break;
	    
	    case 7: /* Trusted load of abjects */
		argc--;
		fprintf(stdout, "INFO: argc = %d\n",argc);
		char_ptr = (char *) arguments;
		memcpy((void *)char_ptr, (void*)&syscall_table_vm, sizeof(unsigned long));
		char_ptr = char_ptr + sizeof(unsigned long);

		/* load the object names */
		for( i = 0; i< argc ; i++) {
		    if(!strcmp(args[i], "null")) break;
		    length = strlen(args[i]);
		    length++;
		    memcpy((void *)char_ptr, (void*)&length, sizeof(int));
		    char_ptr = char_ptr + sizeof(int);
		    fprintf(stdout,"INFO: length = %d %s\n",length, args[i]);
		    memcpy((void*)char_ptr, (void*)&args[i], (length * sizeof(char)));
		    char_ptr =  char_ptr + (length * sizeof(char));
		}

		/* Invoke the sumodule to set up the hook */
	    	ret = load_command_func(0,submodule_id,arguments, i );
		if(ret) {
		    fprintf(stdout,"ERROR: load_comand_func call failed.\n");
		    return 1;
		}
		result_ready();
    

	    	/* load the command line arguments */
		bzero(arguments, 500);
		i++;
		char_ptr = (char *) arguments;		
		for(; i< (argc - 3 ) ;i++) {
		    length = strlen(args[i]);
		    memcpy((void *)char_ptr, (void*)&length, sizeof(int));
		    char_ptr = char_ptr + sizeof(int);
		    fprintf(stdout,"INFO: length = %d %s\n",length, args[i]);
		    memcpy((void*)char_ptr, (void*)&args[i], (length * sizeof(char))+ 1);
		    char_ptr =  char_ptr + (length * sizeof(char)) + 1 ;
		}
		i = 0;
		memcpy((void *)char_ptr, (void*)&i, sizeof(int));
		char_ptr = char_ptr + sizeof(int);

		/* load the environment */
		for( i = (argc-3) ; i < argc; i++) {
		    length = strlen(args[i]);
		    memcpy((void *)char_ptr, (void*)&length, sizeof(int));
		    char_ptr = char_ptr + sizeof(int);
		    fprintf(stdout,"INFO: length = %d %s\n",length, args[i]);
		    memcpy((void*)char_ptr, (void*)&args[i], (length * sizeof(char))+1);
		    char_ptr =  char_ptr + ((length * sizeof(char)) + 1);

		}
		i = 0;
		memcpy((void *)char_ptr, (void*)&i, sizeof(int));
		char_ptr = char_ptr + sizeof(int);
		
		/*invoke the submodule to start the process */
		ret = load_command_func(0, 6, arguments,argc);
		if(ret) {
		    fprintf(stdout,"ERROR: load_comand_func call failed.\n");
		    return 1;
		}
		
		/* Sleep for sometime to make sure the boot is complete */
		sleep(4); 
		result_ready();
			    
		/* unhook the syscall table */
		bzero(arguments, 500);
		char_ptr = (char *) arguments;
		memcpy((void *)char_ptr, (void*)&syscall_table_vm, sizeof(unsigned long));
		char_ptr = char_ptr + sizeof(unsigned long);
		ret = load_command_func(1, submodule_id, arguments,1);
		if(ret) {
		    fprintf(stdout,"ERROR: load_comand_func call failed.\n");
		    return 1;
		}
	    
		result_ready();
	
		break;
	    case 8: 	
		int_ptr = (int *) arguments;
		pid = atoi(args[0]);
		memcpy((void *)int_ptr, (void *) &pid, sizeof(int));
		int_ptr++;
		fprintf(stdout,"INFO: Invoking function to restart  process : %d \n", pid);
		/* Only passing the pid to the recovery component */
		ret = load_command_func(0,0,arguments,1);
		if(ret) {
		    fprintf(stdout,"ERROR: load_comand_func call failed.\n");
		    return 1;
		}
	    	
		/* Get result of command execution */
		result_ready();
		bzero(arguments, 500);
		
		/* restart a process */
		char_ptr = (char *) arguments;
		argc = argc - 1;
		/* load the command line arguments */
		for(i= 1; i< (argc - 3 ) ;i++) {
		    length = strlen(args[i]);
		    memcpy((void *)char_ptr, (void*)&length, sizeof(int));
		    char_ptr = char_ptr + sizeof(int);
		    //fprintf(stdout,"INFO: length = %d %s\n",length, args[i]);
		    memcpy((void*)char_ptr, (void*)&args[i], (length * sizeof(char)) + 1);
		    char_ptr =  char_ptr + (length * sizeof(char)) + 1; ;
		}
		i = 0;
		memcpy((void *)char_ptr, (void*)&i, sizeof(int));
		char_ptr = char_ptr + sizeof(int);

		/* load the environment */
		for( i = (argc-3) ; i < argc; i++) {
		    length = strlen(args[i]);
		    memcpy((void *)char_ptr, (void*)&length, sizeof(int));
		    char_ptr = char_ptr + sizeof(int);
		    //fprintf(stdout,"INFO: length = %d %s\n",length, args[i]);
		    memcpy((void*)char_ptr, (void*)&args[i], (length * sizeof(char))+1);
		    char_ptr =  char_ptr + ((length * sizeof(char)) + 1);

		}
		i = 0;
		memcpy((void *)char_ptr, (void*)&i, sizeof(int));
		char_ptr = char_ptr + sizeof(int);
		
		ret = load_command_func(0,6,arguments,argc);
		if(ret) {
		    fprintf(stdout,"ERROR: load_comand_func call failed.\n");
		    return 1;
		}
		result_ready();
		break;
		    default: break; 
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
