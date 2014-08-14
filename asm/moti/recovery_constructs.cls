
;==============Rules for dealing with unknown processes======================
(defrule kill-unknown-process
	(declare (salience 10))
	?f <- (unknown-process 
			 (name ?name1)
			 (pid ?pid)
			 (ppid ?ppid))
	(not (exists (unknown-process-recovery-prev-action
		         ( prev_action ps_kill|ps_kill_parent)
			 (name ?name1)
			 (pid ?pid))))

	=>
	(assert (recovery-action
		    ( function-name kill_process)
		    ( arg_list  ?name1 ?pid)))
	(assert (unknown-process-recovery-prev-action
		    ( name ?name1)
		    ( pid ?pid)
		    ( prev_action ps_kill)))
	(retract ?f)
	(save-facts "state_information/recovery_action.fac" visible recovery-action) 
	(save-facts "state_information/process_state_info.fac" visible unknown-process-recovery-prev-action)
	(printout t "RECOVERY: Killing the unknown process " ?pid   crlf))

(defrule kill-unknown-process_1
	(declare (salience 20))
	?f <- (unknown-process 
			 (name ?name2)
			 (pid ?pid1)
			 (ppid ?ppid1))
	 ?of <- (unknown-process-recovery-prev-action
		         ( prev_action ps_kill)
			 (name ?name2)
        		 (pid ?pid1))
	=>
	(assert (recovery-action
		    (function-name kill_parent_process)
		    (arg_list ?name2 ?pid1 ?ppid1)))
	(retract ?f)
	(retract ?of)
	(assert (unknown-process-recovery-prev-action
		    (prev_action ps_kill_parent)
		    (name ?name2)
		    (pid ?pid1)))
	(save-facts "state_information/recovery_action.fac" visible recovery-action) 
	(save-facts "state_information/process_state_info.fac" visible unknown-process-recovery-prev-action)
	(printout t "RECOVERY: Killing the unknown process " ?pid1 " and parent process " ?ppid1 crlf))

(defrule kill-unknown-process_2
	(declare (salience 30))
	?f <- (unknown-process 
			 (name ?name2)
			 (pid ?pid1)
			 (ppid ?ppid1))
	?of <- (unknown-process-recovery-prev-action
		         ( prev_action ps_kill_parent)
			 (name ?name2)
			 (pid ?pid1))
	=>
	(retract ?of)
	(retract ?f)
	(save-facts "state_information/process_state_info.fac" visible unknown-process-recovery-prev-action)
        (printout t "RECOVERY: Tried killing the unknown process " ?pid1 " and its parent " ?ppid1 ", but the process still exist. !!! Repeating the  recovery cycle now. " crlf))


;==============Rules for dealing with unknown modules that are loaded.=========================
(defrule unload-unknown-modules
	(declare (salience 10))
	?f <- (unknown-module
		    (name ?name1))
	(not (exists (unknown-module-recovery-prev-action
			(prev_action unload)
			(name ?name1))))
	=>
	(assert (recovery-action
		    (function-name unload_kernel_module)
		    (arg_list ?name1)))
	(assert (unknown-module-recovery-prev-action
		    (prev_action unload)
		    (name ?name1)))
	(retract ?f)
	(save-facts "state_information/recovery_action.fac" visible recovery-action) 
	(save-facts "state_information/module_state_info.fac" visible unknown-module-recovery-prev-action)
	(printout t "RECOVERY: Unloading the  module " ?name1   crlf))

(defrule unload-unknown-modules_1
	(declare (salience 20))
	?f <- (unknown-module 
			 (name ?name2))
	?of <- (unknown-module-recovery-prev-action
		         ( prev_action unload)
			 (name ?name2))
	=>
	(retract ?of)
	(assert (recovery-action
		    (function-name unload_kernel_module)
		    (arg_list  ?name2)))
	(retract ?f)
	(assert (unknown-module-recovery-prev-action
		    (prev_action unload)
		    (name ?name2)))
	(save-facts "state_information/recovery_action.fac" visible recovery-action) 
	(save-facts "state_information/module_state_info.fac" visible unknown-module-recovery-prev-action)
	(printout t "RECOVERY: Module " ?name2 "was found loaded again!!!!, unloading it." crlf))


;===============Rules for dealing with tampered system call table entries=======================
(defrule fix-syscall-entries
	(declare (salience 10))
	?f <- (tampered-syscall
		    (name ?name1)
		    (index ?index)
		    (original ?address)
		    (base_address ?base_address))
	 => 
	(assert (recovery-action
		    (function-name fix_syscall_entry)
		    (arg_list  ?base_address ?index ?address)))
	(save-facts "state_information/recovery_action.fac" visible recovery-action) 
	(printout t "RECOVERY: Fixed syscall table entry for " ?name1 crlf))

;Rules for dealing with hooked  system call table entries
(defrule fix-hooked-entries
	(declare (salience 10))
	?f <- (hooked-syscall
		    (name ?name1)
		    (address ?address)
		    (original-0-8 ?bytes1)
		    (original-8-16 ?bytes2))
	=> 
	(assert (recovery-action
		    (function-name fix_hooked_entry)
		    (arg_list  ?address ?bytes1 ?bytes2)))
	(save-facts "state_information/recovery_action.fac" visible recovery-action) 
	(printout t "RECOVERY: Fixed hooked syatem call " ?name1 crlf))


;=================Rules for dealing with unauthorized UDP connections====================
(defrule close-udp-sockets
	(declare (salience 10))
	?f <- (open-udp-socket
		(name ?name1)
		(pid ?pid))
	(not (exists ( open-udp-socket-recovery-prev-action
			(prev_action close_socket|kill_process)
			(name ?name1)
			(pid ?pid))))
	=>
	(assert (recovery-action
		    (function-name close_udp_socket)
		    (arg_list ?name1 ?pid)))
	(retract ?f)
	(assert (open-udp-socket-recovery-prev-action
		    (prev_action close_socket)
		    (name ?name1)
		    (pid ?pid)))
	(save-facts "state_information/recovery_action.fac" visible recovery-action) 
	(save-facts "state_information/udp_state_info.fac" visible open-udp-socket-recovery-prev-action)
	(printout t "RECOVERY: Closed UDP sockets of process " ?name1 crlf))

(defrule close-udp-socket_1
	(declare (salience 20))
	?f <- (open-udp-socket
		(name ?name1)
		(pid ?pid))
	?of <- (open-udp-socket-recovery-prev-action
		    (prev_action close_socket)
		    (name ?name1)
		    (pid ?pid))
	=>
	(assert (recovery-action
		( function-name kill_process)
		( arg_list ?name1 ?pid)))
	(retract ?f)
	(retract ?of)
	(assert (open-udp-socket-recovery-prev-action
		(prev_action kill_process)
		(name ?name1)))
	(save-facts "state_information/recovery_action.fac" visible recovery-action) 
	(save-facts "state_information/udp_state_info.fac" visible open-udp-socket-recovery-prev-action)
	(printout t "RECOVERY: The UDP socket for the proces " ?name1" was opened again !!! Killing the process now" crlf))

(defrule close-udp-socket_2
	(declare (salience 30))
	?f <- (open-udp-socket
		(name ?name1)
		(pid ?pid))
	?of <- (open-udp-socket-recovery-prev-action
		    (prev_action kill_process)
		    (name ?name1))
	=>
	(retract ?f)
	(retract ?of)
	(save-facts "state_information/udp_state_info.fac" visible open-udp-socket-recovery-prev-action)
	(printout t "RECOVERY: Process " ?name1" with unauthorised UPD socket was found again. !!! Repeating the recovery cycle now." crlf))


;====================Rules for dealing with unauthorized TCP connections===========================
(defrule close-tcp-sockets
	(declare (salience 10))
	?f <- (open-tcp-socket
		(name ?name1)
		(pid ?pid))
	(not (exists ( open-tcp-socket-recovery-prev-action
			(prev_action close_socket|kill_process)
			(name ?name1)
			(pid ?pid))))
	=>
	(assert (recovery-action
		    (function-name close_tcp_socket)
		    (arg_list ?name1 ?pid)))
	(retract ?f)
	(assert (open-tcp-socket-recovery-prev-action
		    (prev_action close_socket)
		    (name ?name1)
		    (pid ?pid)))
	(save-facts "state_information/recovery_action.fac" visible recovery-action) 
	(save-facts "state_information/tcp_state_info.fac" visible open-tcp-socket-recovery-prev-action)
	(printout t "RECOVERY: Closed tcp sockets of process " ?name1 crlf))

(defrule close-tcp-socket_1
	(declare (salience 20))
	?f <- (open-tcp-socket
		(name ?name1)
		(pid ?pid))
	?of <- (open-tcp-socket-recovery-prev-action
		    (prev_action close_socket)
		    (name ?name1)
		    (pid ?pid))
	=>
	(assert (recovery-action
		( function-name kill_process)
		( arg_list ?name1 ?pid)))
	(retract ?f)
	(retract ?of)
	(assert (open-tcp-socket-recovery-prev-action
		(prev_action kill_process)
		(name ?name1)))
	(save-facts "state_information/recovery_action.fac" visible recovery-action) 
	(save-facts "state_information/tcp_state_info.fac" visible open-tcp-socket-recovery-prev-action)
	(printout t "RECOVERY: The TCP socket for the proces " ?name1" was opened again !!! Killing the process now" crlf))

(defrule close-tcp-socket_2
	(declare (salience 30))
	?f <- (open-tcp-socket
		(name ?name1)
		(pid ?pid))
	?of <- (open-tcp-socket-recovery-prev-action
		    (prev_action kill_process)
		    (name ?name1))
	=>
	(retract ?f)
	(retract ?of)
	(save-facts "state_information/tcp_state_info.fac" visible open-tcp-socket-recovery-prev-action)
	(printout t "RECOVERY: Proces " ?name1" with unauthorized TCP socket was found again!!! Repeating the recovery cycle now" crlf))


;================Rules for delaling with high per process cpu utilization=============================

(defrule correct-cpu-utilization 
	(declare (salience 10))
	?f <- (per-process-cpu-utilization
	     (name ?name1)
	     (pid ?pid)
	     (cpu ?utilization)
	     (count ?count))
	(test ( =  (mod ?count  2 ) 0))
	(test (not ( = ?count 0))) 
	(test ( > (/ ?utilization ?count) 90))
	;now test if the overall cpu load is really high and the process
	; is a low priority process
	(low-priority-process $?low-prio-processes)
	(test (member$ ?name1 $?low-prio-processes))
	(cpu-load (five-min ?load))
	(test ( > ?load 0.3))
	=>
	(assert (recovery-action
		    (function-name reduce_utilization)
		    (arg_list ?name1 ?pid)))
	(save-facts "state_information/recovery_action.fac" visible recovery-action) 
	(printout t "RECOVERY: Process " ?name1 " has high cpu utilization over the past 2 iterations" crlf)
	(printout t "RECOVERY: The cpu load during past 2 mins is " ?load crlf)
        (modify ?f (cpu 0.0) (count 0))
	(save-facts "state_information/cpu_state_info.fac" visible per-process-cpu-utilization))

;================Rules for dealing with priv escalation===========================
;
;(defrule correct-priv-escalation
;	(declare (salience 10))
;	?f <- (priv-escalated-process
;		(name ?name1)
;		(pid ?pid))
;	(not (exists (priv-escalation-recovery-prev-action
;			(prev_action kill_process)
;			(name ?name1))))
;	=>
;	(assert (recovery-action
;		    (function-name kill_process)
;		    (arg_list ?name1 ?pid)))
;	(retract ?f)
;	(assert (priv-escalation-recovery-prev-action
;		    (prev_action kill_process)
;		    (name ?name1)))
;	(save-facts "state_information/recovery_action.fac" visible recovery-action)
;	(save-facts "state_information/process_priv_state_info.fac" visible priv-escalation-recovery-prev-action)
;	(printout t "RECOVERY: Killing the priv escalated process " ?name1 crlf ))
;
;
;(defrule correct-priv-escalation_01
;	(declare (salience 20))
;	?f <- (priv-escalated-process
;		(name ?name1)
;		(pid ?pid)
;		(parent_pid ?parent_pid))
;	?of <-( priv-escalation-recovery-prev-action
;		(name ?name1)
;		(prev_action kill_process))
;	=>
;	(assert (recovery-action
;		    (function-name kill_parent_process)
;		    (arg_list ?name1 ?pid ?parent_pid)))
;	(retract ?f)
;	(retract ?of)
;	(assert (priv-escalation-recovery-prev-action
;		(prev_action kill_parent_process)
;		(name ?name1)))
;	(save-facts "state_information/recovery_action.fac" visible recovery-action)
;	(save-facts "state_information/process_priv_state_info.fac" visible priv-escalation-recovery-prev-action)
;	(printout t "RECOVERY: The privileges for the process " ?name1" was escalated again !!! Killing the parent process now" crlf))
;
;(defrule correct-priv-escalation_02
;	(declare (salience 30))
;	?f <- (priv-escalated-process
;		(name ?name1)
;		(pid ?pid)
;		(parent_pid ?parent_pid))
;	?of <-( priv-escalation-recovery-prev-action
;		(name ?name1)
;		(prev_action kill_parent_process))
;	=>
;	(retract ?f)
;	(retract ?of)
;	(save-facts "state_information/process_priv_state_info.fac" visible priv-escalation-recovery-prev-action)
;	(printout t "RECOVERY: The privileges escalated  process " ?name1" was found again !!! Repating the recovery cycle" crlf))
;

;======================rules for dealing with unknown objects loaded=======================
; These rules show how to use handle-multiple-threds fact to deal with multiple
; process with multiple threads. We have to make sure that the same repair action
; is applied to all the threads in the same iteration.

(defrule unload-unknown-objects
    (declare (salience 10))
    ?f <- (unknown-object-list
		(name ?name)
		(pid ?pid)
		(object-list $?list))
    (mandatory-process 
		(name ?name)
		(command $?command))
    (not (exists (unload-unknown-object-prev-action
		         ( prev_action kill_process |sled_object)
			 (name ?name1))))
    (not (exists (handle-multiple-threads
		    (name ?name)
		    (stage one ))))
    =>
    (assert (recovery-action
		(function-name restart_process)
		(arg_list ?pid $?command )))
    (retract ?f)
    (assert (unload-unknown-object-prev-action
		(prev_action  restart_process)
		(name ?name)
		(pid ?pid)))
    (assert (handle-multiple-threads
		(name ?name)
		(stage zero)))
    (save-facts "state_information/recovery_action.fac" visible recovery-action)
    (save-facts "state_information/unload_unknown_object_state_info.fac" visible unload-unknown-object-prev-action)
    (printout t "RECOVERY: Restarting the process " ?name  crlf))

(defrule unload-unknown-objects_01
    (declare (salience 20))
    ?f <- (unknown-object-list
		(name ?name)
		(pid ?pid)
		(object-list $?list))
    ?of <- (unload-unknown-object-prev-action
		(prev_action  restart_process)
		(name ?name))
    (mandatory-process 
		(name ?name)
		(command $?command))
    (not (exists (handle-multiple-threads
		    (name ?name)
		    (stage zero))))
    =>
    (retract ?f)
    (retract ?of)
    (assert (recovery-action
		(function-name trusted_restart)
		(arg_list  ?pid $?list $?command )))
    (assert (handle-multiple-threads
		(name ?name)
		(stage one)))
    (assert (unload-unknown-object-prev-action
		(prev_action  trusted_restart)
		(name ?name)
		(pid ?pid)))
    (save-facts "state_information/recovery_action.fac" visible recovery-action)
    (save-facts "state_information/unload_unknown_object_state_info.fac" visible unload-unknown-object-prev-action)
    (printout t "RECOVERY: The unknown objets "?list " were found to be loaded again. Trying to restart the process in a trust mode" crlf))



(defrule unload-unknown-objects_02
    (declare (salience 30))
    ?f <- (unknown-object-list
		(name ?name)
		(pid ?pid)
		(object-list $?list))
    ?of <- (unload-unknown-object-prev-action
		(prev_action  trusted_restart)
		(name ?name))
    (not (exists (handle-multiple-threads
		    (name ?name)
		    (stage one))))
    ;(test (= (str-compare ?name "apache2") 0))
    =>
    (retract ?f)
    (retract ?of)
    (assert (recovery-action
		(function-name sled_object)
		(arg_list ?pid $?list )))
    (assert (unload-unknown-object-prev-action
		(prev_action  sled_object)
		(name ?name)
		(pid ?pid)))
     (assert (handle-multiple-threads
		(name ?name)
		(stage two)))
    (save-facts "state_information/recovery_action.fac" visible recovery-action)
    (save-facts "state_information/unload_unknown_object_state_info.fac" visible unload-unknown-object-prev-action)
    (printout t "RECOVERY: Sledding the unknown objects " $?list " loaded by the process " ?name crlf)
    (printout t "RECOVERY: This repair may cause certain processes to crash or become unresponsive." crlf))


(defrule unload-unknown-objects_03
    (declare (salience 40))
    ?f <- (unknown-object-list
		(name ?name)
		(pid ?pid)
		(object-list $?list))
    ?of <- (unload-unknown-object-prev-action
		(prev_action  sled_object)
		(name ?name)
		(pid ?pid))
    (not (exists (handle-multiple-threads
		    (name ?name)
		    (stage two))))
    ;(test (= (str-compare ?name "apache2") 0))
    =>
    (retract ?f)
    (save-facts "state_information/recovery_action.fac" visible recovery-action)
    (save-facts "state_information/unload_unknown_object_state_info.fac" visible unload-unknown-object-prev-action)
    (printout t "RECOVERY: The unknown object loaded by the process " ?name " has already been sledded. "crlf))

(defrule unload-unknown-objects_04
    (declare (salience 5))
    ?f <- (unknown-object-list
		(name ?name)
		(pid ?pid)
		(object-list $?list))
    (not (exists (mandatory-process 
		    (name ?name)
		    (command $?command))))
    =>
    (assert (recovery-action
		(function-name kill_process)
		(arg_list  ?name ?pid  )))
    (save-facts "state_information/recovery_action.fac" visible recovery-action)
    (printout t "RECOVERY: Terminating the non mandatory process " ?name " as it has an unknown object loaded. "crlf))



;===============rules for dealing with unknown files opened by a process=======================
(defrule close-unknown-open-files
    (declare (salience 10))
    ?f <- (unknown-open-files
		(name ?name)
		(pid ?pid)
		(file ?file))
    =>
    (assert (recovery-action
		(function-name close_open_files)
		(arg_list ?pid ?file)))
    (retract ?f)
    (save-facts "state_information/recovery_action.fac" visible recovery-action)    
    (printout t "RECOVERY: Closing the files:" ?file " open by the process " ?name crlf))


;===================Rules for dealing with with wrong process credentials=====================
(defrule correct-proc-cred
	(declare (salience 10))
	?f <- (wrong-process-cred
		(name ?name1)
		(pid ?pid)
		(uid ?uid)
		(gid ?gid))
	(not (exists (wrong-proc-cred-prev-action
			(prev_action reset_cred | kill_process )
			(name ?name1))))
	=>
	(assert (recovery-action
		    (function-name reset_credentials)
		    (arg_list ?name1 ?pid ?uid ?gid)))
	(retract ?f)
	(assert (wrong-proc-cred-prev-action
		    (prev_action reset_cred)
		    (name ?name1)))
	(save-facts "state_information/recovery_action.fac" visible recovery-action)
	(save-facts "state_information/process_priv_state_info.fac" visible wrong-proc-cred-prev-action)
	(printout t "RECOVERY: Resetting credentials of the process " ?name1 crlf ))


(defrule correct-proc-cred_01
	(declare (salience 20))
	?f <- (wrong-process-cred
		(name ?name1)
		(pid ?pid)
		(uid ?uid?)
		(gid ?gid))
	?of <-( wrong-proc-cred-prev-action
		(name ?name1)
		(prev_action reset_cred))
	=>
	(assert (recovery-action
		    (function-name kill_process)
		    (arg_list  ?pid)))
	(retract ?f)
	(retract ?of)
	(assert (wrong-proc-cred-prev-action
		(prev_action kill_process)
		(name ?name1)))
	(save-facts "state_information/recovery_action.fac" visible recovery-action)
	(save-facts "state_information/process_priv_state_info.fac" visible wrong-proc-cred-prev-action)
	(printout t "RECOVERY: The privileges for the process " ?name1" was escalated again !!! Killing the  process now" crlf))

(defrule correct-proc-cred_02
	(declare (salience 30))
	?f <- (wrong-process-cred
		(name ?name1)
		(pid ?pid))
	?of <-( wrong-proc-cred-prev-action
		(name ?name1)
		(prev_action kill_process))
	=>
	(retract ?f)
	(retract ?of)
	(save-facts "state_information/process_priv_state_info.fac" visible wrong-proc-cred-prev-action)
	(printout t "RECOVERY: The privileges escalated  process " ?name1" was found again !!! Repating the recovery cycle" crlf))

;================== rules for starting mandatory processes ==================================
(defrule start-mandatory-process
    (declare (salience 10))
    ?f <- (missing-process
		(name ?name)
		(command $?command))
    =>
    (assert (recovery-action
		(function-name start_process)
		(arg_list $?command)))
    (retract ?f)
    (save-facts "state_information/recovery_action.fac" visible recovery-action)
    (printout t "RECOVERY: Starting the process " ?name  crlf))

; rule to terminate root shells
(defrule kill-root-shells
    (declare (salience 10))
    ?f <- (root-shells
		(name ?name1)
	        (pid ?pid))
    =>
    (assert (recovery-action
    ( function-name kill_process)
    ( arg_list  ?name1 ?pid)))
    ( retract ?f)
    ( save-facts "state_information/recovery_action.fac" visible recovery-action) 
    (printout t "RECOVERY: Killing the root shell " ?pid   crlf))
