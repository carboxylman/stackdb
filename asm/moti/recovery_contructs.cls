
;================== Recovery rule to to generate recoveryfacts =======================
; Rules for dealing with unknown processes
(defrule kill-unknown-process
	(declare (salience 10))
	?f <- (unknown-process 
			 (name ?name1)
			 (pid ?pid))
	(not (exists (unknown-process-recovery-prev-action
		         ( prev_action ps_kill|ps_kill_parent)
			 (name ?name1))))

	=>
	(assert (unknown-process-recovery
		    ( function-name "ps_kill")
		    ( arg_list ?pid ?name1)))
	(assert (unknown-process-recovery-prev-action
		    ( name ?name1)
		    ( prev_action ps_kill)))
	(retract ?f)
	(save-facts "process_state_info.fac" visible unknown-process-recovery-prev-action)
	(printout t " Killing the unknown pocess " ?pid   crlf))

(defrule kill-unknown-process_1
	(declare (salience 20))
	?f <- (unknown-process 
			 (name ?name2)
			 (pid ?pid1))
	 ?of <- (unknown-process-recovery-prev-action
		         ( prev_action ps_kill)
			 (name ?name2))
	=>
	(assert (unknown-process-recovery
		    (function-name "ps_kill_parent")
		    (arg_list ?pid1 ?name2)))
	(retract ?f)
	(retract ?of)
	(assert (unknown-process-recovery-prev-action
		    (prev_action ps_kill_parent)
		    (name ?name2)))
	(save-facts "process_state_info.fac" visible unknown-process-recovery-prev-action)
	(printout t "Killing the process and parent process" crlf))

; Rules for dealing with unknown modules that are loaded.
(defrule unload-unknown-modules
	(declare (salience 10))
	?f <- (unknown-module
		    (name ?name1))
	(not (exists (unknown-module-recovery-prev-action
			(prev_action unload)
			(name ?name1))))
	=>
	(assert (unknown-module-recovery
		    (function-name "module_unload")
		    (arg_list ?name1)))
	(assert (unknown-module-recovery-prev-action
		    (prev_action unload)
		    (name ?name1)))
	(retract ?f)
	(save-facts "module_state_info.fac" visible unknown-module-recovery-prev-action)
	(printout t " Unloading the  module " ?name1   crlf))

(defrule unload-unknown-modules_1
	(declare (salience 20))
	?f <- (unknown-module 
			 (name ?name2))
	?of <- (unknown-module-recovery-prev-action
		         ( prev_action unload)
			 (name ?name2))
	=>
	(retract ?of)
	(assert (unknown-process-recovery
		    (function-name "module_unload")
		    (arg_list  ?name2)))
	(retract ?f)
	(assert (unknown-process-recovery-prev-action
		    (prev_action unload)
		    (name ?name2)))
	(save-facts "module_state_info.fac" visible unknown-module-recovery-prev-action)
	(printout t "Module " ?name2 "was found loaded again!!!!, unloading it." crlf))


;Rules for dealing with tampered system call table entries
(defrule fix-syscall-entries
	(declare (salience 10))
	?f <- (tampered-syscall
		    (name ?name1)
		    (index ?index)
		    (original ?address))
	=> 
	(assert (tampered-syscall-recovery
		    (function-name "fix_syscall_entry")
		    (arg_list  ?index ?address)))
	(printout t " Fixed syscall table entry for " ?name1 crlf))

; Rules for dealing with unauthorized UDP connections

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
	(assert (open-udp-socket-recovery
		    (function-name "close_udp_socket")
		    (arg_list ?name1 ?pid)))
	(retract ?f)
	(assert (open-udp-socket-recovery-prev-action
		    (prev_action close_socket)
		    (name ?name1)
		    (pid ?pid)))
	(save-facts "udp_state_info.fac" visible open-udp-socket-recovery-prev-action)
	(printout t "closed UDP sockets of process " ?name1 crlf)))

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
	(assert (open-udp-socket-recovery
		( function-name "ps_kill")
		( arg_list ?name1 ?pid)))
	(retract ?f)
	(retract ?of)
	(assert (open-udp-socket-recovery-prev-action
		(prev_action kill_process)
		(name ?name1)))
	(save-facts "udp_state_info.fac" visible open-udp-socket-recovery-prev-action)
	(printout t "The UDP socket for the proces " ?name1" was opened again !!! Killing the process now" crlf))

; Rules for dealing with unauthorized TCP connections
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
	(assert (open-tcp-socket-recovery
		    (function-name "close_tcp_socket")
		    (arg_list ?name1 ?pid)))
	(retract ?f)
	(assert (open-tcp-socket-recovery-prev-action
		    (prev_action close_socket)
		    (name ?name1)
		    (pid ?pid)))
	(save-facts "tcp_state_info.fac" visible open-tcp-socket-recovery-prev-action)
	(printout t "closed tcp sockets of process " ?name1 crlf)))

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
	(assert (open-tcp-socket-recovery
		( function-name "ps_kill")
		( arg_list ?name1 ?pid)))
	(retract ?f)
	(retract ?of)
	(assert (open-tcp-socket-recovery-prev-action
		(prev_action kill_process)
		(name ?name1)))
	(save-facts "tcp_state_info.fac" visible open-tcp-socket-recovery-prev-action)
	(printout t "The TCP socket for the proces " ?name1" was opened again !!! Killing the process now" crlf))


