
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

