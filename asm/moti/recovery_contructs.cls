
;================== Recovery rule to to generate recoveryfacts =======================
)
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
	(save-facts "state_info.fac" visible unknown-process-recovery-prev-action)
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
	(save-facts "state_info.fac" visible unknown-process-recovery-prev-action)
	(printout t "Killing the process and parent process" crlf))


