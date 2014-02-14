
;==========================Template for base facts ===============================

(deftemplate task-struct
	(slot comm (type STRING))
	(slot pid (type INTEGER))
	(slot tgid (type INTEGER))
	(slot is_vcpu (type INTEGER))
	(slot is_wq_worker (type INTEGER))
	(slot used_superpriv (type INTEGER))
	(slot is_kswapd (type INTEGER))
	(slot is_kthread (type INTEGER))
	(slot prio (type INTEGER))
	(slot static_prio (type INTEGER))
	(slot normal_prio (type INTEGER))
	(slot rt_priority (type INTEGER))
	(slot nice (type INTEGER))
	(slot uid (type INTEGER))
	(slot euid (type INTEGER))
	(slot suid (type INTEGER))
	(slot fsuid (type INTEGER))
	(slot gid (type INTEGER))
	(slot egid (type INTEGER))
	(slot sgid (type INTEGER))
	(slot fsgid (type INTEGER))
	(slot parent_pid (type INTEGER))
	(slot parent_name (type STRING)))

(deftemplate opened-files
	(slot comm (type STRING))
	(slot pid (type INTEGER))
	(slot lnk_count (type INTEGER) (default 0))
	(multislot lnk_files (type STRING) ( default "NONE"))
	(slot reg_count (type INTEGER) ( default 0))
	(multislot reg_files (type STRING) ( default "NONE"))
	(slot dir_count (type INTEGER) ( default 0))
	(multislot dir_files (type STRING) ( default "NONE"))
	(slot chr_count (type INTEGER) ( default 0))
	(multislot chr_files (type STRING) ( default "NONE"))
	(slot blk_count (type INTEGER) ( default 0))
	(multislot blk_files (type STRING) ( default "NONE"))
	(slot fifo_count (type INTEGER) ( default 0))
	(multislot fifo_files (type STRING) ( default "NONE"))
	(slot sock_count (type INTEGER) ( default 0))
	(multislot sock_files (type STRING) ( default "NONE"))
	(slot num_opened_files (type INTEGER) ( default 0)))

(deftemplate loaded-module
	(slot name (type STRING)))

(deftemplate cpu-load
	(slot one-min (type FLOAT))
	(slot five-min (type FLOAT))
	(slot fifteen-min (type FLOAT)))

(deftemplate cpu_utilization
	(slot comm (type STRING))
	(slot pid (type INTEGER))
	(slot utime (type INTEGER))
	(slot utimescaled (type INTEGER))
	(slot stime (type INTEGER))
	(slot stimescaled (type INTEGER))
	(slot sum_exec_runtime (type INTEGER))
	(slot vruntime (type INTEGER))
	(slot utilization (type FLOAT)))


(deftemplate loaded-objects
	(slot comm (type STRING))
	(slot pid (type INTEGER))
	(multislot objects (type STRING)))

(deftemplate tampered_sys_call  
	(slot name (type STRING))
	(slot original (type INTEGER))
	(slot current (type INTEGER))
	(slot index (type INTEGER)))

(deftemplate command_line
	(slot command (type STRING))
	(slot environment (type STRING)))

;===========Users application level knowledge captured facts====================

(deffacts base-facts
	(known-processes "swapper/0" "init" "kthreadd" "ksoftirqd/0" "kworker/0:0" 
	"kworker/0:0H" "kworker/u:0" "kworker/u:0H" "migration/0" "rcu_bh"
	"rcu_sched" "watchdog/0" "cpuset" "khelper" "kdevtmpfs" "netns" "xenwatch"
	"xenbus" "bdi-default" "kintegrityd" "kblockd" "ata_sff" "khubd" "md"
	"devfreq_wq" "kworker/0:1" "khungtaskd" "kswapd0" "ksmd" "fsnotify_mark"
	"ecryptfs-kthrea" "crypto" "kthrotld" "kworker/0:1" "khvcd" "binder" "deferwq"
	"charger_manager" "kworker/0:1H" "jbd2/xvda1-8" "ext4-dio-unwrit" "upstart-udev-br"
	"udevd" "rpcbind" "sshd" "upstart-socket-" "dbus-daemon" "rsyslogd" "cron"
	"atd" "mysqld" "ntpd" "getty" "flush-202:1")
	
	(known-modules "coretemp" "microcode" "xenfs" "xen_privcmd" "parport")
	(process-with-udp "rpcbind") ;ntpd                 
	(process-with-tcp  "mysqld"  "rpcbind") ;sshd
	(process-with-reg-files-opened "rpcbind" "rsyslogd" "ntpd" "cron" "atd" "mysqld" "udevd")
	(high-priority-process "apache" "sshd")
	(med-priority-process  "mysqld" "ntpd" )
	(low-priority-process  "perl" "temp")
	
	(process-run-as-root "swapper/0" "init" "kthreadd" "ksoftirqd/0" "kworker/0:0" 
	"kworker/0:0H" "kworker/u:0" "kworker/u:0H" "migration/0" "rcu_bh"
	"rcu_sched" "watchdog/0" "cpuset" "khelper" "kdevtmpfs" "netns" "xenwatch"
	"xenbus" "bdi-default" "kintegrityd" "kblockd" "ata_sff" "khubd" "md"
	"devfreq_wq" "kworker/0:1" "khungtaskd" "kswapd0" "ksmd" "fsnotify_mark"
	"ecryptfs-kthrea" "crypto" "kthrotld" "kworker/0:1" "khvcd" "binder" "deferwq"
	"charger_manager" "kworker/0:1H" "jbd2/xvda1-8" "ext4-dio-unwrit" "upstart-udev-br"
	"udevd" "rpcbind" "sshd" "upstart-socket-"  "cron"
	"atd" "ntpd" "getty" "flush-202:1" "login" )
	
	)


	
;============================== Template for anomaly facts =============================

	
(deftemplate unknown-process
	(slot name (type STRING))
	(slot pid (type INTEGER)))

(deftemplate unknown-module
	(slot name (type STRING)))

(deftemplate tampered-syscall
	(slot name (type STRING))
	(slot index (type INTEGER))
	(slot original (type INTEGER)))

(deftemplate open-udp-socket
	(slot name (type STRING))
	(slot pid (type INTEGER)))

(deftemplate open-tcp-socket
	(slot name (type STRING))
	(slot pid (type INTEGER)))

(deftemplate open-reg-file
	(slot name  (type STRING))
	(slot pid (type INTEGER))
	(slot file_name (type STRING)))

(deftemplate per-process-cpu-utilization
	(slot name (type STRING))
	(slot pid (type INTEGER))
	(slot cpu (type FLOAT) (default 0.0))
 	(slot count (type INTEGER)(default 0)))

(deftemplate priv-escalated-process
	(slot name (type STRING))
	(slot pid (type INTEGER))
	(slot parent_pid (type INTEGER)))
	;(slot original_uid (type INTEGER)) how do we get the original values
	;(slot original_gid (type INTEGER))) or do we assign random non root values.


;========== Application level rules that are used to detect anomalies =================

;rule to detect any unkown process that is executing
(defrule identify-unknown-process
	(task-struct (comm ?name1)
		      (pid ?pid))
	(known-processes $?name2)
        (test (not( member$ ?name1 $?name2)))
	=>
	(assert (unknown-process
		       (name ?name1)
		       (pid ?pid)))
	(printout t "Unknown process " ?name1 " found" crlf) )

;rule to detect any unknown module that is loaded
(defrule identify-unknown-module
	(loaded-module (name ?name1))
	(known-modules $?name2)
	(test (not (member$ ?name1 $?name2)))
	=>
	(assert (unknown-module (name ?name1)))
	(printout t "Unknown module " ?name1 "found" crlf)) 

;rule to check for tampered syscall table entries
(defrule identify-tampered-syscall
	(tampered_sys_call
	    (name ?name1)
	    (index ?index)
	    (original ?address))
	=>
	(assert (tampered-syscall
	    (name ?name1)
	    (index ?index)
	    (original ?address)))
	(printout t "Tampered system call " ?name1 " found at offset " ?index crlf))

;rule to check fo unauthorised TCP/UDP sockets
(defrule identify-open-udp-sockets
	(opened-files
	    (comm ?name1)
	    (pid ?pid)
	    (sock_files $?sockets))
	(or (test(member$ "UDP" $?sockets)) (test (member$ "UDPv6" $?sockets)))
	(process-with-udp $?proc_list)
	(test (member$ ?name1 $?proc_list))
	=>
	(assert (open-udp-socket
	    (name ?name1)
	    (pid ?pid)))
	(printout t " UDP sockets open for process " ?name1 crlf ))

(defrule identify-open-tcp-sockets
	(opened-files
	    (comm ?name1)
	    (pid ?pid)
	    (sock_files $?sockets))
	(or (test (member$ "TCP" $?sockets)) (test (member$ "TCPv6" $?sockets)))
	(process-with-tcp $?proc_list)
	(test (member$ ?name1 $?proc_list))
	=>
	(assert (open-tcp-socket
	    (name ?name1)
	    (pid ?pid)))
	(printout t " TCP socket open for process " ?name1 crlf))

;rule to identify high cpu utilization

(defrule identify-high-cpu-utilization_1
	(cpu_utilization
	    (comm ?name1)
	    (pid ?pid)
	    (utilization ?cpu))
	(not (exists ( per-process-cpu-utilization
			    (name ?name1)
			    (pid ?pid))))
	(test (not ( = ?cpu 0.0)))
	=>
	(assert (per-process-cpu-utilization
		    (name ?name1)
		    (pid ?pid)))
	(printout t " Initializing per process cpu utilization numbers for " ?name1 crlf))

(defrule identify-high-cpu-utilization_2
	?of <- (cpu_utilization
	       (comm ?name1)
	       (pid ?pid)
	       (utilization ?cpu))
	?f <- ( per-process-cpu-utilization
			    (name ?name1)
			    (pid ?pid)
			    (cpu ?utilization)
			    (count ?count))
	=>
	(bind ?utilization (+ ?utilization ?cpu))
	(bind ?count (+ ?count 1))
	(retract ?f)
	(retract ?of)
	(assert (per-process-cpu-utilization
			    (name ?name1)
			    (pid ?pid)
			    (cpu ?utilization)
			    (count ?count)))
	(save-facts "cpu_state_info.fac" visible per-process-cpu-utilization)
	(printout t "Adding the current cpu utilization value to the prevent value for " ?name1 crlf)
	(printout t "Sum of cpu utilization " ?utilization " for iteration " ?count crlf ))

; rules to deal with priviledge escalation
(defrule identify-privledge-escalation
    ( task-struct
	(comm ?name)
	(pid ?pid)
	(uid ?uid)
	(euid ?euid)
	(gid  ?gid)
	(egid ?egid)
	(parent_pid ?parent_pid))
    (or (test (= ?uid 0)) (test (= ?euid 0)))
    (process-run-as-root $?process-run-as-root)
    (test (not (member$ ?name $?process-run-as-root)))
    =>
    (assert (priv-escalated-process
		(name ?name)
		(pid ?pid)
		(parent_pid ?parent_pid)))
    (printout t " Process " ?name " with unauthorised root priv found" crlf))


;=================template  for recovery facts ===================================

;recovery fact template for unkown processes
(deftemplate unknown-process-recovery
	    (slot function-name (type STRING))
	    (multislot arg_list (type SYMBOL)))

(deftemplate unknown-process-recovery-prev-action
	    (slot prev_action (type SYMBOL))
	    (slot name (type STRING)))

;recovery fact template for unknown modules
(deftemplate unknown-module-recovery
	    (slot function-name (type STRING))
	    (multislot arg_list (type SYMBOL)))

(deftemplate unknown-module-recovery-prev-action
	    (slot prev_action (type SYMBOL))
	    (slot name (type STRING)))


;recovery fact template for tampered syscall
(deftemplate tampered-syscall-recovery
	    (slot function-name (type STRING))
	    (multislot arg_list (type SYMBOL)))

;recovery fact template for open UDP sockets
(deftemplate open-udp-socket-recovery
	    (slot function-name (type STRING))
	    (multislot arg_list (type SYMBOL)))

(deftemplate open-udp-socket-recovery-prev-action
	    (slot prev_action (type SYMBOL))
	    (slot name (type STRING))
	    (slot pid (type INTEGER)))

;recovery fact template for open TCP sockets
(deftemplate open-tcp-socket-recovery
	    (slot function-name (type STRING))
	    (multislot arg_list (type SYMBOL)))

(deftemplate open-tcp-socket-recovery-prev-action
	    (slot prev_action (type SYMBOL))
	    (slot name (type STRING))
	    (slot pid (type INTEGER)))

;recovery fact template for high cpu utilization
(deftemplate high-cpu-utilization-recovery
	    (slot function-name (type STRING))
	    (multislot arg_list (type SYMBOL))) 

; recovey fact template for priv escalation
(deftemplate priv-escalation-recovery
	    (slot function-name (type STRING))
	    (multislot arg_list (type SYMBOL)))
(deftemplate priv-escalation-recovery-prev-action
	    (slot prev_action (type SYMBOL))
	    (slot name (type STRING)))



