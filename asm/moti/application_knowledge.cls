
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
	(slot index (type INTEGER))
	(slot base_address (type INTEGER)))

(deftemplate hooked_sys_call
	(slot name (type STRING))
	(slot original (type INTEGER))
	(slot current (type INTEGER))
	(slot address (type INTEGER)))


(deftemplate command_line
	(slot command (type STRING))
	(slot environment (type STRING)))

;===========Users application level knowledge captured facts====================

(deftemplate known-objects
	(slot name (type STRING))
	(multislot object-list (type STRING)))
(deftemplate known-open-files
	(slot name (type STRING))
	(multislot file-names (type STRING)))

(deffacts base-facts
	(known-processes "swapper/0" "init" "kthreadd" "ksoftirqd/0" "kworker/0:0" 
	"kworker/0:0H" "kworker/u:0" "kworker/u:0H" "migration/0" "rcu_bh"
	"rcu_sched" "watchdog/0" "cpuset" "khelper" "kdevtmpfs" "netns" "xenwatch"
	"xenbus" "bdi-default" "kintegrityd" "kblockd" "ata_sff" "khubd" "md"
	"devfreq_wq" "kworker/0:1" "khungtaskd" "kswapd0" "ksmd" "fsnotify_mark"
	"ecryptfs-kthrea" "crypto" "kthrotld" "kworker/0:1" "khvcd" "binder" "deferwq"
	"charger_manager" "kworker/0:1H" "jbd2/xvda1-8" "ext4-dio-unwrit" "upstart-udev-br"
	"udevd" "rpcbind" "sshd" "upstart-socket-" "dbus-daemon" "rsyslogd" "cron"
	"atd" "mysqld" "ntpd" "getty" "flush-202:1" "apache2" "kworker/u:1" "login"
	"bash" "repair_submodul" "python" )
	
	(known-modules "coretemp" "microcode" "xenfs" "xen_privcmd" "parport")
	(process-with-udp "rpcbind" "ntpd" "mysqld")                 
	(process-with-tcp  "mysqld"  "rpcbind" "sshd" "ntpd") 
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
	"atd" "ntpd" "getty" "flush-202:1" "login" "bash" "apache2" "kworker/u:1" "repair_submodul" "python")

;	(known-objects
;	    (name "bash")
;	    (object-list  "bash"  "libnss_files-2.15.so"    
;	    "libnss_nis-2.15.so"  "libnsl-2.15.so" 
;	    "libnss_compat-2.15.so"  "locale-archive"  "libc-2.15.so"
;	    "libdl-2.15.so" "libtinfo.so.5.9" "ld-2.15.so")) ;ld-2.15.so
	(known-objects 
    		    	( name "test")
      		    	( object-list  "libc-2.15.so"  "ld-2.15.so"  ));test
	(known-objects
	    (name "apache2")
	    (object-list "libnss_files-2.15.so" "libnss_nis-2.15.so" "libnsl-2.15.so"  "libnss_compat-2.15.so" "mod_status.so"  "mod_setenvif.so"   "mod_reqtimeout.so"  "mod_negotiation.so" "mod_env.so" "mod_dir.so" "libz.so.1.2.3.4" "mod_deflate.so" "mod_autoindex.so" "mod_authz_user.so" "mod_authz_host.so" "mod_authz_groupfile.so" "mod_authz_default.so" "mod_authn_file.so"  "mod_auth_basic.so" "mod_alias.so"  "libdl-2.15.so" "libuuid.so.1.3.0"
	    "libexpat.so.1.5.2"   "libcrypt-2.15.so"  "libc-2.15.so"  "libpthread-2.15.so"  "libapr-1.so.0.4.6"   "libaprutil-1.so.0.3.12"   "libpcre.so.3.12.1"  "ld-2.15.so"  "dev/zero"  "ld-2.15.so" "libgcc_s.so.1" "mod_mime.so" "mod_cgid.so" ));apache2
;	
;	(known-open-files
;	    (name "mysqld")
;	    (file-names "ibdata1"  "ibrXE6sH"  "ibpAJ2Qg"
;	    "ibbc3YeQ"  "ibgGvhIp"  "ib_logfile0"  "ib_logfile1"  "ibBj4eXZ"  "host.MYI"  "host.MYD"  "user.MYI"
;	    "user.MYD"  "db.MYI"  "db.MYD"  "proxies_priv.MYI"  "proxies_priv.MYD"  "tables_priv.MYI"
;	    "tables_priv.MYD"  "columns_priv.MYI"  "columns_priv.MYD"  "procs_priv.MYI"  "procs_priv.MYD"
;	    "servers.MYI"  "servers.MYD"  "event.MYI"  "event.MYD"  "proc.MYI"  "proc.MYD"  "func.MYI"
;	    "func.MYD"  "general_log.CSM"  "general_log.CSV"  "help_category.MYI"  "help_category.MYD"
;	    "help_keyword.MYI"  "help_keyword.MYD"  "help_relation.MYI"  "help_relation.MYD"  "help_topic.MYI"
;	    "help_topic.MYD"  "ndb_binlog_index.MYI"  "ndb_binlog_index.MYD"  "plugin.MYI"  "plugin.MYD"
;	    "slow_log.CSM"  "slow_log.CSV"  "time_zone.MYI"  "time_zone.MYD"  "time_zone_leap_second.MYI"
;	    "time_zone_leap_second.MYD"  "time_zone_name.MYI"  "time_zone_name.MYD" 
;	    "time_zone_transition.MYI"  "time_zone_transition.MYD"  "time_zone_transition_type.MYI"
;	    "time_zone_transition_type.MYD " "ibdXzyvI" "ibllKoER" "ibhfBa90" "ibdsC3Ha" "ibXM1Wgk" 
;	     "error.log"))
       
       (known-open-files
	    (name "perl")
	    (file-names "temp"))
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
	(slot original (type INTEGER))
	(slot base_address (type INTEGER)))

(deftemplate hooked-syscall
	(slot name (type STRING))
	(slot address (type INTEGER))
	(slot original (type STRING)))


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

(deftemplate unknown-object-list
	(slot name (type STRING))
	(slot pid (type INTEGER))
	(multislot object-list (type STRING) (default "NULL")))

(deftemplate unknown-open-files
	(slot name (type STRING))
	(slot pid (type INTEGER))
	(slot file (type STRING)))


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
	(printout t "ANOMALY: Unknown process " ?name1 " found" crlf) )

;rule to detect any unknown module that is loaded
(defrule identify-unknown-module
	(loaded-module (name ?name1))
	(known-modules $?name2)
	(test (not (member$ ?name1 $?name2)))
	=>
	(assert (unknown-module (name ?name1)))
	(printout t "ANOMALY: Unknown module " ?name1 "found" crlf)) 

;rule to check for tampered syscall table entries
(defrule identify-tampered-syscall
	(tampered_sys_call
	    (name ?name1)
	    (index ?index)
	    (original ?address)
	    (base_address ?base_address))
	=>
	(assert (tampered-syscall
	    (name ?name1)
	    (index ?index)
	    (original ?address)
	    (base_address ?base_address)))
	(printout t "ANOMALY: Tampered system call " ?name1 " found at offset " ?index crlf))

;rule to check for hooked syscall table entries
(defrule identify-hooked-syscall
	(hooked_sys_call
	    (name ?name1)
	    (address ?address)
	    (original ?bytes))
	=>
	(assert (hooked-syscall
	    (name ?name1)
	    (address ?address)
	    (original ?bytes)))
	(printout t "ANOMALY: Hooked system call " ?name1 " found at address " ?address crlf))


;rule to check fo unauthorised TCP/UDP sockets
(defrule identify-open-udp-sockets
	(opened-files
	    (comm ?name1)
	    (pid ?pid)
	    (sock_files $?sockets))
	(or (test(member$ "UDP" $?sockets)) (test (member$ "UDPv6" $?sockets)))
	(process-with-udp $?proc_list)
	(not (test (member$ ?name1 $?proc_list)))
	=>
	(assert (open-udp-socket
	    (name ?name1)
	    (pid ?pid)))
	(printout t "ANOMALY: UDP sockets open for process " ?name1 crlf ))

(defrule identify-open-tcp-sockets
	(opened-files
	    (comm ?name1)
	    (pid ?pid)
	    (sock_files $?sockets))
	(or (test (member$ "TCP" $?sockets)) (test (member$ "TCPv6" $?sockets)))
	(process-with-tcp $?proc_list)
	(not (test (member$ ?name1 $?proc_list)))
	=>
	(assert (open-tcp-socket
	    (name ?name1)
	    (pid ?pid)))
	(printout t "ANOMALY: TCP socket open for process " ?name1 crlf))

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
	(printout t "ANOMALY: Initializing per process cpu utilization numbers for " ?name1 crlf))

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
	(save-facts "state_information/cpu_state_info.fac" visible per-process-cpu-utilization)
	(printout t "ANOMALY: Adding the current cpu utilization value to the previous value for " ?name1 crlf)
	(printout t "ANOMALY: Sum of cpu utilization " ?utilization " for iteration " ?count crlf ))

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
    (printout t "ANOMALY: Process " ?name " with unauthorised root priv found" crlf))

;rules to identify unknown objects loded for processes.
(defrule identify-unknown-loaded-objects
    (loaded-objects
	(comm ?name)
	(pid ?pid)
	(objects $?objects))
    (known-objects
	(name ?name)
	(object-list $?known_objects))
    (test (not (subsetp $?objects $?known_objects)))
    (not (exists (unknown-object-list
	(name ?name)
	(pid ?pid))))
    =>
    (assert ( unknown-object-list
		(name ?name)
		(pid ?pid)))
    (printout t "ANOMALY: Unknown objects found for process " ?name crlf))

(defrule identify-unknown-objects_1
     ?of <- (loaded-objects
	(comm ?name)
	(pid ?pid)
	(objects $?objects))
    (known-objects
	(name ?name)
	(object-list $?known_objects))
    (test (not (subsetp $?objects $?known_objects)))
    ?f <- (unknown-object-list
	    (name ?name)
	    (pid ?pid)
	    (object-list $?list))
    =>
    (progn$ (?field  $?objects)
	(if (not ( member$ ?field $?known_objects))
		 then 
		 (bind $?list  (insert$ $?list 1 ?field))))
	(modify ?f (object-list $?list))
	(retract ?of)
    (printout t "ANOMALY: Inserted the unknown object name into the list " crlf ))
	    	    

;rules to identify unknown files opened by processes
(defrule identify-unknown-open-files
    (opened-files
	(comm ?name)
	(pid ?pid)
	(reg_files $?file_names))
    (known-open-files
	(name ?name)
	(file-names $?known_files))
    =>
    (progn$ (?field  $?file_names)
	(if (not ( member$ ?field $?known_files))
		 then 
		 (assert(unknown-open-files
			    (name ?name)
			    (pid ?pid)
			    (file ?field)))
		(printout t "ANOMALY: Unknown open file found for  process " ?name ?field crlf))))


;=================template  for recovery facts ===================================

;A common recovery fact template for all receovery actions
(deftemplate recovery-action
	    (slot function-name (type SYMBOL))
	    (multislot arg_list (type SYMBOL)))

(deftemplate unknown-process-recovery-prev-action
	    (slot prev_action (type SYMBOL))
	    (slot name (type STRING)))


(deftemplate unknown-module-recovery-prev-action
	    (slot prev_action (type SYMBOL))
	    (slot name (type STRING)))


(deftemplate open-udp-socket-recovery-prev-action
	    (slot prev_action (type SYMBOL))
	    (slot name (type STRING))
	    (slot pid (type INTEGER)))


(deftemplate open-tcp-socket-recovery-prev-action
	    (slot prev_action (type SYMBOL))
	    (slot name (type STRING))
	    (slot pid (type INTEGER)))


(deftemplate priv-escalation-recovery-prev-action
	    (slot prev_action (type SYMBOL))
	    (slot name (type STRING)))








