
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

(deftemplate loaded-modules
	(multislot name (type STRING)))

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
	"atd" "mysqld" "ntpd" "getty" "flush-202:1"))


;============================== Template for anomaly facts =============================

	
(deftemplate unknown-process
	(slot name (type STRING))
	(slot pid (type INTEGER)))


;========== Application level rules that are used to detect anomalies =================


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


;=================template  for recovery facts ===================================

(deftemplate unknown-process-recovery
	    (slot function-name (type STRING))
	    (multislot arg_list (type SYMBOL)))

(deftemplate unknown-process-recovery-prev-action
	    (slot prev_action (type SYMBOL))
	    (slot name (type STRING)))





