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
     (slot original-0-8 (type STRING))
     (slot original-8-16 (type STRING))
     (slot address (type STRING)))


(deftemplate command_line
     (slot command (type STRING))
     (slot environment (type STRING)))


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
     (slot address (type STRING))
     (slot original-0-8 (type STRING))
     (slot original-8-16 (type STRING)))


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
    
(deftemplate wrong-process-cred
     (slot name (type STRING))
     (slot pid (type INTEGER))
     (slot uid (type INTEGER))
     (slot gid (type INTEGER)))

(deftemplate wrong-process-hierarchies
     (slot name (type STRING))
     (slot pid (type INTEGER)))

(deftemplate missing-process
     (slot name (type STRING))
     (multislot command (type SYMBOL)))

(deftemplate root-shells
     (slot name (type STRING))
     (slot pid (type INTEGER)))

(deftemplate root-shells
     (slot name (type STRING))
     (slot pid (type INTEGER)))

;=================templates  for recovery facts ===================================

    ;A common recovery fact template for all receovery actions
(deftemplate recovery-action
     (slot function-name (type SYMBOL))
     (multislot arg_list (type SYMBOL)))

(deftemplate handle-multiple-threads
     (slot name (type STRING))
     (slot stage (type SYMBOL)))

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


;(deftemplate priv-escalation-recovery-prev-action
;    (slot prev_action (type SYMBOL))
;     (slot name (type STRING)))

(deftemplate wrong-proc-cred-prev-action
      (slot prev_action (type SYMBOL))
      (slot name (type STRING)))

(deftemplate unload-unknown-object-prev-action
      (slot name (type STRING))
      (slot pid (type INTEGER))
      (slot prev_action (type SYMBOL)))

;=================Templates for application level facts=======================

(deftemplate known-objects
     (slot name (type STRING))
     (multislot object-list (type STRING)))

(deftemplate known-object-regex
     (slot name (type STRING))
     (slot object-regex (type STRING)))

(deftemplate known-open-files
     (slot name (type STRING))
     (multislot file-names (type STRING)))
    
(deftemplate known-process-cred
     (slot name (type STRING))
     (multislot uid (type INTEGER))
     (multislot euid (type INTEGER))
     (multislot suid (type INTEGER))
     (multislot fsuid (type INTEGER))
     (multislot gid (type INTEGER))
     (multislot egid (type INTEGER))
     (multislot sgid (type INTEGER))
     (multislot fsgid (type INTEGER))
     (multislot parent_name (type STRING)))

(deftemplate mandatory-process
     (slot name (type STRING))
     (multislot command (type SYMBOL))) 



;========== Application level rules that are used to detect anomalies =================

    ;=========rule to detect any unkown process that is executing======
    (defrule identify-unknown-process
    (task-struct (comm ?name1)
	(pid ?pid))
    (known-processes $?name2)
    (test (not( member$ ?name1 $?name2)))
     =>
    (assert (unknown-process
		(name ?name1)
		(pid ?pid)))
    (printout t "ANOMALY: Unknown process " ?name1 " found" crlf))

 
    ;======rule to detect a known process with wrong credentials========
    (defrule identify-wrong-process-cred
    (task-struct (comm ?name1)
		 (pid ?pid1)
		 (uid ?uid1)
		 (gid ?gid1))
    (known-process-cred
		  (name ?name1)
		  (uid $?uid2)
		  (gid $?gid2))
    (test (or (not ( member$ ?uid1 $?uid2)) (not ( member$ ?gid1 $?gid2))))
     =>
    (assert(wrong-process-cred
		 (name ?name1)
		 (pid ?pid1)
		 (uid (nth$ 1 $?uid2))
		 (gid (nth$ 1 $?gid2))))
     (printout t "ANOMALY: Process " ?name1 " has wrong uid: "?uid1 ": gid " ?gid1 ".Expected uid " (nth$ 1 $?gid2) " gid " (nth$ 1 $?gid2) crlf))
    

    ;========rule to detect any unknown module that is loaded=============
    (defrule identify-unknown-module
    (loaded-module (name ?name1))
    (known-modules $?name2)
    (test (not (member$ ?name1 $?name2)))
     =>
    (assert (unknown-module (name ?name1)))
    (printout t "ANOMALY: Unknown module " ?name1 "found" crlf)) 

    ;=======rule to check for tampered syscall table entries=============
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

    ;==========rule to check for hooked syscall table entries===========
    (defrule identify-hooked-syscall
    (hooked_sys_call
	(name ?name1)
	(address ?address)
	(original-0-8 ?bytes1)
	(original-8-16 ?bytes2))
    =>
    (assert (hooked-syscall
	    (name ?name1)
	    (address ?address)
	    (original-0-8 ?bytes1)
	    (original-8-16 ?bytes2)))
    (printout t "ANOMALY: Hooked system call " ?name1 " found at address " ?address crlf))


    ;========rule to check fo unauthorised TCP/UDP sockets===========
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

    ;===========rule to identify high cpu utilization================
    (defrule identify-high-cpu-utilization_1
    (cpu_utilization
	(comm ?name1)
	(pid ?pid)
	(utilization ?cpu))
    (not (exists (per-process-cpu-utilization
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


     ;=========rules to identify unknown objects loded for processes.=========
    (defrule identify-unknown-loaded-objects
    (loaded-objects
	(comm ?name)
	(pid ?pid)
	(objects $?objects))
    (known-objects
	(name ?name)
	(object-list $?known_objects))
    (test (not (subsetp $?objects $?known_objects)))
    (known-object-regex
	(name ?name)
	(object-regex ?regex))
    (not (exists (unknown-object-list
		   (name ?name)
		   (pid ?pid))))
     =>
    (progn$ (?field  $?objects)
    (if (and (not ( member$ ?field $?known_objects))
	     (not (str-index ?regex ?field)))  
    then
	(assert ( unknown-object-list
		    (name ?name)
		    (pid ?pid))))))

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
    (known-object-regex
	(name ?name)
	(object-regex ?regex))
     =>
    (progn$ (?field  $?objects)
    (if (and (not ( member$ ?field $?known_objects))
	      (not (str-index ?regex ?field))) 
    then
	(printout t "ANOMALY: Unknown object " ?field " found for process " ?name crlf)
	(bind $?list  (insert$ $?list 1 ?field))))
    (modify ?f (object-list $?list))
    (retract ?of))


    ;========rules to identify unknown files opened by processes==========
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


    ;=========rules to identify wrong process hierarchies============= 
    (defrule identify-wrong-process-hierarchies
    (task-struct (comm ?name1)
		  (pid ?pid1)
		  (parent_name ?parent_name))
    (known-process-cred
		  (name ?name1)
		  (parent_name $?parent))
    (test (not ( member$ ?parent_name $?parent)))
    =>
    (assert(unknown-process
		 (name ?name1)
		 (pid ?pid1)))
    (printout t "ANOMALY: Process " ?name1 " has wrong parent:" ?parent_name  crlf))



    ;============rule to make sure all the mandatory process are executing=========
    (defrule identify-missing-process
    (mandatory-process (name ?name)
		       (command $?command))
    (not (exists(task-struct (comm ?name))))
     =>
    (assert (missing-process
		(name ?name)
		(command $?command)))
    (printout t "ANOMALY: Process " ?name " not found." crlf))

     ;===========rule to check for root shells spawne from non root processes========
     (defrule identify-root-shells
     (task-struct (comm ?name1)
		  (pid ?pid)
		  (parent_pid ?ppid) 
		  (uid ?uid))
     (task-struct (pid ?ppid)
                  (uid ?puid))
     (and (test(= ?uid 0)) (test(!= ?puid 0)))
     (test (member$ ?name1 (create$ "bash" "sh" "csh" "-bash" "-csh" "-sh")))
     =>
     (assert (root-shells
	     (name ?name1)
	     (pid ?pid)))
     (printout t "ANOMALY: Root shell " ?name1 " found with pid" ?pid  crlf))

     ;=============rule to check for invalid su command usage.================
     (defrule validate-su-processes
     (task-struct (comm ?name1)
		  (pid ?pid)
		  (parent_pid ?ppid))
     (test (member$ ?name1 (create$ "su")))
     (task-struct (pid ?ppid)
                  (uid ?puid))
     (users-with-su-priv $?su_users)
     (test(not (member$ ?puid $?su_users)))
     =>
     (assert (unknown-process
     (pid ?pid)))
     (printout t "ANOMALY: Unauthorised su process found" ?pid  crlf))





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
      "atd" "mysqld" "ntpd" "getty" "flush-202:1" "apache2" "kworker/u:1" "login"
      "bash" "repair_submodul" "python" "perl" "httpd" "sh" "su" "helper")
     
     (mandatory-process 
	(name "apache2")
	(command /usr/bin/sudo /etc/init.d/apache2 start HOME=/ TERM=linux /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)) 

     (mandatory-process 
	(name "sshd")
	(command /usr/bin/sudo /usr/sbin/sshd  HOME=/ TERM=linux /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)) 

     (known-modules "coretemp" "microcode" "xenfs" "xen_privcmd" "parport" "lp" "repair_driver" "sled_object_module" "psaction_module" "close_file_module" "killsocket_module" "start_process_module" "sled_object_module")
     (process-with-udp "rpcbind" "ntpd" "mysqld" "apache2")                 
     (process-with-tcp  "mysqld"  "rpcbind" "sshd" "ntpd" "apache2") 
     (process-with-reg-files-opened "rpcbind" "rsyslogd" "ntpd" "cron" "atd" "mysqld" "udevd")
     (high-priority-process "apache" "sshd")
     (med-priority-process  "mysqld" "ntpd" )
     (low-priority-process  "perl" "temp")
     (users-with-su-priv 1001)

     (process-run-as-root "swapper/0" "init" "kthreadd" "ksoftirqd/0" "kworker/0:0" 
      "kworker/0:0H" "kworker/u:0" "kworker/u:0H" "migration/0" "rcu_bh"
      "rcu_sched" "watchdog/0" "cpuset" "khelper" "kdevtmpfs" "netns" "xenwatch"
      "xenbus" "bdi-default" "kintegrityd" "kblockd" "ata_sff" "khubd" "md"
      "devfreq_wq" "kworker/0:1" "khungtaskd" "kswapd0" "ksmd" "fsnotify_mark"
      "ecryptfs-kthrea" "crypto" "kthrotld" "kworker/0:1" "khvcd" "binder" "deferwq"
      "charger_manager" "kworker/0:1H" "jbd2/xvda1-8" "ext4-dio-unwrit" "upstart-udev-br"
      "udevd" "rpcbind" "sshd" "upstart-socket-"  "cron"
      "atd" "ntpd" "getty" "flush-202:1" "login" "bash" "apache2" "kworker/u:1" "repair_submodul" "python")


     (known-objects 
    	( name "init")
      	( object-list  "libnss_files-2.15.so"  "libnss_nis-2.15.so"  "libnsl-2.15.so"  "libnss_compat-2.15.so"  "libc-2.15.so"  "librt-2.15.so"  "libpthread-2.15.so"  "libdbus-1.so.3.5.8"  "libnih-dbus.so.1.0.0"  "libnih.so.1.0.0"  "ld-2.15.so"  "init"  ))

;; NOTE: NO smart pattern matching is going on here. We just match the constant
;;       part of the string.
    (known-object-regex
	(name "init")
	(object-regex "NULL"))
 
     (known-objects 
    	( name "upstart-udev-br")
      	( object-list  "librt-2.15.so"  "libc-2.15.so"  "libudev.so.0.13.0"  "libpthread-2.15.so"  "libdbus-1.so.3.5.8"  "libnih-dbus.so.1.0.0"  "libnih.so.1.0.0"  "ld-2.15.so"  "upstart-udev-bridge"  ))

    (known-object-regex
	(name "spstart-udev-br")
	(object-regex "NULL"))

      (known-objects 
    	( name "udevd")
      	( object-list  "libnss_files-2.15.so"  "libnss_nis-2.15.so"  "libnsl-2.15.so"  "libnss_compat-2.15.so"  "libpthread-2.15.so"  "libdl-2.15.so"  "libc-2.15.so"  "librt-2.15.so"  "libselinux.so.1"  "ld-2.15.so"  "udevd"  ))

    (known-object-regex
	(name "udevd")
	(object-regex "NULL"))

     (known-objects 
	( name "upstart-socket-")
      	( object-list  "librt-2.15.so"  "libc-2.15.so"  "libpthread-2.15.so"  "libdbus-1.so.3.5.8"  "libnih-dbus.so.1.0.0"  "libnih.so.1.0.0"  "ld-2.15.so"  "upstart-socket-bridge"  ))

    (known-object-regex
	(name "upstart-socket-")
	(object-regex "NULL"))

     (known-objects 
    	( name "dbus-daemon")
      	( object-list  "libnss_files-2.15.so"  "libnss_nis-2.15.so"  "libnsl-2.15.so"  "libnss_compat-2.15.so"  "libdl-2.15.so"  "libc-2.15.so"  "librt-2.15.so"  "libpthread-2.15.so"  "libselinux.so.1"  "libexpat.so.1.5.2"  "ld-2.15.so"  "dbus-daemon"  ))

    (known-object-regex
	(name "dbus-daemon")
	(object-regex "NULL"))

     (known-objects 
    	( name "rpcbind")
      	( object-list  "rpcbind"  "libnss_files-2.15.so"  "libdl-2.15.so"  "libgssglue.so.1.0.0"  "libnsl-2.15.so"  "libc-2.15.so"  "libpthread-2.15.so"  "libtirpc.so.1.0.10"  "libwrap.so.0.7.6"  "ld-2.15.so"  ))

    (known-object-regex
	(name "rpcbind")
	(object-regex "NULL"))

     (known-objects 
    	( name "rsyslogd")
      	( object-list  "rsyslogd"  "libnss_nis-2.15.so"  "libnsl-2.15.so"  "libnss_compat-2.15.so"  "imklog.so"  "imuxsock.so"  "libnss_files-2.15.so"  "lmnet.so"  "libc-2.15.so"  "librt-2.15.so"  "libdl-2.15.so"  "libpthread-2.15.so"  "libz.so.1.2.3.4"  "ld-2.15.so"  ))

    (known-object-regex
	(name "rsyslogd")
	(object-regex "NULL"))

     (known-objects 
    	( name "cron")
      	( object-list  "cron"  "libnss_files-2.15.so"  "libnss_nis-2.15.so"  "libnsl-2.15.so"  "libnss_compat-2.15.so"  "libdl-2.15.so"  "libc-2.15.so"  "libselinux.so.1"  "libpam.so.0.83.0"  "ld-2.15.so"  ))
 
    (known-object-regex
	(name "cron")
	(object-regex "NULL"))

     (known-objects 
    	( name "atd")
      	( object-list  "atd"  "libnss_files-2.15.so"  "libnss_nis-2.15.so"  "libnsl-2.15.so"  "libnss_compat-2.15.so"  "libdl-2.15.so"  "libc-2.15.so"  "libpam.so.0.83.0"  "ld-2.15.so"  ))

    (known-object-regex
	(name "atd")
	(object-regex "NULL"))

     (known-objects 
    	( name "mysqld")
	( object-list  "libnss_files-2.15.so"  "libnss_nis-2.15.so"  "libnss_compat-2.15.so"  "libgcc_s.so.1"  "libnsl-2.15.so"  "libc-2.15.so"  "libm-2.15.so"  "libstdc++.so.6.0.16"  "libpthread-2.15.so"  "libdl-2.15.so"  "libcrypt-2.15.so"  "libwrap.so.0.7.6"  "librt-2.15.so"  "libz.so.1.2.3.4"  "ld-2.15.so"  "mysqld"  ))

    (known-object-regex
	(name "mysqld")
	(object-regex "NULL"))

     (known-objects 
    	( name "login")
      	( object-list  "login"  "libnss_files-2.15.so"  "libnss_nis-2.15.so"  "libnss_compat-2.15.so"  "pam_umask.so"  "pam_mail.so"  "pam_motd.so"  "libutil-2.15.so"  "pam_lastlog.so"  "pam_limits.so"  "pam_group.so"  "pam_permit.so"  "pam_deny.so"  "libcrypt-2.15.so"  "libnsl-2.15.so"  "pam_unix.so"  "pam_env.so"  "libselinux.so.1"  "pam_selinux.so"  "pam_nologin.so"  "pam_securetty.so"  "pam_faildelay.so"  "libdl-2.15.so"  "libc-2.15.so"  "libpam_misc.so.0.82.0"  "libpam.so.0.83.0"  "ld-2.15.so"  "libpam.so.0.83.0"))
 
    (known-object-regex
	(name "login")
	(object-regex "NULL"))
   
     (known-objects 
    	( name "bash")
	( object-list  "bash"  "libnss_files-2.15.so"  "libnss_nis-2.15.so"  "libnsl-2.15.so"  "libnss_compat-2.15.so"  "locale-archive"  "libc-2.15.so"  "libdl-2.15.so"  "libtinfo.so.5.9"  "ld-2.15.so"  "gconv-modules.cache"  "ld-2.15.so" "libutil-2.15.so" ))

    (known-object-regex
	(name "bash")
	(object-regex "NULL"))

     (known-objects 
    	( name "httpd")
      	( object-list  "httpd"  "libnss_files-2.15.so"  "libnss_nis-2.15.so"  "libnsl-2.15.so"  "libnss_compat-2.15.so"  "libm-2.15.so"  "mod_uni_mem.so"  "mod_rewrite.so"  "mod_alias.so"  "mod_userdir.so"  "mod_speling.so"  "mod_actions.so"  "mod_imagemap.so"  "mod_dir.so"  "mod_negotiation.so"  "mod_vhost_alias.so"  "mod_dav_fs.so"  "mod_cgi.so"  "mod_info.so"  "mod_asis.so"  "mod_autoindex.so"  "mod_status.so"  "mod_dav.so"  "mod_mime.so"  "mod_proxy_balancer.so"  "mod_proxy_ajp.so"  "mod_proxy_scgi.so"  "mod_proxy_http.so"  "mod_proxy_ftp.so"  "mod_proxy_connect.so"  "mod_proxy.so"  "mod_version.so"  "mod_setenvif.so"  "mod_unique_id.so"  "mod_usertrack.so"  "mod_ident.so"  "mod_headers.so"  "mod_expires.so"  "mod_cern_meta.so"  "mod_mime_magic.so"  "mod_env.so"  "mod_logio.so"  "mod_log_forensic.so"  "mod_log_config.so"  "libz.so.1.2.3.4"  "mod_deflate.so"  "mod_substitute.so"  "mod_filter.so"  "mod_include.so"  "mod_ext_filter.so"  "mod_reqtimeout.so"  "mod_dumpio.so"  "mod_dbd.so"  "mod_auth_digest.so"  "mod_auth_basic.so"  "mod_authz_default.so"  "mod_authz_owner.so"  "mod_authz_dbm.so"  "mod_authz_user.so"  "mod_authz_groupfile.so"  "mod_authz_host.so"  "mod_authn_default.so"  "mod_authn_dbd.so"  "mod_authn_anon.so"  "mod_authn_dbm.so"  "mod_authn_file.so"  "libdl-2.15.so"  "libcrypt-2.15.so"  "libexpat.so.0.5.0"  "libc-2.15.so"  "libpthread-2.15.so"  "libapr-1.so.0.4.5"  "libaprutil-1.so.0.4.1"  "ld-2.15.so"  "dev/zero"  "ld-2.15.so"  ))

    (known-object-regex
	(name "httpd")
	(object-regex "NULL"))
   
     (known-objects 
    	( name "sshd")
      	( object-list  "libnss_files-2.15.so"  "libnss_nis-2.15.so"  "libnss_compat-2.15.so"  "libresolv-2.15.so"  "libkeyutils.so.1.4"  "libkrb5support.so.0.1"  "libk5crypto.so.3.1"  "libdl-2.15.so"  "libnsl-2.15.so"  "libc-2.15.so"  "libcom_err.so.2.1"  "libkrb5.so.3.3"  "libgssapi_krb5.so.2.2"  "libcrypt-2.15.so"  "libz.so.1.2.3.4"  "libutil-2.15.so"  "libcrypto.so.1.0.0"  "libpthread-2.15.so"  "libselinux.so.1"  "libpam.so.0.83.0"  "libwrap.so.0.7.6"  "ld-2.15.so"  "sshd"  ))

    (known-object-regex
	(name "sshd")
	(object-regex "NULL"))

     (known-objects 
    	( name "ntpd")
      	( object-list  "libnss_nis-2.15.so"  "libnsl-2.15.so"  "libnss_compat-2.15.so"  "libresolv-2.15.so"  "libnss_dns-2.15.so"  "libnss_files-2.15.so"  "libpthread-2.15.so"  "libc-2.15.so"  "libcap.so.2.22"  "librt-2.15.so"  "libm-2.15.so"  "libopts.so.25.10.0"  "ld-2.15.so"  "ntpd"  ))

    (known-object-regex
	(name "ntpd")
	(object-regex "NULL"))

     (known-objects 
    	( name "apache2")
      	( object-list  "apache2"  "libnss_files-2.15.so"  "libnss_nis-2.15.so"  "libnsl-2.15.so"  "libnss_compat-2.15.so"  "libm-2.15.so"  "mod_rewrite.so"  "mod_alias.so"  "mod_userdir.so"  "mod_speling.so"  "mod_actions.so"  "mod_imagemap.so"  "mod_dir.so"  "mod_negotiation.so"  "mod_vhost_alias.so"  "mod_dav_fs.so"  "mod_cgi.so"  "mod_info.so"  "mod_asis.so"  "mod_autoindex.so"  "mod_status.so"  "mod_dav.so"  "mod_mime.so"  "mod_proxy_balancer.so"  "mod_proxy_ajp.so"  "mod_proxy_scgi.so"  "mod_proxy_http.so"  "mod_proxy_ftp.so"  "mod_proxy_connect.so"  "mod_proxy.so"  "mod_version.so"  "mod_setenvif.so"  "mod_unique_id.so"  "mod_usertrack.so"  "mod_ident.so"  "mod_headers.so"  "mod_expires.so"  "mod_cern_meta.so"  "mod_mime_magic.so"  "mod_env.so"  "mod_logio.so"  "mod_log_forensic.so"  "mod_log_config.so"  "libz.so.1.2.3.4"  "mod_deflate.so"  "mod_substitute.so"  "mod_filter.so"  "mod_include.so"  "mod_ext_filter.so"  "mod_reqtimeout.so"  "mod_dumpio.so"  "mod_dbd.so"  "mod_auth_digest.so"  "mod_auth_basic.so"  "mod_authz_default.so"  "mod_authz_owner.so"  "mod_authz_dbm.so"  "mod_authz_user.so"  "mod_authz_groupfile.so"  "mod_authz_host.so"  "mod_authn_default.so"  "mod_authn_dbd.so"  "mod_authn_anon.so"  "mod_authn_dbm.so"  "mod_authn_file.so"  "libdl-2.15.so"  "libcrypt-2.15.so"  "libexpat.so.0.5.0"  "libc-2.15.so"  "libpthread-2.15.so"  "libapr-1.so.0.4.5"  "libaprutil-1.so.0.4.1"  "ld-2.15.so"  "dev/zero"  "ld-2.15.so" "libgcc_s.so.1" "mod_cgid.so" "libuuid.so.1.3.0" "libexpat.so.1.5.2" "libapr-1.so.0.4.6" "libaprutil-1.so.0.3.12" "libpcre.so.3.12.1" ))

    (known-object-regex
	(name "apache2")
	(object-regex "SYSSV"))


     ;(known-open-files
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

    (known-process-cred
      (name "swapper/0")
      (uid 0)
      (euid 0)
      (suid 0)
      (fsuid 0)
      (gid 0)
      (egid 0)
      (sgid 0)
      (fsgid 0)
      (parent_name "swapper/0"))

    (known-process-cred
     (name "init")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "swapper/0"))

    (known-process-cred 
     (name "kthreadd")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "swapper/0"))

    (known-process-cred  
     (name "ksoftirqd/0")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "kworker/0:0")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "kworker/0:0H")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "kworker/u:0")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "kworker/u:0H")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "migration/0")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "rcu_bh")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "rcu_sched")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "watchdog/0")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "cpuset")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "khelper")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "kdevtmpfs")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "netns")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "xenwatch")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "xenbus")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "bdi-default")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "kintegrityd")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "kblockd")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "ata_sff")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "khubd")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "md")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name  "devfreq_wq")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "kworker/0:1")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "khungtaskd")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "kswapd0")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "ksmd")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "fsnotify_mark")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "ecryptfs-kthrea")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "crypto")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "kthrotld")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "kworker/u:1")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "khvcd")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "binder")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "deferwq")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "charger_manager")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "kworker/0:1H")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "kworker/0:1")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "jbd2/xvda1-8")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "ext4-dio-unwrit")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "upstart-udev-br")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "init"))

    (known-process-cred  
     (name "udevd")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "init" "udevd"))

     (known-process-cred   
      (name "upstart-socket-")
      (uid 0)
      (euid 0)
      (suid 0)
      (fsuid 0)
      (gid 0)
      (egid 0)
      (sgid 0)
      (fsgid 0)
      (parent_name "init"))

    (known-process-cred  
     (name "rpcbind")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "init"))

    (known-process-cred  
     (name "sshd")
     (uid 0 1001)
     (euid 0 1001)
     (suid 0 1001)
     (fsuid 0 1001)
     (gid 0 1001)
     (egid 0 1001)
     (sgid 0 1001)
     (fsgid 0 1001)
     (parent_name "init" "sshd"))


    (known-process-cred  
     (name "rsyslogd")
     (uid 101)
     (euid 101)
     (suid 101)
     (fsuid 101)
     (gid 103)
     (egid 103)
     (sgid 103)
     (fsgid 103)
     (parent_name "init"))

    (known-process-cred  
     (name "dbus-daemon")
     (uid 106)
     (euid 106)
     (suid 106)
     (fsuid 106)
     (gid 114)
     (egid 114)
     (sgid 114)
     (fsgid 114)
     (parent_name "init"))

    (known-process-cred  
     (name "ntpd")
     (uid 0 104)
     (euid 0 104)
     (suid 0 104)
     (fsuid 0 104)
     (gid 0 110)
     (egid 0 110)
     (sgid 0 110)
     (fsgid 0 110)
     (parent_name "init" "ntpd"))


    (known-process-cred  
     (name "cron")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "init"))

    (known-process-cred  
     (name "atd")
     (uid 0)
     (euid 1)
     (suid 1)
     (fsuid 1)
     (gid 0)
     (egid 1)
     (sgid 1)
     (fsgid 1)
     (parent_name "init"))

    (known-process-cred  
      (name "mysqld")
      (uid 108)
      (euid 108)
      (suid 108)
      (fsuid 108)
      (gid 120)
      (egid 120)
      (sgid 120)
      (fsgid 120)
      (parent_name "init"))

     (known-process-cred  
      (name "apache2")
      (uid 0 33)
      (euid 0 33)
      (suid 0 33)
      (fsuid 0 33)
      (gid 0 33)
      (egid 0 33)
      (sgid 0 33)
      (fsgid 0 33)
      (parent_name "init" "apache2" "sudo"))

    (known-process-cred  
     (name "login")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "init"))

    (known-process-cred  
     (name "flush-202:1")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "bash")
     (uid 0 1001)
     (euid 0 1001)
     (suid 0 1001)
     (fsuid 0 1001)
     (gid 0 1001)
     (egid 0 1001)
     (sgid 0 1001)
     (fsgid 0 1001)
     (parent_name "login" "sshd"))

    (known-process-cred  
     (name "repair_submodul")
     (uid 0)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 0)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "kthreadd"))

    (known-process-cred  
     (name "perl")
     (uid 444)
     (euid 0)
     (suid 0)
     (fsuid 0)
     (gid 444)
     (egid 0)
     (sgid 0)
     (fsgid 0)
     (parent_name "bash")))

