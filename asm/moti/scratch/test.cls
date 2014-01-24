 (deftemplate task-struct
      (slot comm (type STRING))
      (slot pid (type INTEGER))
      (slot uid (type INTEGER))
      (slot euid (type INTEGER))
      (slot suid (type INTEGER))
      (slot fsuid (type INTEGER))
      (slot gid (type INTEGER))
      (slot egid (type INTEGER))
      (slot sgid (type INTEGER))
      (slot fsgid (type INTEGER)))

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
