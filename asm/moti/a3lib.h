struct a3_hc_stats {
	int stuff;
};

int a3_hc_init(char *domid, char *server, int syslog);
void a3_hc_report_stats(struct a3_hc_stats *sb);
int a3_hc_signal_anomaly(char *atype);
int a3_hc_signal_recovery_attempt(char *func, int argc, char **argv);
int a3_hc_signal_recovery_complete(char *func, int status);
