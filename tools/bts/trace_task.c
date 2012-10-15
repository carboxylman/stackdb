/*
 * Collect a branch trace of the traced guest over the indicated time frame.
 *
 * "Time frame" here is represented by start and end EIP+brctr values.
 * Note that the EIP is actually a symbol and the branch counter value is
 * optional. If the start location has no brctr, it is taken to mean the
 * first time the symbol is hit. If the end location has no brctr, it is
 * taken to mean the first time hit after the start has been reached.
 *
 * Once the trace has been completed, we extract it from the replay logfile
 * and write it to a file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include <dwdebug.h>
#include <target_api.h>
#include <target.h>
#include <target_xen_vm.h>

#include <probe_api.h>
#include <probe.h>
#include <alist.h>

#include <xentt.h>
#include <bts.h>

int debug = 0;
static struct xentt_replay_session *session;
static char *symfile;
static struct target *target;
static struct bsymbol ssymbol, esymbol;
static int xc = -1;
GHashTable *probes;

static int check_symbols(char *statedir, char *ssym, char *esym);
static int register_probe(struct target *t, GHashTable *probes, char *symname,
			  struct bsymbol *sym);
static void unregister_probes(GHashTable *probes);

static void
onexit(int sig)
{
    if (target != NULL) {
        target_pause(target);
	unregister_probes(probes);
        target_close(target);
    }
    if (session != NULL)
	xentt_replay_destroy(session);
    if (xc != -1)
	xc_interface_close(xc);
    exit(sig);
}

static int
handler(struct probe *probe, void *handler_data, struct probe *trigger)
{
    fprintf(stderr, "handler called\n");

    /* turn on BTS */
    /* use VMI to put a probe on the end point and run til then */
    /* turn off BTS */

    return 0;
}

int
main(int argc, char **argv)
{
    char *name, *statedir;
    char *s_sym, *e_sym;
    unsigned long long s_brctr, e_brctr;
    target_status_t tstat;
    char ch, *cp;

    while ((ch = getopt(argc, argv, "d")) != -1) {
	switch(ch) {
	case 'd':
	    debug++;
	    break;
	}
    }
    argc -= optind;
    argv += optind;
    
    if (argc < 3) {
	fprintf(stderr, "Usage: trace_task statedir start-sym[:brctr] end-sym[:brctr]\n");
	exit(1);
    }
    statedir = argv[0];
    if ((cp = index(argv[1], ':')) != 0 && cp[1] != '\0') {
	*cp = '\0';
	s_sym = strdup(argv[1]);
	s_brctr = strtoull(cp+1, NULL, 0);
	*cp = ':';
    } else {
	s_sym = strdup(argv[1]);
	s_brctr = 0;
    }
    if ((cp = index(argv[2], ':')) != 0 && cp[1] != '\0') {
	*cp = '\0';
	e_sym = strdup(argv[2]);
	e_brctr = strtoull(cp+1, NULL, 0);
	*cp = ':';
    } else {
	e_sym = strdup(argv[2]);
	e_brctr = 0;
    }
    if (debug)
	fprintf(stderr, "Start: %s:%llu, End: %s:%llu\n",
		s_sym, s_brctr, e_sym, e_brctr);

    /*
     * XXX heavily tied to the tt_record/tt_replay scripts right now.
     * We use the last component of the state directory name as the
     * domain name.
     */
    name = rindex(statedir, '/');
    if (name == 0) {
	fprintf(stderr, "Could not determine name from statedir %s\n",
		statedir);
	exit(1);
    }
    name++;

    /*
     * Make sure the symbols are legit for the replay OS.
     */
    if (check_symbols(statedir, s_sym, e_sym)) {
	fprintf(stderr, "Could not resolve start/end symbols\n");
	exit(1);
    }

    /*
     * Don't leave behind unsightly domains.
     */
    signal(SIGINT, onexit);
    signal(SIGTERM, onexit);
    signal(SIGHUP, onexit);
    signal(SIGQUIT, onexit);
    signal(SIGABRT, onexit);
    signal(SIGKILL, onexit);
    signal(SIGSEGV, onexit);
    signal(SIGPIPE, onexit);
    signal(SIGALRM, onexit);
    signal(SIGUSR1, onexit);
    signal(SIGUSR2, onexit); 

    /*
     * Create a replay session.
     */
    if (debug)
	fprintf(stderr, "Creating replay session %s from %s\n",
		name, statedir);

    session = xentt_replay_create(name, statedir);
    if (session == NULL) {
	fprintf(stderr, "Could not create replay session %s from %s\n",
		name, statedir);
	exit(1);
    }
    if (xentt_replay_start(session, NULL) != 0) {
	fprintf(stderr, "Could not start replay session %s\n", name);
	onexit(1);
    }

    dwdebug_init();
    vmi_set_log_level(debug);
    xa_set_debug_level(debug);

    if ((target = xen_vm_attach(name, 0)) == NULL) {
	fprintf(stderr, "xen_vm_attach failed for %s\n", name);
	onexit(1);
    }
    if (target_open(target, NULL) != 0) {
        fprintf(stderr, "cannot open target %s!\n", name);
	onexit(1);
    }

    /* use VMI to put a probe on the start point and run til then */
    if (register_probe(target, probes, s_sym, &ssymbol) != 0) {
        fprintf(stderr, "failed to register start probe\n");
        exit(1);
    }

    xc = xc_interface_open();
    if (xc == -1) {
	fprintf(stderr, "Could not get xc handle\n");
	exit(1);
    }

    target_resume(target);
    while (1) {
        tstat = target_monitor(target);
	if (tstat != TSTATUS_PAUSED)
	    break;

	printf("domain %s interrupted at 0x%" PRIxREGVAL "\n", name,
	       target_read_reg(target, TID_GLOBAL, target->ipregno));
	if (target_resume(target)) {
	    fprintf(stderr, "Can't resume target dom %s\n", name);
	    tstat = TSTATUS_ERROR;
	    break;
	}
    }

    if (tstat == TSTATUS_DONE) {
	/* extract the branch trace from the replay log, dump to file */
	onexit(0);
    }

    onexit(-1);
}

static int check_symbols(char *statedir, char *ssym, char *esym)
{
    char buf[256], *bp;
    FILE *fd;
    struct symmap map[1];
    struct lsymbol *s = 0, *e = 0;
    int rv;
	
    snprintf(buf, sizeof buf, "%s/symfile", statedir);
    if ((fd = fopen(buf, "r")) == NULL) {
	perror(buf);
	return -1;
    }
    rv = fscanf(fd, "%s", buf);
    fclose(fd);
    if (rv != 1) {
	perror("fscanf");
	return -1;
    }

    if ((bp = index(buf, '\n')) != 0)
	*bp = '\0';
    symfile = strdup(buf);

    memset(map, 0, sizeof(struct symmap));
    map[0].symfile = symfile;
    if (symlist_init(map, 1))
	return -1;

    if (debug)
	fprintf(stderr, "Looking up symbols in '%s'\n", symfile);

    rv = 1;
    s = symlist_lookup_name(ssym);
    if (s) {
	if (debug)
	    fprintf(stderr, "Found %s\n", ssym);
	e = symlist_lookup_name(esym);
	if (e) {
	    if (debug)
		fprintf(stderr, "Found %s\n", esym);
	    rv = 0;
	}
    }
    if (s) {
	if (debug)
	    fprintf(stderr, "Releasing %s\n", ssym);
	lsymbol_release(s);
    }
    if (e) {
	if (debug)
	    fprintf(stderr, "Releasing %s\n", esym);
	lsymbol_release(e);
    }
    symlist_deinit();

    return rv;
}

static int
register_probe(struct target *target, GHashTable *probes, char *symname,
	       struct bsymbol *sym)
{
    struct probe *probe;
    struct bsymbol *bsymbol;

    bsymbol = target_lookup_sym(target, symname, ".", NULL,
				SYMBOL_TYPE_FLAG_NONE);
    if (!bsymbol) {
	fprintf(stderr, "Could not find symbol %s!\n", symname);
	return -1;
    }

    //bsymbol_dump(bsymbol, &udn);

    /* Create a probe for the given EIP */
    probe = probe_create(target, TID_GLOBAL, NULL, symname,
			 handler, NULL, NULL, 0);
    if (!probe) {
	fprintf(stderr,
		"could not create probe for '%s'\n", symname);
	unregister_probes(probes);
	return -1;
    }

    if (!probe_register_symbol(probe, 
			       bsymbol, PROBEPOINT_FASTEST,
			       PROBEPOINT_EXEC, PROBEPOINT_LAUTO)) {
	fprintf(stderr, "could not register probe on '%s'\n",
		bsymbol->lsymbol->symbol->name);
	probe_free(probe, 1);
	unregister_probes(probes);
	return -1;
    }
    g_hash_table_insert(probes, 
			(gpointer)probe->probepoint->addr, 
			(gpointer)probe);

    return 0;
}

static void unregister_probes(GHashTable *probes)
{
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;

    g_hash_table_iter_init(&iter, probes);
    while (g_hash_table_iter_next(&iter, (gpointer)&key, (gpointer)&probe)) {
	probe_unregister(probe,1);
    }
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
