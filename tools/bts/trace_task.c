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

int debug = 0;
static struct xentt_replay_session *session;
static char *symfile;
static struct target *target;
GHashTable *probes;

static int init_symbols(char *statedir, char *ssym, char *esym);
static int register_probes(struct target *t, GHashTable *probes,
			   char *ssym, char *esym);
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
    exit(sig);
}

int
main(int argc, char **argv)
{
    char *name, *statedir;
    char *s_sym, *e_sym;
    unsigned long long s_brctr, e_brctr;
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
    if (init_symbols(statedir, s_sym, e_sym)) {
	fprintf(stderr, "Could not resolve start/end symbols\n");
	exit(1);
    }

    exit(0);

    /*
     * Don't leave behind unsightly domains.
     */
    signal(SIGINT, onexit);
    signal(SIGTERM, onexit);

    /*
     * Create a replay session.
     */
    if (debug)
	fprintf(stderr, "Creating replay session %s from %s\n",
		name, statedir);

    exit(0);

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
    if (register_probes(target, probes, s_sym, e_sym) != 0) {
        fprintf(stderr, "failed to register probes\n");
        exit(1);
    }

    /* use VMI to put a probe on the start point and run til then */
    /* turn on BTS */
    /* use VMI to put a probe on the end point and run til then */
    /* turn off BTS */

    /* kill the replay session */
    xentt_replay_destroy(session);

    /* extract the branch trace from the replay log, dump to file */

    exit(0);
}

static int init_symbols(char *statedir, char *ssym, char *esym)
{
    char buf[256], *bp;
    FILE *fd;
	
    snprintf(buf, sizeof buf, "%s/symfile", statedir);
    if ((fd = fopen(buf, "r")) == NULL) {
	perror(buf);
	return -1;
    }
    if (fscanf(fd, "%s", buf) != 1) {
	perror("fscanf");
	fclose(fd);
	return -1;
    }
    if ((bp = index(buf, '\n')) != 0)
	*bp = '\0';
    symfile = strdup(buf);
    if (debug)
	fprintf(stderr, "Looking up symbols in '%s'\n", symfile);

#if 0
    ssymbol = target_lookup_sym(target, ssym, ".", NULL,
				SYMBOL_TYPE_FLAG_NONE);
    esymbol = target_lookup_sym(target, esym, ".", NULL,
				SYMBOL_TYPE_FLAG_NONE);
    if (!ssymbol || !esymbol) {
	fprintf(stderr, "Could not find one of symbols %s/%s!\n",
		ssym, esym);
	exit(1);
    }
#endif
    return 0;
}

static int register_probes(struct target *target, GHashTable *probes,
			   char *ssym, char *esym)
{
#if 0
    struct probe *probe;
    struct bsymbol *bsymbol;

    bsymbol = target_lookup_sym(target, ssym, ".", NULL,
				SYMBOL_TYPE_FLAG_NONE);
    if (!bsymbol) {
	fprintf(stderr, "Could not find symbol %s!\n", ssym);
	return -1;
    }

    //bsymbol_dump(bsymbol, &udn);

    /* Create a probe for the given EIP */
    probe = probe_create(target, TID_GLOBAL, NULL, "start",
			 start_handler, NULL, NULL, 0);
    if (!probe) {
	fprintf(stderr,
		"could not create probe for start address 0x%lx\n", saddr);
	unregister_probes(probes);
	return -1;
    }

    if (!probe_register_symbol(probe, 
			       bsymbol, PROBEPOINT_FASTEST,
			       PROBEPOINT_EXEC, PROBEPOINT_LAUTO)) {
	ERR("could not register probe on '%s'\n",
	    bsymbol->lsymbol->symbol->name);
	probe_free(probe, 1);
	unregister_probes(probes);
	return -1;
    }
    g_hash_table_insert(probes, 
			(gpointer)probe->probepoint->addr, 
			(gpointer)probe);
#endif
    return 0;
}

static void unregister_probes(GHashTable *probes)
{
#if 0
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;

    g_hash_table_iter_init(&iter, probes);
    while (g_hash_table_iter_next(&iter, (gpointer)&key, (gpointer)&probe)) {
	probe_unregister(probe,1);
    }
#endif
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
