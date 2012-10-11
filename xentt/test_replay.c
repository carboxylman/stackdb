/*
 * Test the C API.
 * You need a pre-recorded (via tt_record) domU.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <xenctrl.h>

#include <xentt.h>

int
main(int argc, char **argv)
{
    struct xentt_replay_session *session;
    char *name, statedir[256];
    domid_t domid;
    int xc;

    if (argc != 2) {
	fprintf(stderr, "usage: test_replay <recorded-domain-name>\n");
	fprintf(stderr, "  e.g., \"test_replay foo\" where \"foo\" was\n");
	fprintf(stderr, "  pre-recorded via \"tt_record foo\"\n");
	exit(1);
    }
    name = argv[1];
    snprintf(statedir, sizeof statedir, "/local/sda4/xentt-state/%s", name);

    if (getuid()) {
	fprintf(stderr, "Must run as root\n");
	exit(1);
    }

    printf("Get handle for xc operations ...\n");
    xc = xc_interface_open();
    if (xc == -1) {
	fprintf(stderr, "Could not get xc handle\n");
	exit(1);
    }

    printf("Creating session from %s ...\n", statedir);
    session = xentt_replay_create(name, statedir);
    if (session == NULL) {
	fprintf(stderr, "Could not create session from %s\n", statedir);
	exit(1);
    }

    printf("Starting session ...\n");
    if (xentt_replay_start(session, NULL)) {
	fprintf(stderr, "Could not create session from %s\n", statedir);
	exit(1);
    }
    if (xentt_replay_domid(session, &domid)) {
	fprintf(stderr, "Could not get domain ID for %s\n", statedir);
	xentt_replay_destroy(session);
	exit(1);
    }

    printf("Unpausing replay domain %s(%d)\n", name, domid);
    if (xc_domain_unpause(xc, domid)) {
	fprintf(stderr, "Could not unpause replay domain\n");
	xentt_replay_destroy(session);
	exit(1);
    }

    sleep(2);

    printf("Re-pausing replay domain %s(%d)\n", name, domid);
    if (xc_domain_pause(xc, domid)) {
	fprintf(stderr, "Could not pause replay domain\n");
	xentt_replay_destroy(session);
	exit(1);
    }

    printf("Stopping the replay session ...\n");
    if (xentt_replay_stop(session)) {
	fprintf(stderr, "Could not stop replay domain\n");
	xentt_replay_destroy(session);
	exit(1);
    }

    printf("Destroying the replay session ...\n");
    xentt_replay_destroy(session);

    xc_interface_close(xc);
    exit(0);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
