/*
 * Based on include/asm-x86/ds.h
 */
#include <stdint.h>

/* For symbol mapping */
struct symmap {
    char *symfile;
    char *prefix;
    uint32_t loaddr;
    uint32_t hiaddr;
    void *dbfile;
};

extern int symbol_init(struct symmap[], int);
void symbol_string(uint32_t, char *, int);

/* Records as logged by the TT engine */
struct bts_rec {
    uint64_t from;
    uint64_t to;
    uint64_t format;
};

typedef void * BTSFD;

extern BTSFD bts_open(const char *);
extern void bts_close(BTSFD);
extern int bts_seek(BTSFD, uint64_t);
extern int bts_read(BTSFD, struct bts_rec *, int);
extern int debug;
