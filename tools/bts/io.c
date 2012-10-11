/*
 * Provide streaming read of BTS branch records from a file.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bts.h>

struct bts_stream {
    FILE *fd;
    uint64_t recno;
};

#define _BBUFSIZE (10240 * sizeof(struct bts_rec))

BTSFD
bts_open(const char *logname)
{
	struct bts_stream *bs;

	bs = malloc(sizeof *bs);
	if (bs == 0) {
		fprintf(stderr, "No memory\n");
		return 0;
	}
	memset(bs, 0, sizeof *bs);

	bs->fd = fopen(logname, "r");
	if (bs->fd == NULL) {
		perror(logname);
		free(bs);
		return 0;
	}

	return (BTSFD)bs;
}

/*
 * Seek to a specific record number.
 * Return 0 on sucess, -1 otherwise.
 */
int
bts_seek(BTSFD fd, uint64_t recno)
{
	struct bts_stream *bs = fd;
	off_t foff = recno * sizeof(struct bts_rec);

	if (bs == 0) {
		fprintf(stderr, "bts_seek: invalid BTSFD\n");
		return -1;
	}

	if (bs->recno != recno) {
		if (fseeko(bs->fd, foff, SEEK_SET) == -1) {
			fprintf(stderr, "bts_seek: cannot seek to 0x%llx\n",
					(unsigned long long)foff);
			return -1;
		}
		bs->recno = recno;
	}

	return 0;
}

/*
 * Read up to maxrec branch records from the current offset into buf.
 * Returns the number of records sucessfully read (0 on EOF),
 * or -1 on error.
 */
int
bts_read(BTSFD fd, struct bts_rec *buf, int maxrec)
{
	struct bts_stream *bs = fd;
	size_t nbytes, rbytes;
	int nrecs;

	if (bs == 0 || buf == 0) {
		fprintf(stderr, "bts_read: invalid BTSFD or buffer\n");
		return -1;
	}

	nbytes = maxrec * sizeof(struct bts_rec);
	rbytes = fread(buf, 1, nbytes, bs->fd);
	if (rbytes != nbytes) {
		if (rbytes == 0) {
			if (feof(bs->fd))
				return 0;
			return -1;
		}
		nrecs = rbytes / sizeof(struct bts_rec);
		if ((rbytes % sizeof(struct bts_rec)) != 0) {
			if (nrecs == 0) {
				fprintf(stderr, "bts_read: got partial record!\n");
				return -1;
			}
            fprintf(stderr, "bts_read: read not multiple of record size, "
					"truncating!\n");

			/* get to a record boundary in the file */
			bts_seek(fd, bs->recno+nrecs);
			return nrecs;
		}
	} else
		nrecs = maxrec;

	bs->recno += nrecs;
	return nrecs;
}

void
bts_close(BTSFD fd)
{
	struct bts_stream *bs = fd;

	if (bs) {
		fclose(bs->fd);
		free(bs);
	}
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
