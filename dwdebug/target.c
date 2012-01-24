#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include "libdwdebug.h"

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/**
 ** The generic target API!
 **/
int target_open(struct target *target) {
    int rc;
    struct memregion *region;

    ldebug(5,"opening target type %s on space %s\n",target->type,
	   target->space->idstr);

    ldebug(6,"target type %s: init\n",target->type);
    if ((rc = target->ops->init(target))) {
	return rc;
    }

    ldebug(6,"target type %s: loadregions\n",target->type);
    if ((rc = target->ops->loadregions(target))) {
	return rc;
    }
    list_for_each_entry(region,&target->space->regions,region) {
	ldebug(6,"loaddebugfiles target(%s:%s), region %s:%d\n",
	       target->type,target->space->idstr,
	       region->filename,region->type);
	if ((rc = target->ops->loaddebugfiles(target,region))) {
	    lwarn("could not open debuginfo for region %s (%d)\n",
		  region->filename,rc);
	}
    }

    ldebug(6,"attach target(%s:%s)\n",target->type,target->space->idstr);
    if ((rc = target->ops->attach(target))) {
	return rc;
    }

    return 0;
}
    
target_status_t target_monitor(struct target *target) {
    ldebug(5,"monitoring target(%s:%s)\n",target->type,target->space->idstr);
    return target->ops->monitor(target);
}
    
int target_resume(struct target *target) {
    ldebug(5,"resuming target(%s:%s)\n",target->type,target->space->idstr);
    return target->ops->resume(target);
}

unsigned char *target_read_addr(struct target *target,
				unsigned long long addr,
				unsigned long length,
				unsigned char *buf) {
    ldebug(5,"reading target(%s:%s) at %16llx into %p (%d)\n",
	   target->type,target->space->idstr,addr,buf,length);
    return target->ops->read(target,addr,length,buf);
}

int target_write_addr(struct target *target,unsigned long long addr,
		      unsigned long length,unsigned char *buf) {
    ldebug(5,"writing target(%s:%s) at %16llx (%d)\n",
	   target->type,target->space->idstr,addr,length);
    return target->ops->write(target,addr,length,buf);
}

struct value *target_read(struct target *target,struct symbol *symbol) {
    

    return 0;
}

int target_write(struct target *target,struct symbol *symbol,
		 struct value *value) {
    

    return 0;
}

char *target_reg_name(struct target *target,REG reg) {
    ldebug(5,"target(%s:%s) reg name %d)\n",
	   target->type,target->space->idstr,reg);
    return target->ops->regname(target,reg);
}

REGVAL target_read_reg(struct target *target,REG reg) {
    ldebug(5,"reading target(%s:%s) reg %d)\n",
	   target->type,target->space->idstr,reg);
    return target->ops->readreg(target,reg);
}

int target_write_reg(struct target *target,REG reg,REGVAL value) {
    ldebug(5,"writing target(%s:%s) reg %d %" PRIx64 ")\n",
	   target->type,target->space->idstr,reg);
    return target->ops->writereg(target,reg,value);
}

int target_close(struct target *target) {
    int rc;

    ldebug(5,"closing target(%s:%s)\n",target->type,target->space->idstr);

    ldebug(6,"detach target(%s:%s)\n",target->type,target->space->idstr);
    if ((rc = target->ops->detach(target))) {
	return rc;
    }

    ldebug(6,"fini target(%s:%s)\n",target->type,target->space->idstr);
    if ((rc = target->ops->fini(target))) {
	return rc;
    }

    return 0;
}

void target_free(struct target *target) {
    
}


/*
 * The target interface.  You can use address spaces and all the other
 * memory-modeling and symbol objects fully without using a live or dead
 * target if you just want to process debug files.
 */

extern struct target_ops linux_userspace_process_ops;

/*
 * A generic file read function.  If the user doesn't supply a buffer,
 * we malloc one, and they must free it later.  If they specify a zero
 * length, we attempt to read as many bytes as possible until we see a
 * \0 byte -- i.e., we hit the end of a string.  On error we return
 * NULL.
 */
unsigned char *target_generic_fd_read(int fd,
				      unsigned long long addr,
				      unsigned long length,
				      unsigned char *buf) {
    unsigned char *lbuf = buf;
    unsigned char *tbuf;
    int bufinc = 128;
    int bufsiz = length;
    int read_until_null = !length;
    int rc = 0;
    int retval;
    int len;

    ldebug(5,"reading fd %d at 0x%llx into %p (%d)\n",fd,addr,buf,length);

    /* We must malloc their buffer if they want us to read a NUL-term
     * string!
     */
    if (buf && !length) {
	errno = EINVAL;
	return NULL;
    }

    if (!lbuf) {
	if (read_until_null)
	    bufsiz = bufinc;
	lbuf = malloc(bufsiz);
    }

    if (lseek64(fd,addr,SEEK_SET) == (off64_t) -1) {
	lerror("lseek64(%d,0x%llx,0): %s\n",fd,addr,strerror(errno));
	return NULL;
    }

    while (1) {
	retval = read(fd,lbuf+rc,bufsiz - rc);
	if (retval > 0) {
	    rc += retval;
	    if (rc < bufsiz && !read_until_null) {
		/* read some more bytes */
	    }
	    else if (read_until_null 
		     && (len = strnlen((const char *)lbuf,rc)) < rc) {
		/* we've found a NUL-term string */
		if (!realloc(lbuf,len + 1)) {
		    free(lbuf);
		    lerror("realloc: %s\n",strerror(errno));
		    return NULL;
		}
		return lbuf;
	    }
	    else if (read_until_null && rc == bufsiz) {
		/* expand our buffer via realloc, or malloc. */
		if (!realloc(lbuf,bufsiz + bufinc)) {
		    tbuf = malloc(bufsiz + bufinc);
		    if (!tbuf) {
			/* we can't recover from this! */
			free(lbuf);
			lerror("malloc: %s\n",strerror(errno));
			return NULL;
		    }
		    memcpy(tbuf,lbuf,bufsiz);
		    free(lbuf);
		    lbuf = tbuf;
		    bufsiz += bufinc;
		}
	    }
	    else if (!read_until_null && rc == bufsiz) {
		/* we're done! */
		return lbuf;
	    }
	}
	else if (retval == 0 && rc != bufsiz) {
	    if (lbuf != buf) 
		free(lbuf);
	    lerror("EOF before reading %d bytes!\n",bufsiz);
	    errno = EOF;
	    return NULL;
	}
	else if (retval < 0
		 && retval != EAGAIN && retval != EINTR) {
	    if (lbuf != buf) 
		free(lbuf);
	    lerror("read: %s\n",strerror(errno));
	    return NULL;
	}
	else 
	    break;
    }

    return lbuf;
}

unsigned long target_generic_fd_write(int fd,
				      unsigned long long addr,
				      unsigned long length,
				      unsigned char *buf) {
    size_t rc;
    size_t total = 0;

    if (lseek64(fd,addr,0) == (off_t)-1) {
	lerror("lseek64: %s",strerror(errno));
	return 0;
    }

    while (1) {
	rc = write(fd,buf+total,length-total);
	if (rc > 0 && (total + rc) == length)
	    break;
	else if ((rc > 0 && rc < length)
		 || (rc <= 0 && (rc == EAGAIN || rc == EINTR))) 
	    total += rc;
	else {
	    lerror("write error: %s (after %ld bytes)\n",strerror(errno),total);
	    break;
	}
    }

    return total;
}
