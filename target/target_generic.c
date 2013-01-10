/*
 * Copyright (c) 2011, 2012, 2013 The University of Utah
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "target.h"

#include <sys/types.h>
#include <unistd.h>

/*
 * A generic file read function.  If the user doesn't supply a buffer,
 * we malloc one, and they must free it later.  If they specify a zero
 * length, we attempt to read as many bytes as possible until we see a
 * \0 byte -- i.e., we hit the end of a string.  On error we return
 * NULL.
 */
unsigned char *target_generic_fd_read(int fd,
				      ADDR addr,
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

    vdebug(5,LA_TARGET,LF_TOTHER,"reading fd %d at 0x%"PRIxADDR" into %p (%d)\n",
	   fd,addr,buf,length);

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
	verror("lseek64(%d,0x%"PRIxADDR",0): %s\n",fd,addr,strerror(errno));
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
		    verror("realloc: %s\n",strerror(errno));
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
			verror("malloc: %s\n",strerror(errno));
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
	    verror("EOF before reading %d bytes!\n",bufsiz);
	    errno = EOF;
	    return NULL;
	}
	else if (retval < 0
		 && retval != EAGAIN && retval != EINTR) {
	    if (lbuf != buf) 
		free(lbuf);
	    verror("read: %s\n",strerror(errno));
	    return NULL;
	}
	else 
	    break;
    }

    return lbuf;
}

unsigned long target_generic_fd_write(int fd,
				      ADDR addr,
				      unsigned long length,
				      unsigned char *buf) {
    size_t rc;
    long total = 0;

    if (lseek64(fd,addr,0) == (off_t)-1) {
	verror("lseek64: %s",strerror(errno));
	return -1;
    }

    while (1) {
	rc = write(fd,buf+total,length-total);
	if (rc > 0 && (total + rc) == length) {
	    total += rc;
	    break;
	}
	else if ((rc > 0 && rc < length)
		 || (rc <= 0 && (rc == EAGAIN || rc == EINTR))) 
	    total += rc;
	else {
	    verror("write error: %s (after %ld bytes of %lu total) (buf 0x%p)\n",
		   strerror(errno),total,length,(void *)buf);
	    break;
	}
    }

    return total;
}
