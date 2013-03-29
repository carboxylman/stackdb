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



/* need to define a structure for commands and acknowledgment */
struct cmd_rec {

};

struct ack_rec {

};


/*
 * This structure contains the metadata for a single trace buffer.  The head
 * field, indexes into an array of struct t_rec's.
 */
struct cmd_buf {
    unsigned long   cons;      /* Next item to be consumed. */
    unsigned long   prod;      /* Next item to be produced.           */

    /* Shape of the buffer */
    unsigned long      payload_buffer_mfn;   /* what is this ?? */
    unsigned long      payload_buffer_size;
    unsigned long      size_of_a_rec;        /* size of a single record */
    unsigned long      size_in_recs;         /* size of the buffer in recs */
};


struct cmd_ring_channel {
    struct cmd_buf   *buf;                  /* pointer to the buffer metadata   */
    unsigned long     buf_mfn;              /* what is this ? */
    unsigned long     buf_order;

    void             *priv_metadata;        /* pointer to the private buffer metadata  */
    unsigned long     priv_metadata_size;   /* size of the private buffer metadata  */
    unsigned long     header_order;         /* size of the private buffer metadata  */

    char             *recs;                 /* pointer to buffer data areas      */

    unsigned long     size_of_a_rec;        /* size of a single record */
    unsigned long     size_in_recs;         /* size of the buffer in recs */

    /* not sure if we need the following fields, keeping it as of now */
    unsigned long     highwater;            /* buffer is quite full, time to notify other end */
    unsigned long     emergency_margin;     /* buffer is nearly full, time to freeze everything */
    
};


static inline void cmd_ring_channel_init(struct cmd_ring_channel *ring_channel)
{
    memset(ring_channel, 0, sizeof(*ring_channel));
    return;
}

static inline void cmd_ring_channel_buf_init(struct cmd_buf *buf)
{
    memset(buf, 0, sizeof(*buf));
    return;
}

int cmd_ring_channel_alloc(struct cmd_ring_channel *ring_channel, unsigned long size_in_pages, unsigned long size_of_a_rec);
int cmd_ring_channel_alloc_with_metadata(struct cmd_ring_channel *ring_channel, unsigned long size_in_pages, unsigned long size_of_a_rec, unsigned long priv_metadata_size);
void cmd_ring_channel_free(struct cmd_ring_channel *ring_channel);

static inline void *cmd_ring_channel_get_priv_metadata(struct cmd_ring_channel *ring_channel) {
    return ring_channel->priv_metadata;
};

static inline unsigned long cmd_ring_channel_get_prod(struct cmd_ring_channel *ring_channel) {
    return ring_channel->buf->prod;
};

static inline unsigned long cmd_ring_channel_inc_prod(struct cmd_ring_channel *ring_channel) {
    return (ring_channel->buf->prod++);
};

static inline void cmd_ring_channel_set_prod(struct cmd_ring_channel *ring_channel, unsigned long prod) {
    ring_channel->buf->prod = prod;
    return;
};

static inline unsigned long cmd_ring_channel_get_cons(struct cmd_ring_channel *ring_channel) {
    return ring_channel->buf->cons;
};

static inline unsigned long cmd_ring_channel_inc_cons(struct cmd_ring_channel *ring_channel) {
    return (ring_channel->buf->cons++);
};


static inline void cmd_ring_channel_set_cons(struct cmd_ring_channel *ring_channel, unsigned long cons) {
    ring_channel->buf->cons = cons;
    return; 
};

/* what do the following 2 functions do */
static inline char *cmd_ring_channel_get_rec_slow(struct cmd_ring_channel *ring_channel, unsigned long cons) {
    return (ring_channel->recs + (cons % ring_channel->size_in_recs) * ring_channel->size_of_a_rec);
};


static inline unsigned long cmd_ring_channel_get_index_mod_slow(struct cmd_ring_channel *ring_channel, unsigned long index) {
    return (index % ring_channel->size_in_recs);
}

static inline unsigned long cmd_ring_channel_size_in_recs(struct cmd_ring_channel *ring_channel) {
    return ring_channel->size_in_recs;
}

static inline unsigned long cmd_ring_channel_size_of_a_rec(struct cmd_ring_channel *ring_channel) {
    return ring_channel->size_of_a_rec;
}

static inline unsigned long cmd_ring_channel_size(struct cmd_ring_channel *ring_channel) {
    return ring_channel->size_in_recs * ring_channel->size_of_a_rec;
}

/* Not sure if we require the following 2 functions, keeping them as of now */
static inline unsigned long cmd_ring_channel_highwater(struct cmd_ring_channel *ring_channel) {
    return ring_channel->highwater;
}

static inline unsigned long cmd_ring_channel_emergency_margin(struct cmd_ring_channel *ring_channel) {
    return ring_channel->emergency_margin;
}

