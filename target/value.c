/*
 * Copyright (c) 2011, 2012, 2013, 2014 The University of Utah
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

#include <glib.h>

#include "glib_wrapper.h"
#include "target_api.h"
#include "target.h"
#include "memcache.h"
#include "dwdebug.h"
#include "dwdebug_priv.h"

int value_set_addr(struct value *value,ADDR addr) {
    value->res.addr = addr;
    value->res_ip = target_read_creg(value->thread->target,value->thread->tid,
				     CREG_IP);
    return 0;
}

int value_set_mmap(struct value *value,ADDR addr,struct memcache_mmap_entry *mme,
		   char *offset_ptr) {
    value->ismmap = 1;
    value->buf = offset_ptr;
    value->res.addr = addr;
    value->res_ip = target_read_creg(value->thread->target,value->thread->tid,
				     CREG_IP);
    return 0;
}

int value_set_reg(struct value *value,REG reg) {
    value->isreg = 1;
    value->res.reg = reg;
    value->res_ip = target_read_creg(value->thread->target,value->thread->tid,
				     CREG_IP);
    return 0;
}

int value_set_child(struct value *value,struct value *parent_value,ADDR addr) {
    if (addr < parent_value->res.addr 
	|| addr >= (parent_value->res.addr + parent_value->bufsiz))
	return -1;

    value->parent_value = parent_value;
    value->buf = parent_value->buf + (addr - parent_value->res.addr);
    value->res.addr = addr;
    value->range = parent_value->range;
    value->res_ip = target_read_creg(value->thread->target,value->thread->tid,
				     CREG_IP);

    return 0;
}

void value_set_strlen(struct value *value,int len) {
    value->bufsiz = len;
    value->isstring = 1;
}

void value_set_const(struct value *value) {
    value->isconst = 1;
}

struct value *value_create_raw(struct target *target,
			       struct target_thread *tthread,
			       struct memrange *range,int len) {
    struct value *value;

    if (!(value = malloc(sizeof(struct value)))) 
	return NULL;
    memset(value,0,sizeof(struct value));

    if (tthread)
	value->thread = tthread;
    else
	value->thread = target->global_thread;
    value->range = range;

    value->buf = malloc(len);
    if (!value->buf) {
	free(value);
	return NULL;
    }
    value->bufsiz = len;

    return value;
}

struct value *value_create_type(struct target_thread *thread,
				struct memrange *range,struct symbol *type) {
    struct value *value;
    int len = symbol_type_full_bytesize(type);

    if (len < 1) {
	verror("type %s (ref 0x%"PRIxSMOFFSET") had 0-byte size!\n",
	       type->name,type->ref);
	return NULL;
    }

    if (!(value = malloc(sizeof(struct value)))) 
	return NULL;
    memset(value,0,sizeof(struct value));

    if (thread)
	value->thread = thread;
    else if (range)
	value->thread = range->region->space->target->global_thread;
    else 
	vwarn("value without thread being created; BUG!\n");
    value->range = range;

    RHOLD(type,value);
    value->type = type;

    value->buf = malloc(len);
    if (!value->buf) {
	free(value);
	return NULL;
    }
    value->bufsiz = len;

    return value;
}

struct value *value_create(struct target_thread *thread,struct memrange *range,
			   struct lsymbol *lsymbol,struct symbol *type) {
    struct value *value = value_create_type(thread,range,type);

    if (!value)
	return NULL;

    if (lsymbol) {
	RHOLD(lsymbol,value);
	value->lsymbol = lsymbol;
    }

    return value;
}

struct value *value_create_noalloc(struct target_thread *thread,
				   struct memrange *range,
				   struct lsymbol *lsymbol,struct symbol *type) {
    struct value *value;
    int len = symbol_type_full_bytesize(type);

    /*
     * NB: don't check this because we want to create NULL values sometimes!
     */
#if 0
    if (len < 1) {
	verror("type %s (ref 0x%"PRIxSMOFFSET") had 0-byte size!\n",
	       type->name,type->ref);
	return NULL;
    }
#endif

    if (!(value = malloc(sizeof(struct value)))) 
	return NULL;
    memset(value,0,sizeof(struct value));

    if (thread)
	value->thread = thread;
    else
	value->thread = thread->target->global_thread;
    value->range = range;

    if (type) {
	RHOLD(type,value);
	value->type = type;
    }

    if (lsymbol) {
	RHOLD(lsymbol,value);
	value->lsymbol = lsymbol;
    }

    value->bufsiz = len;

    return value;
}

struct value *value_clone(struct value *in) {
    struct value *out = (struct value *)calloc(1,sizeof(*out));
    if (!out)
	return NULL;

    if (in->type) {
	out->type = in->type;
	RHOLD(out->type,out);
    }
    if (in->lsymbol) {
	out->lsymbol = in->lsymbol;
	RHOLD(out->lsymbol,out);
    }
    out->thread = in->thread;
    out->range = in->range;
    out->ismmap = in->ismmap;
    out->isreg = in->isreg;
    out->isstring = in->isstring;
    out->res.addr = in->res.addr;
    out->res.reg = in->res.reg;
    out->res_ip = in->res_ip;

    out->buf = malloc(in->bufsiz);
    memcpy(out->buf,in->buf,in->bufsiz);
    out->bufsiz = in->bufsiz;

    return out;
}

void value_free(struct value *value) {
    REFCNT trefcnt;

    if (value->ismmap) {
	/*
	 * XXX: if we ever link mmaps and values, handle refcnt stuff here.
	 */
    }
    else if (!value->parent_value)
	free(value->buf);

    if (value->type)
	RPUT(value->type,symbol,value,trefcnt);

    if (value->lsymbol)
	RPUT(value->lsymbol,lsymbol,value,trefcnt);

    free(value);
}

ADDR value_addr(struct value *value) {
    if (value->isreg) {
	errno = EINVAL;
	return 0;
    }

    return value->res.addr;
}

/*
 * Do our best to see if the value needs to be reloaded; if so, reload
 * it.
 *
 * There are several ways we can do this.  If we have page tracking, and
 * we know if a page has been updated since we last saw it, we can check
 * that.  If the value is mmap'd, we can just check content if
 * necessary.  Otherwise, we have to load the value again.
 *
 * If the value has a parent, we can only reload the parent if
 * @recursive is set.  Ugh, don't want that, but there is no other way.
 *
 * Wow, there are tons of complications involved with tracking values --
 * the thread could be gone; the value (symbol) could be out of scope;
 * it could have been a raw address on the stack; the value (symbol)
 * could be in scope but unavailable for load; ...
 */

int value_refresh(struct value *value,int recursive) {
    struct target *target;
    REGVAL regval;

    if (!value->thread) {
	vwarn("value no longer associated with a thread!\n");
	errno = EADDRNOTAVAIL;
	return -1;
    }
    if (!value->thread->target) {
	vwarn("value thread no longer associated with a target!\n");
	errno = EADDRNOTAVAIL;
	return -1;
    }
    if (value->parent_value && !recursive) {
	vwarn("value has a parent and you did not force recursive!\n");
	errno = EBUSY;
	return -1;
    }

    target = value->thread->target;

    /*
     * For now, just do it!
     */
    if (value->isreg) {
	errno = 0;
	regval = target_read_reg(target,value->thread->tid,value->res.reg);
	if (errno) {
	    verror("could not read reg %d in target %s!\n",
		   value->res.reg,target->name);
	    return -1;
	}
	memcpy(value->buf,&regval,value->bufsiz);
    }
    else {
	if (!target_read_addr(target,value->res.addr,value->bufsiz,
			      (unsigned char *)value->buf)) {
	    verror("could not read 0x%"PRIxADDR" in target %s!\n",
		   value->res.addr,target->name);
	    if (!errno)
		errno = EFAULT;
	    return -1;
	}
    }

    return 0;
}

int value_refresh_diff(struct value *value,int recurse,value_diff_t *vdiff,
		       char **old_buf,int *old_bufsiz,value_hash_t *old_vhash) {
    verror("not supported yet!\n");
    errno = ENOTSUP;
    return -1;
}

signed char      v_c(struct value *v)   { return *((signed char *)v->buf); }
unsigned char    v_uc(struct value *v)  { return *((unsigned char *)v->buf); }
wchar_t          v_wc(struct value *v)  { return *((wchar_t *)v->buf); }
uint8_t          v_u8(struct value *v)  { return *((uint8_t *)v->buf); }
uint16_t         v_u16(struct value *v) { return *((uint16_t *)v->buf); }
uint32_t         v_u32(struct value *v) { return *((uint32_t *)v->buf); }
uint64_t         v_u64(struct value *v) { return *((uint64_t *)v->buf); }
int8_t           v_i8(struct value *v)  { return *((int8_t *)v->buf); }
int16_t          v_i16(struct value *v) { return *((int16_t *)v->buf); }
int32_t          v_i32(struct value *v) { return *((int32_t *)v->buf); }
int64_t          v_i64(struct value *v) { return *((int64_t *)v->buf); }
num_t            v_num(struct value *v) {
    if (v->bufsiz == (signed)sizeof(int64_t))
	return v_i64(v);
    else if (v->bufsiz == (signed)sizeof(int32_t))
	return v_i32(v);
    else if (v->bufsiz == (signed)sizeof(int16_t))
	return v_i16(v);
    else if (v->bufsiz == (signed)sizeof(int8_t))
	return v_i8(v);
    else {
	errno = EINVAL;
	return -1;
    }
    return 0;
}
unum_t           v_unum(struct value *v){
    if (v->bufsiz == (signed)sizeof(uint64_t))
	return v_u64(v);
    else if (v->bufsiz == (signed)sizeof(uint32_t))
	return v_u32(v);
    else if (v->bufsiz == (signed)sizeof(uint16_t))
	return v_u16(v);
    else if (v->bufsiz == (signed)sizeof(uint8_t))
	return v_u8(v);
    else {
	errno = EINVAL;
	return -1;
    }
    return 0;
}
float            v_f(struct value *v)   { return *((float *)v->buf); }
double           v_d(struct value *v)   { return *((double *)v->buf); }
long double      v_dd(struct value *v)  { return *((long double *)v->buf); }
ADDR             v_addr(struct value *v){ return *((ADDR *)v->buf); }
char *           v_string(struct value *v){ return v->buf; }

int value_update(struct value *value,const char *buf,int bufsiz) {
    if (bufsiz < 0) {
	errno = EINVAL;
	return -1;
    }
    else if (bufsiz > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    else if (bufsiz > 0)
	memcpy(value->buf,buf,bufsiz);

    return 0;
}

int value_update_zero(struct value *value,const char *buf,int bufsiz) {
    if (bufsiz < 0) {
	errno = EINVAL;
	return -1;
    }
    else if (bufsiz > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    else if (bufsiz > 0)
	memcpy(value->buf,buf,bufsiz);

    if (bufsiz < value->bufsiz)
	memset(value->buf + bufsiz,0,value->bufsiz - bufsiz);

    return 0;
}

int value_update_c(struct value *value,signed char v) {
    if ((signed)sizeof(signed char) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(signed char));
    return 0;
}
int value_update_uc(struct value *value,unsigned char v) {
    if ((signed)sizeof(signed char) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(signed char));
    return 0;
}
int value_update_wc(struct value *value,wchar_t v) {
    if ((signed)sizeof(signed char) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(signed char));
    return 0;
}
int value_update_u8(struct value *value,uint8_t v) {
    if ((signed)sizeof(uint8_t) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(uint8_t));
    return 0;
}
int value_update_u16(struct value *value,uint16_t v) {
    if ((signed)sizeof(uint16_t) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(uint16_t));
    return 0;
}
int value_update_u32(struct value *value,uint32_t v) {
    if ((signed)sizeof(uint32_t) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(uint32_t));
    return 0;
}
int value_update_u64(struct value *value,uint64_t v) {
    if ((signed)sizeof(uint64_t) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(uint64_t));
    return 0;
}
int value_update_i8(struct value *value,int8_t v) {
    if ((signed)sizeof(int8_t) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(int8_t));
    return 0;
}
int value_update_i16(struct value *value,int16_t v) {
    if ((signed)sizeof(int16_t) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(int16_t));
    return 0;
}
int value_update_i32(struct value *value,int32_t v) {
    if ((signed)sizeof(int32_t) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(int32_t));
    return 0;
}
int value_update_i64(struct value *value,int64_t v) {
    if ((signed)sizeof(int64_t) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(int64_t));
    return 0;
}
int value_update_f(struct value *value,float v) {
    if ((signed)sizeof(float) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(float));
    return 0;
}
int value_update_d(struct value *value,double v) {
    if ((signed)sizeof(double) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(double));
    return 0;
}
int value_update_dd(struct value *value,long double v) {
    if ((signed)sizeof(long double) > value->bufsiz) {
	errno = EOVERFLOW;
	return -1;
    }
    memcpy(value->buf,&v,sizeof(long double));
    return 0;
}
int value_update_addr(struct value *value,ADDR v) {
    if (value->bufsiz <= (signed)sizeof(ADDR)) {
	memcpy(value->buf,&v,value->bufsiz);
    }
    else /* if (value->bufsiz > sizeof(ADDR)) */ {
	memcpy(value->buf,&v,sizeof(ADDR));
    }
    return 0;
}
int value_update_num(struct value *value,num_t v) {
    if (value->bufsiz == (signed)sizeof(int64_t))
	return value_update_i64(value,v);
    else if (value->bufsiz == (signed)sizeof(int32_t))
	return value_update_i32(value,(int32_t)v);
    else if (value->bufsiz == (signed)sizeof(int16_t))
	return value_update_i16(value,(int16_t)v);
    else if (value->bufsiz == (signed)sizeof(int8_t))
	return value_update_i8(value,(int8_t)v);
    else {
	errno = EINVAL;
	return -1;
    }
    return 0;
}
int value_update_unum(struct value *value,unum_t v) {
    if (value->bufsiz == (signed)sizeof(uint64_t))
	return value_update_u64(value,v);
    else if (value->bufsiz == (signed)sizeof(uint32_t))
	return value_update_u32(value,(uint32_t)v);
    else if (value->bufsiz == (signed)sizeof(uint16_t))
	return value_update_u16(value,(uint16_t)v);
    else if (value->bufsiz == (signed)sizeof(uint8_t))
	return value_update_u8(value,(uint8_t)v);
    else {
	errno = EINVAL;
	return -1;
    }
    return 0;
}

int value_snprintf(struct value *value,char *buf,int buflen) {
    int nrc;
    struct symbol *tmpsym;
    struct value fake_value;
    OFFSET offset;
    int *indicies;
    int i;
    int j;
    int found;
    uint32_t tbytesize;
    struct symbol *datatype = value->type;
    struct symbol *datatype2;
    GSList *gsltmp;
    loctype_t ltrc;
    struct location tloc;

    /* Handle AUTO_STRING specially. */
    if (value->isstring) {
	nrc = snprintf(buf,buflen,"\"%s\"",value->buf);
	goto out;
    }

    if (!datatype) 
	return -1;

    datatype = symbol_type_skip_qualifiers(datatype);
    tbytesize = symbol_get_bytesize(datatype);

    switch (datatype->datatype_code) {
    case DATATYPE_BASE:;
	encoding_t enc = SYMBOLX_ENCODING_V(datatype);
	if (enc == ENCODING_ADDRESS) {
	    if (tbytesize == 1) 
		nrc = snprintf(buf,buflen,"%"PRIx8,v_u8(value));
	    else if (tbytesize == 2) 
		nrc = snprintf(buf,buflen,"%"PRIx16,v_u16(value));
	    else if (tbytesize == 4) 
		nrc = snprintf(buf,buflen,"%"PRIx32,v_u32(value));
	    else if (tbytesize == 8) 
		nrc = snprintf(buf,buflen,"%"PRIx64,v_u64(value));
	    else
		nrc = snprintf(buf,buflen,"<UNSUP_ENC_%d_%d>",
			       enc,tbytesize);
	}
	else if (enc == ENCODING_BOOLEAN
	    || enc == ENCODING_UNSIGNED) {
	    if (tbytesize == 1) 
		nrc = snprintf(buf,buflen,"%"PRIu8,v_u8(value));
	    else if (tbytesize == 2) 
		nrc = snprintf(buf,buflen,"%"PRIu16,v_u16(value));
	    else if (tbytesize == 4) 
		nrc = snprintf(buf,buflen,"%"PRIu32,v_u32(value));
	    else if (tbytesize == 8) 
		nrc = snprintf(buf,buflen,"%"PRIu64,v_u64(value));
	    else
		nrc = snprintf(buf,buflen,"<UNSUP_ENC_%d_%d>",
			       enc,tbytesize);
	}
	else if (enc == ENCODING_SIGNED) {
	    if (tbytesize == 1) 
		nrc = snprintf(buf,buflen,"%"PRIi8,v_i8(value));
	    else if (tbytesize == 2) 
		nrc = snprintf(buf,buflen,"%"PRIi16,v_i16(value));
	    else if (tbytesize == 4) 
		nrc = snprintf(buf,buflen,"%"PRIi32,v_i32(value));
	    else if (tbytesize == 8) 
		nrc = snprintf(buf,buflen,"%"PRIi64,v_i64(value));
	    else
		nrc = snprintf(buf,buflen,"<UNSUP_ENC_%d_%d>",
			       enc,tbytesize);
	}
	else if (enc == ENCODING_FLOAT) {
	    if (tbytesize == 4) 
		nrc = snprintf(buf,buflen,"%f",(double)v_f(value));
	    else if (tbytesize == 8) 
		nrc = snprintf(buf,buflen,"%f",v_d(value));
	    else if (tbytesize == 16) 
		nrc = snprintf(buf,buflen,"%Lf",v_dd(value));
	    else
		nrc = snprintf(buf,buflen,"<UNSUP_ENC_%d_%d>",
			       enc,tbytesize);
	}
	else if (enc == ENCODING_SIGNED_CHAR
		 || enc == ENCODING_UNSIGNED_CHAR) {
	    if (tbytesize == 1) 
		nrc = snprintf(buf,buflen,"%c",(int)v_c(value));
	    else if (tbytesize == 2) 
		nrc = snprintf(buf,buflen,"%lc",(wint_t)v_wc(value));
	    else
		nrc = snprintf(buf,buflen,"<UNSUP_ENC_%d_%d>",
			       enc,tbytesize);
	}
	else if (enc == ENCODING_COMPLEX_FLOAT) {
	    nrc = snprintf(buf,buflen,"<UNSUP_ENC_%d_%d>",
			   enc,tbytesize);
	}
	else if (enc == ENCODING_IMAGINARY_FLOAT) {
	    nrc = snprintf(buf,buflen,"<UNSUP_ENC_%d_%d>",
			   enc,tbytesize);
	}
	else if (enc == ENCODING_PACKED_DECIMAL) {
	    nrc = snprintf(buf,buflen,"<UNSUP_ENC_%d_%d>",
			   enc,tbytesize);
	}
	else if (enc == ENCODING_NUMERIC_STRING) {
	    nrc = snprintf(buf,buflen,"<UNSUP_ENC_%d_%d>",
			   enc,tbytesize);
	}
	else if (enc == ENCODING_EDITED) {
	    nrc = snprintf(buf,buflen,"<UNSUP_ENC_%d_%d>",
			   enc,tbytesize);
	}
	else if (enc == ENCODING_SIGNED_FIXED) {
	    nrc = snprintf(buf,buflen,"<UNSUP_ENC_%d_%d>",
			   enc,tbytesize);
	}
	else if (enc == ENCODING_UNSIGNED_FIXED) {
	    nrc = snprintf(buf,buflen,"<UNSUP_ENC_%d_%d>",
			   enc,tbytesize);
	}
	else {
	    nrc = snprintf(buf,buflen,"<BAD_ENC_%d_%d>",
			   enc,tbytesize);
	}
	break;
    case DATATYPE_PTR:
	if (tbytesize == 4)
	    nrc = snprintf(buf,buflen,"0x%"PRIx32,v_u32(value));
	else if (tbytesize == 8)
	    nrc = snprintf(buf,buflen,"0x%"PRIx64,v_u64(value));
	else 
	    nrc = snprintf(buf,buflen,"<UNSUP_PTR_%d>",tbytesize);
	break;
    case DATATYPE_ARRAY:;
	GSList *subranges = SYMBOLX_SUBRANGES(datatype);
	int subrange_first;
	int subrange;
	int llen;

	if (!subranges) {
	    nrc = snprintf(buf,buflen,"[ ]");
	    break;
	}

	llen = g_slist_length(subranges);
	subrange_first = (int)(uintptr_t)g_slist_nth_data(subranges,0);

	datatype2 = symbol_get_datatype(datatype);

	/* First, if it's a single-index char array, print as a string
	 * if AUTO_STRING.
	 */
	if (llen == 1 && symbol_type_is_char(datatype2)) {
	    nrc = snprintf(buf,buflen,"\"%.*s\"",subrange_first,value->buf);
	    break;
	}

	nrc = 0;
	/* Otherwise, just dump the members of the array. */
	indicies = malloc(sizeof(int)*llen);
	for (i = 0; i < llen; ++i) {
	    indicies[i] = 0;
	    nrc += snprintf(buf + nrc,buflen - nrc,"[ ");
	}
	fake_value.bufsiz = symbol_get_bytesize(datatype2);
	fake_value.buf = value->buf;
	fake_value.type = datatype2;
    again:
	while (1) { /* fake_value.buf < (value->buf + value->bufsiz)) {
		       */
	    nrc += value_snprintf(&fake_value,buf + nrc,buflen - nrc);
	    nrc += snprintf(buf + nrc,buflen - nrc,", ");

	    /* calc current offset */
	    fake_value.buf += symbol_get_bytesize(datatype2);

	    /* close brackets */
	    for (j = llen - 1; j > -1; --j) {
		++indicies[j];
		subrange = (int)(uintptr_t)g_slist_nth_data(subranges,j);

		if (indicies[j] >= subrange) {
		    nrc += snprintf(buf + nrc,buflen - nrc," ],");
		    if (j == 0)
			/* Break to outer loop and the main termination */
			break;
		    indicies[j] = 0;
		}
		else 
		    goto again;
	    }

	    /* terminate if we're done */
	    if (indicies[0] >= subrange_first)
		break;

	    for ( ; j < llen; ++j)
		nrc += snprintf(buf + nrc,buflen - nrc," [ ");
	}
	free(indicies);

	break;
    case DATATYPE_STRUCT:
    case DATATYPE_UNION:
    case DATATYPE_CLASS:
	nrc = snprintf(buf,buflen,"{");
	gsltmp = NULL;
	v_g_slist_foreach(SYMBOLX_MEMBERS(datatype),gsltmp,tmpsym) {
	    if (symbol_get_name(tmpsym))
		nrc += snprintf(buf + nrc,buflen - nrc,
				" .%s = ",symbol_get_name(tmpsym));
	    else
		nrc += snprintf(buf + nrc,buflen - nrc," ");
	    memset(&tloc,0,sizeof(tloc));
	    ltrc = symbol_resolve_location(tmpsym,NULL,&tloc);
	    if (ltrc != LOCTYPE_MEMBER_OFFSET) {
		nrc += snprintf(buf + nrc,buflen - nrc,"?,");
	    }
	    else {
		offset = LOCATION_OFFSET(&tloc);
		fake_value.buf = value->buf + offset;
		fake_value.type = symbol_get_datatype(tmpsym);
		fake_value.lsymbol = NULL;
		fake_value.bufsiz = symbol_get_bytesize(fake_value.type);
		nrc += value_snprintf(&fake_value,buf + nrc,buflen - nrc);
		nrc += snprintf(buf + nrc,buflen - nrc,",");
	    }
	    location_internal_free(&tloc);
	}
	nrc += snprintf(buf + nrc,buflen - nrc," }");
	break;
    case DATATYPE_ENUM:
	found = 0;
	nrc = 0;
	gsltmp = NULL;
	v_g_slist_foreach(SYMBOLX_MEMBERS(datatype),gsltmp,tmpsym) {
	    char *constval = SYMBOLX_VAR_CONSTVAL(tmpsym);
	    if (!constval)
		continue;
	    if (strncmp((char *)constval,value->buf,
			symbol_type_full_bytesize(datatype)) == 0) {
		nrc += snprintf(buf + nrc,buflen - nrc,
				"%s",symbol_get_name(tmpsym));
		found = 1;
		break;
	    }
	}
	if (!found)
	    nrc += snprintf(buf + nrc,buflen - nrc,"%"PRIuNUM" (0x%"PRIxNUM")",
			    v_unum(value),v_unum(value));
	break;
    case DATATYPE_CONST:
	nrc = snprintf(buf,buflen,"<UNSUP_CONST_%s>",
		       symbol_get_name(datatype));
	break;
    case DATATYPE_VOL:
	nrc = snprintf(buf,buflen,"<UNSUP_VOL_%s>",symbol_get_name(datatype));
	break;
    case DATATYPE_TYPEDEF:	
	nrc = snprintf(buf,buflen,"<UNSUP_TYPEDEF_%s>",
		       symbol_get_name(datatype));
	break;
    case DATATYPE_FUNC:
	nrc = snprintf(buf,buflen,"<UNSUP_FUNCTION_%s>",
		       symbol_get_name(datatype));
	break;
    case DATATYPE_VOID:
	nrc = snprintf(buf,buflen,"NULL");
	break;
    default:
	nrc = 0;
	break;
    }

 out:
    return nrc;
}

void __value_dump(struct value *value,struct dump_info *ud) {
    struct symbol *tmpsym;
    struct value fake_value;
    OFFSET offset;
    int *indicies;
    int i;
    int j;
    int found;
    uint32_t tbytesize;
    struct symbol *datatype = value->type;
    struct symbol *datatype2;
    GSList *gsltmp;
    loctype_t ltrc;
    struct location tloc;

    /* Handle AUTO_STRING specially. */
    if (value->isstring) {
	fprintf(ud->stream,"\"%s\"",value->buf);
	goto out;
    }

    if (datatype)
	datatype = symbol_type_skip_qualifiers(datatype);
    tbytesize = symbol_get_bytesize(datatype);

    switch (datatype->datatype_code) {
    case DATATYPE_BASE:;
	encoding_t enc = SYMBOLX_ENCODING_V(datatype);
	if (enc == ENCODING_ADDRESS) {
	    if (tbytesize == 1) 
		fprintf(ud->stream,"%"PRIx8,v_u8(value));
	    else if (tbytesize == 2) 
		fprintf(ud->stream,"%"PRIx16,v_u16(value));
	    else if (tbytesize == 4) 
		fprintf(ud->stream,"%"PRIx32,v_u32(value));
	    else if (tbytesize == 8) 
		fprintf(ud->stream,"%"PRIx64,v_u64(value));
	    else
		fprintf(ud->stream,"<UNSUPPORTED_BYTESIZE_%d>",tbytesize);
	}
	else if (enc == ENCODING_BOOLEAN
	    || enc == ENCODING_UNSIGNED) {
	    if (tbytesize == 1) 
		fprintf(ud->stream,"%"PRIu8,v_u8(value));
	    else if (tbytesize == 2) 
		fprintf(ud->stream,"%"PRIu16,v_u16(value));
	    else if (tbytesize == 4) 
		fprintf(ud->stream,"%"PRIu32,v_u32(value));
	    else if (tbytesize == 8) 
		fprintf(ud->stream,"%"PRIu64,v_u64(value));
	    else
		fprintf(ud->stream,"<UNSUPPORTED_BYTESIZE_%d>",tbytesize);
			}
	else if (enc == ENCODING_SIGNED) {
	    if (tbytesize == 1) 
		fprintf(ud->stream,"%"PRIi8,v_i8(value));
	    else if (tbytesize == 2) 
		fprintf(ud->stream,"%"PRIi16,v_i16(value));
	    else if (tbytesize == 4) 
		fprintf(ud->stream,"%"PRIi32,v_i32(value));
	    else if (tbytesize == 8) 
		fprintf(ud->stream,"%"PRIi64,v_i64(value));
	    else
		fprintf(ud->stream,"<UNSUPPORTED_BYTESIZE_%d>",tbytesize);
	}
	else if (enc == ENCODING_FLOAT) {
	    if (tbytesize == 4) 
		fprintf(ud->stream,"%f",(double)v_f(value));
	    else if (tbytesize == 8) 
		fprintf(ud->stream,"%f",v_d(value));
	    else if (tbytesize == 16) 
		fprintf(ud->stream,"%Lf",v_dd(value));
	    else
		fprintf(ud->stream,"<UNSUPPORTED_BYTESIZE_%d>",tbytesize);
	}
	else if (enc == ENCODING_SIGNED_CHAR
		 || enc == ENCODING_UNSIGNED_CHAR) {
	    if (tbytesize == 1) 
		fprintf(ud->stream,"%c",(int)v_c(value));
	    else if (tbytesize == 2) 
		fprintf(ud->stream,"%lc",(wint_t)v_wc(value));
	    else
		fprintf(ud->stream,"<UNSUPPORTED_BYTESIZE_%d>",tbytesize);
	}
	else if (enc == ENCODING_COMPLEX_FLOAT) {
	    fprintf(ud->stream,"<UNSUPPORTED_COMPLEX_FLOAT_%d>",
		    tbytesize);
	}
	else if (enc == ENCODING_IMAGINARY_FLOAT) {
	    fprintf(ud->stream,"<UNSUPPORTED_IMAGINARY_FLOAT_%d>",
		    tbytesize);
	}
	else if (enc == ENCODING_PACKED_DECIMAL) {
	    fprintf(ud->stream,"<UNSUPPORTED_PACKED_DECIMAL_%d>",
		    tbytesize);
	}
	else if (enc == ENCODING_NUMERIC_STRING) {
	    fprintf(ud->stream,"<UNSUPPORTED_NUMERIC_STRING_%d>",
		    tbytesize);
	}
	else if (enc == ENCODING_EDITED) {
	    fprintf(ud->stream,"<UNSUPPORTED_EDITED_%d>",
		    tbytesize);
	}
	else if (enc == ENCODING_SIGNED_FIXED) {
	    fprintf(ud->stream,"<UNSUPPORTED_SIGNED_FIXED_%d>",
		    tbytesize);
	}
	else if (enc == ENCODING_UNSIGNED_FIXED) {
	    fprintf(ud->stream,"<UNSUPPORTED_UNSIGNED_FIXED_%d>",
		    tbytesize);
	}
	break;
    case DATATYPE_PTR:
	if (tbytesize == 4)
	    fprintf(ud->stream,"0x%"PRIx32,v_u32(value));
	else if (tbytesize == 8)
	    fprintf(ud->stream,"0x%"PRIx64,v_u64(value));
	else 
	    fprintf(ud->stream,"<UNSUPPORTED_PTR_%d>",tbytesize);
	break;
    case DATATYPE_ARRAY:;
	GSList *subranges = SYMBOLX_SUBRANGES(datatype);
	int subrange_first;
	int subrange;
	int llen;

	if (!subranges) {
	    fprintf(ud->stream,"[ ]");
	    break;
	}

	subrange_first = (int)(uintptr_t)g_slist_nth_data(subranges,0);
	llen = g_slist_length(subranges);
	datatype2 = symbol_get_datatype(datatype);

	/* First, if it's a single-index char array, print as a string
	 * if AUTO_STRING.
	 */
	if (llen == 1
	    && symbol_type_is_char(datatype2)) {
	    fprintf(ud->stream,"\"%.*s\"",subrange_first,value->buf);
	    break;
	}

	/* Otherwise, just dump the members of the array. */
	indicies = malloc(sizeof(int)*llen);
	for (i = 0; i < llen; ++i) {
	    indicies[i] = 0;
	    fprintf(ud->stream,"[ ");
	}
	fake_value.bufsiz = symbol_get_bytesize(datatype2);
	fake_value.buf = value->buf;
	fake_value.type = datatype2;
    again:
	while (1) { /* fake_value.buf < (value->buf + value->bufsiz)) { */
	    __value_dump(&fake_value,ud);
	    fprintf(ud->stream,", ");

	    /* calc current offset */
	    fake_value.buf += symbol_get_bytesize(datatype2);

	    /* close brackets */
	    for (j = llen - 1; j > -1; --j) {
		++indicies[j];

		subrange = (int)(uintptr_t)g_slist_nth_data(subranges,j);
		if (indicies[j] >= subrange) {
		    fprintf(ud->stream," ],");
		    if (j == 0)
			/* Break to outer loop and the main termination */
			break;
		    indicies[j] = 0;
		}
		else 
		    goto again;
	    }

	    /* terminate if we're done */
	    if (indicies[0] >= subrange_first)
		break;

	    for ( ; j < llen; ++j)
		fprintf(ud->stream," [ ");
	}
	free(indicies);

	break;
    case DATATYPE_STRUCT:
    case DATATYPE_UNION:
	fprintf(ud->stream,"{");
	gsltmp = NULL;
	v_g_slist_foreach(SYMBOLX_MEMBERS(datatype),gsltmp,tmpsym) {
	    if (symbol_get_name(tmpsym))
		fprintf(ud->stream," .%s = ",symbol_get_name(tmpsym));
	    else
		fprintf(ud->stream," ");
	    memset(&tloc,0,sizeof(tloc));
	    ltrc = symbol_resolve_location(tmpsym,NULL,&tloc);
	    if (ltrc != LOCTYPE_MEMBER_OFFSET) {
		fputs("?,",ud->stream);
	    }
	    else {
		offset = LOCATION_OFFSET(&tloc);
		fake_value.buf = value->buf + offset;
		fake_value.type = symbol_get_datatype(tmpsym);
		fake_value.lsymbol = NULL;
		fake_value.bufsiz = symbol_get_bytesize(fake_value.type);
		__value_dump(&fake_value,ud);
		fputs(",",ud->stream);
	    }
	    location_internal_free(&tloc);
	}
	fprintf(ud->stream," }");
	break;
    case DATATYPE_ENUM:
	found = 0;
	gsltmp = NULL;
	v_g_slist_foreach(SYMBOLX_MEMBERS(datatype),gsltmp,tmpsym) {
	    char *constval = SYMBOLX_VAR_CONSTVAL(tmpsym);
	    if (!constval)
		continue;
	    if (strncmp((char *)constval,value->buf,
			symbol_type_full_bytesize(datatype)) == 0) {
		fprintf(ud->stream,"%s",symbol_get_name(tmpsym));
		found = 1;
		break;
	    }
	}
	if (!found)
	    fprintf(ud->stream,"%"PRIuNUM" (0x%"PRIxNUM")",
		    v_unum(value),v_unum(value));
	break;
    case DATATYPE_CONST:
	fprintf(ud->stream,"<UNSUPPORTED_CONST_%s>",symbol_get_name(datatype));
	break;
    case DATATYPE_VOL:
	fprintf(ud->stream,"<UNSUPPORTED_VOL_%s>",symbol_get_name(datatype));
	break;
    case DATATYPE_TYPEDEF:	
	fprintf(ud->stream,"<UNSUPPORTED_TYPEDEF_%s>",
		symbol_get_name(datatype));
	break;
    case DATATYPE_FUNC:
	fprintf(ud->stream,"<UNSUPPORTED_FUNCTION_%s>",
		symbol_get_name(datatype));
	break;
    case DATATYPE_VOID:
	fprintf(ud->stream,"NULL");
	break;
    default:
	break;
    }

 out:
    return;
}

void value_dump_simple(struct value *value,struct dump_info *ud) {
    __value_dump(value,ud);
    return;
}

void value_dump(struct value *value,struct dump_info *ud) {
    char *p = "";
    char *np;
    struct dump_info udn;
    int i;
    int alen;
    struct symbol *s;

    if (ud->prefix) {
	p = ud->prefix;
	np = malloc(strlen(p) + 1 + 2);
	sprintf(np,"%s%s",p,"  ");
    }
    else {
	np = "  ";
    }
    udn.prefix = np;
    udn.stream = ud->stream;
    udn.meta = ud->meta;
    udn.detail = ud->detail;

    if (value->lsymbol) {
	alen = array_list_len(value->lsymbol->chain);
	for (i = 0; i < alen; ++i) {
	    s = (struct symbol *)array_list_item(value->lsymbol->chain,i);
	    if (symbol_get_name(s)) {
		fprintf(udn.stream,"%s",symbol_get_name(s));
		if ((i + 1) < alen)
		    fputs(".",udn.stream);
	    }
	}

	fputs(" = ",udn.stream);
    }

    __value_dump(value,&udn);

    if (ud->prefix)
	free(np);
    return;
}

signed char      rv_c(void *buf)   { return *((signed char *)buf); }
unsigned char    rv_uc(void *buf)  { return *((unsigned char *)buf); }
wchar_t          rv_wc(void *buf)  { return *((wchar_t *)buf); }
uint8_t          rv_u8(void *buf)  { return *((uint8_t *)buf); }
uint16_t         rv_u16(void *buf) { return *((uint16_t *)buf); }
uint32_t         rv_u32(void *buf) { return *((uint32_t *)buf); }
uint64_t         rv_u64(void *buf) { return *((uint64_t *)buf); }
int8_t           rv_i8(void *buf)  { return *((int8_t *)buf); }
int16_t          rv_i16(void *buf) { return *((int16_t *)buf); }
int32_t          rv_i32(void *buf) { return *((int32_t *)buf); }
int64_t          rv_i64(void *buf) { return *((int64_t *)buf); }
float            rv_f(void *buf)   { return *((float *)buf); }
double           rv_d(void *buf)   { return *((double *)buf); }
long double      rv_dd(void *buf)  { return *((long double *)buf); }
ADDR             rv_addr(void *buf){ return *((ADDR *)buf); }
