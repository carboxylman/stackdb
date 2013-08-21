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

#include "target_api.h"
#include "target.h"
#include "dwdebug.h"
#include "dwdebug_priv.h"

int value_set_addr(struct value *value,ADDR addr) {
    value->res.addr = addr;
    value->region_stamp = value->range->region->stamp;
    value->res_ip = target_read_creg(value->thread->target,value->thread->tid,
				     CREG_IP);
    return 0;
}

int value_set_mmap(struct value *value,ADDR addr,struct mmap_entry *mmap,
		   char *offset_ptr) {
    value->buf = offset_ptr;
    value->res.addr = addr;
    value->mmap = mmap;
    value->region_stamp = value->range->region->stamp;
    value->res_ip = target_read_creg(value->thread->target,value->thread->tid,
				     CREG_IP);
    return 0;
}

int value_set_reg(struct value *value,REG reg) {
    value->res.reg = reg;
    value->region_stamp = 0;
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
    value->region_stamp = value->range->region->stamp;
    value->res_ip = target_read_creg(value->thread->target,value->thread->tid,
				     CREG_IP);

    return 0;
}

void value_set_strlen(struct value *value,int len) {
    value->bufsiz = len;
    value->isstring = 1;
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
    else
	value->thread = range->region->space->target->global_thread;
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
    out->region_stamp = in->region_stamp;
    out->mmap = in->mmap;
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
	if (value->range)
	    target_release_mmap_entry(value->range->region->space->target,
				      value->mmap);
	else {
	    verror("value for symbol %s was mmap'd, but has no range!\n",
		   value->lsymbol->symbol->name);
	}
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
    REGVAL reg;

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
	reg = target_read_reg(target,value->thread->tid,value->res.reg);
	if (errno) {
	    verror("could not read reg %d in target %s!\n",
		   value->res.reg,target->name);
	    return -1;
	}
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

void __value_dump(struct value *value,struct dump_info *ud) {
    struct symbol_instance *tmpi;
    struct symbol *tmpsym;
    struct value fake_value;
    OFFSET offset;
    int *indicies;
    int i;
    int j;
    int found;
    uint32_t tbytesize;

    /* Handle AUTO_STRING specially. */
    if (value->isstring) {
	fprintf(ud->stream,"\"%s\"",value->buf);
	goto out;
    }

    tbytesize = symbol_bytesize(value->type);

    switch (value->type->datatype_code) {
    case DATATYPE_BASE:
	if (value->type->s.ti->d.t.encoding == ENCODING_ADDRESS) {
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
	else if (value->type->s.ti->d.t.encoding == ENCODING_BOOLEAN
	    || value->type->s.ti->d.t.encoding == ENCODING_UNSIGNED) {
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
	else if (value->type->s.ti->d.t.encoding == ENCODING_SIGNED) {
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
	else if (value->type->s.ti->d.t.encoding == ENCODING_FLOAT) {
	    if (tbytesize == 4) 
		fprintf(ud->stream,"%f",(double)v_f(value));
	    else if (tbytesize == 8) 
		fprintf(ud->stream,"%f",v_d(value));
	    else if (tbytesize == 16) 
		fprintf(ud->stream,"%Lf",v_dd(value));
	    else
		fprintf(ud->stream,"<UNSUPPORTED_BYTESIZE_%d>",tbytesize);
	}
	else if (value->type->s.ti->d.t.encoding == ENCODING_SIGNED_CHAR
		 || value->type->s.ti->d.t.encoding == ENCODING_UNSIGNED_CHAR) {
	    if (tbytesize == 1) 
		fprintf(ud->stream,"%c",(int)v_c(value));
	    else if (tbytesize == 2) 
		fprintf(ud->stream,"%lc",(wint_t)v_wc(value));
	    else
		fprintf(ud->stream,"<UNSUPPORTED_BYTESIZE_%d>",tbytesize);
	}
	else if (value->type->s.ti->d.t.encoding == ENCODING_COMPLEX_FLOAT) {
	    fprintf(ud->stream,"<UNSUPPORTED_COMPLEX_FLOAT_%d>",
		    tbytesize);
	}
	else if (value->type->s.ti->d.t.encoding == ENCODING_IMAGINARY_FLOAT) {
	    fprintf(ud->stream,"<UNSUPPORTED_IMAGINARY_FLOAT_%d>",
		    tbytesize);
	}
	else if (value->type->s.ti->d.t.encoding == ENCODING_PACKED_DECIMAL) {
	    fprintf(ud->stream,"<UNSUPPORTED_PACKED_DECIMAL_%d>",
		    tbytesize);
	}
	else if (value->type->s.ti->d.t.encoding == ENCODING_NUMERIC_STRING) {
	    fprintf(ud->stream,"<UNSUPPORTED_NUMERIC_STRING_%d>",
		    tbytesize);
	}
	else if (value->type->s.ti->d.t.encoding == ENCODING_EDITED) {
	    fprintf(ud->stream,"<UNSUPPORTED_EDITED_%d>",
		    tbytesize);
	}
	else if (value->type->s.ti->d.t.encoding == ENCODING_SIGNED_FIXED) {
	    fprintf(ud->stream,"<UNSUPPORTED_SIGNED_FIXED_%d>",
		    tbytesize);
	}
	else if (value->type->s.ti->d.t.encoding == ENCODING_UNSIGNED_FIXED) {
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
    case DATATYPE_ARRAY:
	/* First, if it's a single-index char array, print as a string
	 * if AUTO_STRING.
	 */
	if (value->type->s.ti->d.a.count == 1
	    && symbol_type_is_char(value->type->datatype)) {
	    fprintf(ud->stream,"\"%.*s\"",value->type->s.ti->d.a.subranges[0],
		    value->buf);
	    break;
	}

	/* Otherwise, just dump the members of the array. */
	indicies = malloc(sizeof(int)*value->type->s.ti->d.a.count);
	for (i = 0; i < value->type->s.ti->d.a.count; ++i) {
	    indicies[i] = 0;
	    fprintf(ud->stream,"[ ");
	}
	fake_value.bufsiz = symbol_bytesize(value->type->datatype);
	fake_value.buf = value->buf;
	fake_value.type = value->type->datatype;
    again:
	while (1) { /* fake_value.buf < (value->buf + value->bufsiz)) { */
	    __value_dump(&fake_value,ud);
	    fprintf(ud->stream,", ");

	    /* calc current offset */
	    fake_value.buf += symbol_bytesize(value->type->datatype);

	    /* close brackets */
	    for (j = value->type->s.ti->d.a.count - 1; j > -1; --j) {
		++indicies[j];

		if (indicies[j] >= value->type->s.ti->d.a.subranges[j]) {
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
	    if (indicies[0] >= value->type->s.ti->d.a.subranges[0])
		break;

	    for ( ; j < value->type->s.ti->d.a.count; ++j)
		fprintf(ud->stream," [ ");
	}
	free(indicies);

	break;
    case DATATYPE_STRUCT:
    case DATATYPE_UNION:
	fprintf(ud->stream,"{");
	list_for_each_entry(tmpi,&value->type->s.ti->d.su.members,d.v.member) {
	    tmpsym = tmpi->d.v.member_symbol;
	    if (symbol_get_name(tmpsym))
		fprintf(ud->stream," .%s = ",symbol_get_name(tmpsym));
	    else
		fprintf(ud->stream," ");
	    symbol_get_location_offset(tmpsym,&offset);
	    fake_value.buf = value->buf + offset;
	    fake_value.type = symbol_type_skip_qualifiers(tmpsym->datatype);
	    fake_value.lsymbol = NULL;
	    fake_value.bufsiz = symbol_bytesize(fake_value.type);
	    __value_dump(&fake_value,ud);
	    fputs(",",ud->stream);
	}
	fprintf(ud->stream," }");
	break;
    case DATATYPE_ENUM:
	found = 0;
	list_for_each_entry(tmpi,&value->type->s.ti->d.e.members,d.v.member) {
	    tmpsym = tmpi->d.v.member_symbol;
	    if (strncmp((char *)tmpsym->s.ii->constval,value->buf,
			symbol_type_full_bytesize(value->type)) == 0) {
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
	fprintf(ud->stream,"<UNSUPPORTED_CONST_%s>",symbol_get_name(value->type));
	break;
    case DATATYPE_VOL:
	fprintf(ud->stream,"<UNSUPPORTED_VOL_%s>",symbol_get_name(value->type));
	break;
    case DATATYPE_TYPEDEF:	
	fprintf(ud->stream,"<UNSUPPORTED_TYPEDEF_%s>",
		symbol_get_name(value->type));
	break;
    case DATATYPE_FUNCTION:
	fprintf(ud->stream,"<UNSUPPORTED_FUNCTION_%s>",
		symbol_get_name(value->type));
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
