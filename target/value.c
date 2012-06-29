/*
 * Copyright (c) 2011, 2012 The University of Utah
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

struct value *value_create_raw(int len) {
    struct value *value;

    if (!(value = malloc(sizeof(struct value)))) 
	return NULL;
    memset(value,0,sizeof(struct value));

    value->buf = malloc(len);
    if (!value->buf) {
	free(value);
	return NULL;
    }
    value->bufsiz = len;

    return value;
}

struct value *value_create_type(struct symbol *type) {
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

    symbol_hold(type);

    value->type = type;
    value->buf = malloc(len);
    if (!value->buf) {
	free(value);
	return NULL;
    }
    value->bufsiz = len;

    return value;
}

struct value *value_create(struct lsymbol *lsymbol,struct symbol *type) {
    struct value *value = value_create_type(type);

    if (!value)
	return NULL;

    if (lsymbol) {
	lsymbol_hold(lsymbol);
	value->lsymbol = lsymbol;
    }

    return value;
}

struct value *value_create_noalloc(struct lsymbol *lsymbol,
				   struct symbol *type) {
    struct value *value = value_create_type(type);

    if (!value)
	return NULL;

    if (lsymbol) {
	lsymbol_hold(lsymbol);
	value->lsymbol = lsymbol;
    }

    value->type = type;

    return value;
}

void value_free(struct value *value) {
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
	symbol_release(value->type);

    if (value->lsymbol)
	lsymbol_release(value->lsymbol);

    free(value);
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
ADDR             v_addr(struct value *v){ return *((ADDR *)v->buf); }

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
int value_update_addr(struct value *value,ADDR v) {
    if (value->bufsiz <= (signed)sizeof(ADDR)) {
	memcpy(value->buf,&v,value->bufsiz);
    }
    else /* if (value->bufsiz > sizeof(ADDR)) */ {
	memcpy(value->buf,&v,sizeof(ADDR));
    }
    return 0;
}
int value_update_num(struct value *value,int64_t v) {
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
int value_update_unum(struct value *value,uint64_t v) {
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
ADDR             rv_addr(void *buf){ return *((ADDR *)buf); }
