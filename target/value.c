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
 * Foundation, 51 Franklin St, Suite 500, Boston, MA 02110-1335, USA.
 */

#include "target.h"

struct value *value_create_raw(struct memregion *region,int len) {
    struct value *value;

    if (!(value = malloc(sizeof(struct value)))) 
	return NULL;
    memset(value,0,sizeof(struct value));

    value->region_stamp = region->stamp;
    value->buf = malloc(len);
    if (!value->buf) {
	free(value);
	return NULL;
    }
    value->bufsiz = len;

    return value;
}

struct value *value_create_type(struct memregion *region,struct symbol *type) {
    struct value *value;
    int len = symbol_type_full_bytesize(type);

    if (!(value = malloc(sizeof(struct value)))) 
	return NULL;
    memset(value,0,sizeof(struct value));

    value->type = type;
    value->region_stamp = region->stamp;
    value->buf = malloc(len);
    if (!value->buf) {
	free(value);
	return NULL;
    }
    value->bufsiz = len;

    return value;
}

struct value *value_create(struct bsymbol *bsymbol,struct symbol *type) {
    struct value *value = value_create_type(bsymbol->region,type);
    int len = symbol_type_full_bytesize(type);

    if (!value)
	return NULL;

    value->region_stamp = bsymbol->region->stamp;
    value->type = type;
    value->buf = malloc(len);
    if (!value->buf) {
	free(value);
	return NULL;
    }
    value->bufsiz = len;

    return value;
}

struct value *value_create_noalloc(struct bsymbol *bsymbol,
				   struct symbol *type) {
    struct value *value = value_create_type(bsymbol->region,type);

    if (!value)
	return NULL;

    value->region_stamp = bsymbol->region->stamp;
    value->type = type;

    return value;
}

void value_free(struct value *value) {
    if (value->ismmap)
	target_release_mmap_entry(value->region->space->target,value->mmap);
    else
	free(value->buf);

    free(value);
}

signed char      rvalue_c(void *buf)   { return *((signed char *)buf); }
unsigned char    rvalue_uc(void *buf)  { return *((unsigned char *)buf); }
wchar_t          rvalue_wc(void *buf)  { return *((wchar_t *)buf); }
uint8_t          rvalue_u8(void *buf)  { return *((uint8_t *)buf); }
uint16_t         rvalue_u16(void *buf) { return *((uint16_t *)buf); }
uint32_t         rvalue_u32(void *buf) { return *((uint32_t *)buf); }
uint64_t         rvalue_u64(void *buf) { return *((uint64_t *)buf); }
int8_t           rvalue_i8(void *buf)  { return *((int8_t *)buf); }
int16_t          rvalue_i16(void *buf) { return *((int16_t *)buf); }
int32_t          rvalue_i32(void *buf) { return *((int32_t *)buf); }
int64_t          rvalue_i64(void *buf) { return *((int64_t *)buf); }
