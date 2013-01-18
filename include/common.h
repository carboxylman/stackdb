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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>
#include <inttypes.h>

typedef enum {
    RESULT_SUCCESS = 0,
    RESULT_ERROR = 1,
    RESULT_ABORT = 2,
} result_t;

/*
 * For now, thread ids are a 32-bit int.  This is enough, for instance,
 * to do TIDs on Linux (because pids on 64-bit are still int32_ts. Note
 * that we have reserved INT32_MAX as our "global" identifier.
 */
typedef int32_t tid_t;
#define PRIiTID PRIi32

/* Might have to split these out into platform-specific stuff later; for
 * now, just make them big enough for anything.
 *
 * Also, we only support debugging 32-bit targets on a 32-bit host.  We
 * support 32-bit targets on a 64-bit host, but not the reverse for
 * now.  That case would only have meaning if we wanted to investigate a
 * non-live target (i.e., a 64-bit memory dump) on a 32-bit host.  Even
 * then, we would still need all the 64-bit debuginfo files... and they
 * wouldn't be likely to be on a 32-bit host.  SO, for now, we don't
 * support this case.
 */
#if __WORDSIZE == 64
typedef uint64_t ADDR;
typedef int64_t OFFSET;
typedef uint64_t REGVAL;
#define PRIxADDR PRIx64
#define PRIuADDR PRIu64
#define PRIiOFFSET PRIi64
#define PRIxOFFSET PRIx64
#define PRIxREGVAL PRIx64
#define PRIuREGVAL PRIu64
#define ADDRMAX UINT64_MAX
#define OFFSETMAX UINT64_MAX
#else
typedef uint32_t ADDR;
typedef int32_t OFFSET;
typedef uint32_t REGVAL;
#define PRIxADDR PRIx32
#define PRIuADDR PRIu32
#define PRIiOFFSET PRIi32
#define PRIxOFFSET PRIx32
#define PRIxREGVAL PRIx32
#define PRIuREGVAL PRIu32
#define ADDRMAX UINT32_MAX
#define OFFSETMAX UINT32_MAX
#endif

#ifndef ptr_t
#define ptr_t unsigned long int
#endif

/*
 * Define a "numeric" type; size should be the largest int for any
 * target, for now.  Later we might need something more
 * flexible... sigh.
 */
typedef int64_t num_t;
typedef uint64_t unum_t;
#define PRIuNUM PRIu64
#define PRIiNUM PRIi64
#define PRIxNUM PRIx64

typedef int8_t REG;
#define PRIiREG PRIi8

typedef enum {
    CREG_AX = 0,
    CREG_BX,
    CREG_CX,
    CREG_DX,
    CREG_DI,
    CREG_SI,
    CREG_BP,
    CREG_SP,
    CREG_IP,
    CREG_FLAGS,
    CREG_CS,
    CREG_SS,
    CREG_DS,
    CREG_ES,
    CREG_FS,
    CREG_GS,
} common_reg_t;
#define COMMON_REG_COUNT 16

/*
 * We use small offsets for DWARF offset addrs.  Saves mem in symbol
 * structures, which is very important.
 */
typedef int32_t SMOFFSET;
#define PRIiSMOFFSET PRIi32
#define PRIxSMOFFSET PRIx32

#define DATA_BIG_ENDIAN 0
#define DATA_LITTLE_ENDIAN 1

#define PROT_READ         0x1
#define PROT_WRITE        0x2
#define PROT_EXEC         0x4
#define PROT_SHARED       0x8

/*
 * Reference count stuff.
 */
typedef uint32_t REFCNT;

#define RHOLD(x)          ++((x)->refcnt)
#define RPUT(x,objtype)   --((x)->refcnt) == 0 ? objtype ## _free(x,0) \
	                                       : (x)->refcnt
#define RPUTFF(x,objtype) --((x)->refcnt) == 0 ? objtype ## _free(x,1) \
	                                       : objtype ## _free(x,1)
#define RPUTNF(x)         --((x)->refcnt)

#endif /* __COMMON_H__ */
