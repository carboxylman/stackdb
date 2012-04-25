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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>
#include <inttypes.h>

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

typedef int8_t REG;
#define PRIiREG PRIi8

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
