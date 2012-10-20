/*
 * Copyright (c) 2012 The University of Utah
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

/*
 *  examples/nfs-perf-analysis/nfs-perf.c
 * 
 *  DBG*, ERR*, WARN* declarations
 *
 *  Authors: Anton Burtsev, aburtsev@flux.utah.edu
 * 
 */

#ifndef __NFS_PERF_DEBUG_H__
#define __NFS_PERF_DEBUG_H__

#include <stdio.h>
#include "perf.h"

/*
 * Escape codes for controlling text color, brightness, etc.
 */

#define TXT_CLRSCREEN           "\e[2J"
#define TXT_NORMAL              "\e[0m"
#define TXT_BRIGHT              "\e[1m"
#define TXT_REVERSED            "\e[7m"
#define TXT_FG_BLACK            "\e[30m"
#define TXT_FG_RED              "\e[31m"
#define TXT_FG_GREEN            "\e[32m"
#define TXT_FG_YELLOW           "\e[33m"
#define TXT_FG_BLUE             "\e[34m"
#define TXT_FG_MAGENTA          "\e[35m"
#define TXT_FG_CYAN             "\e[36m"
#define TXT_FG_WHITE            "\e[37m"
#define TXT_BG_BLACK            "\e[40m"
#define TXT_BG_RED              "\e[41m"
#define TXT_BG_GREEN            "\e[42m"
#define TXT_BG_YELLOW           "\e[43m"
#define TXT_BG_BLUE             "\e[44m"
#define TXT_BG_MAGENTA          "\e[45m"
#define TXT_BG_CYAN             "\e[46m"
#define TXT_BG_WHITE            "\e[47m"

#define TXT_FG_COLOR            TXT_FG_WHITE

extern struct target *t;

#define ERR(_f, _a...)   do {                                                   \
        printf(TXT_FG_RED"Error" TXT_FG_WHITE "(brctr:%llu):%s " _f, perf_get_brctr(t),  __FUNCTION__, ## _a);  \
    } while (0)

#define WARN(_f, _a...)  do {                                                   \
        printf(TXT_FG_YELLOW "Warrning" TXT_FG_WHITE "(brctr:%llu):%s " _f, perf_get_brctr(t), __FUNCTION__, ## _a);  \
    } while (0)

#define WARN_ON(_g, _f, _a...) do {                                             \
        if (_g) {                                                               \
            WARN(_f, ## _a);                                                    \
        }                                                                       \
    } while (0)

#define DBG(_f, _a...)   do {                                                   \
        printf(TXT_FG_COLOR "DBG" TXT_FG_WHITE "(brctr:%llu):%s " _f, perf_get_brctr(t), __FUNCTION__, ## _a);       \
    } while (0)

#define DBG_ON(_g, _f, _a...) do {                                              \
        if (_g) {                                                               \
            DBG(_f, ## _a);                                                     \
        }                                                                       \
    } while (0)

#define LOG(_f, _a...)   do {                                                   \
        printf("" _f, ##_a);                                                    \
    } while (0)

#define ERR_ON(_g, _f, _a...) do {                                              \
        if (_g) {                                                               \
            ERR(_f, ## _a);                                                     \
        }                                                                       \
    } while (0)

#define LOG_ON(_g, _f, _a...) do {                                              \
        if (_g) {                                                               \
            LOG(_f, ## _a);                                                     \
        }                                                                       \
    } while (0)

#define DBG_DUMP( _p, _len_p, _max_len) do {                                        \
        int _i, _j;                                                                 \
        unsigned long _len = _len_p;                                                \
                                                                                    \
        if ( (_max_len) && (_len > _max_len)) {                                     \
            _len = _max_len;                                                        \
            fprintf("Buffer exceeds max length, dumping first %i bytes\n", _max_len); \
        }                                                                           \
                                                                                    \
        for ( _i = 0; _i < (_len); ) {                                              \
            for ( _j = 0; ( _j < 16) && (_i < (_len)); _j++, _i++ ) {               \
                fprintf("%02x ", (unsigned char)*((char *)(_p) + _i) );             \
            }                                                                       \
            fprintf(stderr, "\n");                                                  \
        }                                                                           \
        fprintf("\n");                                                              \
    } while (0)

    #define DBG_DUMP_ON(_g, _p, _len_p, _max_len) do {                              \
            if (_g) {                                                               \
                DBG_DUMP(_p, _len_p, _max_len);                                     \
            }                                                                       \
    } while (0)

#endif /* __NFS_PERF_DEBUG_H__ */
