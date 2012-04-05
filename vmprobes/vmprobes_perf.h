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

#ifndef _VMPROBE_PERF_H
#define _VMPROBE_PERF_H

#ifdef VMPROBE_BENCHMARK

#define VMPROBE_CPU_HZ     (2992.792*1024*1024) /* 3GHz */
#define VMPROBE_PERF_ROUND (100)
#define VMPROBE_PERF_STEP  (50)

#define VMPROBE_PERF_RESET()    __perf_reset()
#define VMPROBE_PERF_START()    __perf_start()
#define VMPROBE_PERF_STOP(desc) __perf_stop(desc); __perf_next_step()
#define VMPROBE_PERF_NEXT()     __perf_next_round()
#define VMPROBE_PERF_PRINT()    __perf_print()

struct vmprobe_perf
{
    unsigned long long start, stop;
    char *desc;
};

static struct vmprobe_perf __perf[VMPROBE_PERF_ROUND][VMPROBE_PERF_STEP];
static unsigned long __round, __steps[VMPROBE_PERF_ROUND];

static inline unsigned long long
__rdtsc(void)
{
    unsigned long temp1;
    unsigned long temp2;
    unsigned long long tsc;
    asm volatile(
        "rdtsc\t\n"
        "movl %%eax, %0\t\n"
        "movl %%edx, %1\t\n"
        : "=m" (temp1), "=m" (temp2)
        :
        : "%eax", "%edx");
    tsc = (((unsigned long long)temp2) << 32) + temp1;
    return tsc;
}

static inline long double
__ctos(unsigned long long cycles)
{
    return ((long double)cycles / VMPROBE_CPU_HZ);
}

static inline void
__perf_reset(void)
{
    memset(__perf, 0, sizeof(struct vmprobe_perf) * VMPROBE_PERF_ROUND * 
        VMPROBE_PERF_STEP);
    __round = 0;
    memset(__steps, 0, sizeof(unsigned long) * VMPROBE_PERF_ROUND);
}

static inline void
__perf_next_round(void)
{
    __round++;
}

static inline void
__perf_next_step(void)
{
    __steps[__round]++;
}

static inline void
__perf_start()
{
    struct vmprobe_perf *perf = &__perf[__round][__steps[__round]];
    perf->start = __rdtsc();
}

static inline void
__perf_stop(const char *desc)
{
    struct vmprobe_perf *perf = &__perf[__round][__steps[__round]];
    perf->stop = __rdtsc();
    perf->desc = (char *)desc;
}

static inline void
__perf_print()
{
    struct vmprobe_perf *perf;
    unsigned long long cycle;
    unsigned long r, s;
    for (r = 0; r < __round; r++)
    {
        printf("< ROUND %03ld > -----------------------------------------------"
            "-------------------\n", (r+1));
        for (s = 0; s < __steps[r]; s++)
        {
            perf = &__perf[r][s];
            cycle = perf->stop - perf->start;
            //printf("[%3ld] %8lld cycles (%8Lf ms): %s\n", (s+1), cycle,
            //    __ctos(cycle) * 1000, perf->desc);
            printf("[%3ld] <%lld - %lld> %8lld cycles (%8Lf ms): %s\n", (s+1), 
                perf->start, perf->stop, cycle, __ctos(cycle) * 1000, 
                perf->desc);
        }
        cycle = __perf[r][s-1].stop - __perf[r][0].start;
        printf("TOTAL: %7lld cycles (%8Lf ms)\n", cycle, __ctos(cycle) * 1000);
        printf("---------------------------------------------------------------"
            "-----------------\n");
        printf("\n");
    }
}

#else /* VMPROBE_BENCHMARK */

#define VMPROBE_PERF_RESET()    ((void)0)
#define VMPROBE_PERF_START()    ((void)0)
#define VMPROBE_PERF_STOP(desc) ((void)0)
#define VMPROBE_PERF_NEXT()     ((void)0)
#define VMPROBE_PERF_PRINT()    ((void)0)

#endif /* VMPROBE_BENCHMARK */

#endif /* _VMPROBE_PERF_H */
