#if defined (VMPROBE_i386)
#include "vmprobes_i386.h"
#elif defined (VMPROBE_x86_64) || defined (VMPROBE_x86) || defined (VMPROBE_x64)
#include "vmprobes_x86_64.h"
#elif defined (VMPROBE_ppc) || defined (VMPROBE_powerpc)
#include "vmprobe_ppc.h"
#elif defined (VMPROBE_s390) || defined (VMPROBE_s390x)
#include "vmprobes_s390.h"
#else
#error "Hardware architecture not defined or supported"
#endif
