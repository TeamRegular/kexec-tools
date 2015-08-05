/*
 * ARM64 crashdump.
 */

#if !defined(CRASHDUMP_ARM64_H)
#define CRASHDUMP_ARM64_H

#include "kexec.h"

#define CRASH_MAX_MEMORY_RANGES	32

extern struct memory_ranges usablemem_rgns;
extern struct memory_range crash_reserved_mem;

#endif
