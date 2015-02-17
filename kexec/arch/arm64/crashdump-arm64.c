/*
 * crashdump for arm64
 *
 * Copyright (C) Nokia Corporation, 2010.
 * Author: Mika Westerberg
 *
 * Based on x86 implementation
 * Copyright (C) IBM Corporation, 2005. All rights reserved
 *
 * Copyright (c) 2014 Linaro Limited
 * Author: AKASHI Takahiro <takahiro.akashi@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define _GNU_SOURCE /* for asprintf */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/elf.h>

#include "kexec.h"
#include "crashdump.h"
#include "crashdump-arm64.h"
#include "kexec-arm64.h"
#include "kexec-elf.h"

/*
 * Used to save various memory ranges/regions needed for the captured
 * kernel to boot. (like memmap= option in other archs)
 */
static struct memory_range crash_memory_ranges[CRASH_MAX_MEMORY_RANGES];
struct memory_ranges crashmem_rgns = {
	.size = 0,
	.ranges = crash_memory_ranges,
};

/* memory range reserved for crashkernel */
struct memory_range crash_reserved_mem;
struct memory_ranges usablemem_rgns = {
	.size = 0,
	.ranges = &crash_reserved_mem,
};

static struct crash_elf_info elf_info = {
	.class		= ELFCLASS64,
#if (__BYTE_ORDER == __LITTLE_ENDIAN)
	.data		= ELFDATA2LSB,
#else
	.data		= ELFDATA2MSB,
#endif
	.machine	= EM_AARCH64,
};

int is_crashkernel_mem_reserved(void)
{
	uint64_t start, end;

	if (parse_iomem_single("Crash kernel\n", &start, &end) == 0)
		return start != end;

	return 0;
}

/*
 * crash_range_callback() - callback called for each iomem region
 * @data: not used
 * @nr: not used
 * @str: name of the memory region
 * @base: start address of the memory region
 * @length: size of the memory region
 *
 * This function is called once for each memory region found in /proc/iomem.
 * It locates system RAM and crashkernel reserved memory and places these to
 * variables: @crash_memory_ranges and @crash_reserved_mem. Number of memory
 * regions is placed in @crash_memory_nr_ranges.
 */

static int crash_range_callback(void *UNUSED(data), int UNUSED(nr),
				char *str, unsigned long long base,
				unsigned long long length)
{
	struct memory_range *range;

	if (crashmem_rgns.size >= CRASH_MAX_MEMORY_RANGES)
		return 1;

	range = crashmem_rgns.ranges + crashmem_rgns.size;

	if (strncmp(str, "System RAM\n", 11) == 0) {
		range->start = base;
		range->end = base + length - 1;
		range->type = RANGE_RAM;
		crashmem_rgns.size++;
	} else if (strncmp(str, "Crash kernel\n", 13) == 0) {
		if (base < arm64_mem.memstart)
			base += arm64_mem.memstart;
		crash_reserved_mem.start = base;
		crash_reserved_mem.end = base + length - 1;
		crash_reserved_mem.type = RANGE_RAM;
		usablemem_rgns.size++;
	}

	return 0;
}

/*
 * crash_exclude_range() - excludes memory region reserved for crashkernel
 *
 * Function locates where crashkernel reserved memory is and removes that
 * region from the available memory regions.
 */
static void crash_exclude_range(void)
{
	const struct memory_range *range = &crash_reserved_mem;
	int i;

	for (i = 0; i < crashmem_rgns.size; i++) {
		struct memory_range *r = crashmem_rgns.ranges + i;

		/*
		 * We assume that crash area is fully contained in
		 * some larger memory area.
		 */
		if (r->start <= range->start && r->end >= range->end) {
			struct memory_range *new;

			if (r->start == range->start) {
				if (r->end == range->end) {
					memcpy(r, r + 1,
						sizeof(r)
						* (crashmem_rgns.size - i - 1));
					crashmem_rgns.size--;
				} else {
					r->start = range->end + 1;
				}
				break;
			}
			if (r->end == range->end) {
				r->end = range->start - 1;
				break;
			}

			/*
			 * Let's split this area into 2 smaller ones and
			 * remove excluded range from between. First create
			 * new entry for the remaining area.
			 */
			new = crashmem_rgns.ranges + crashmem_rgns.size;
			new->start = range->end + 1;
			new->end = r->end;
			crashmem_rgns.size++;
			/*
			 * Next update this area to end before excluded range.
			 */
			r->end = range->start - 1;
			break;
		}
	}
}

/*
 * crash_get_memory_ranges() - read system physical memory
 *
 * Function reads through system physical memory and stores found memory
 * regions in @crash_memory_ranges. Number of memory regions found is placed
 * in @crash_memory_nr_ranges. Regions are sorted in ascending order.
 *
 * Returns %0 in case of success and %-1 otherwise (errno is set).
 */
static int crash_get_memory_ranges(void)
{
	/*
	 * First read all memory regions that can be considered as
	 * system memory including the crash area.
	 */
	kexec_iomem_for_each_line(NULL, crash_range_callback, NULL);

	if (usablemem_rgns.size != 1) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * Exclude memory reserved for crashkernel (this may result int
	 * split memory regions).
	 */
	/*
	 * FIXME:
	 * Do we have to check crashkernel is within main memory?
	 */
	crash_exclude_range();

	return 0;
}

/*
 * range_size - Return range size in MiB.
 */

static unsigned long range_size(const struct memory_range *r)
{
	return (r->end - r->start + 1) >> 20;
}

static void dump_crash_ranges(void)
{
	int i;

	if (!kexec_debug)
		return;

	dbgprintf("%s: kernel: %016llx - %016llx (%ld MiB)\n", __func__,
		  crash_reserved_mem.start, crash_reserved_mem.end,
		  range_size(&crash_reserved_mem));

	for (i = 0; i < crashmem_rgns.size; i++) {
		struct memory_range *r = crashmem_rgns.ranges + i;
		dbgprintf("%s: RAM:    %016llx - %016llx (%ld MiB)\n", __func__,
			  r->start, r->end, range_size(r));
	}
}

/*
 * load_crashdump_segments() - create elf core header for /proc/vmcore
 * @info: kexec info structure
 * @option: To be appended to kernel command line
 *
 * This function loads additional segments which are needed for the dump
 * capture kernel. It also updates kernel command line passed in
 * @command_line_extra to have the correct parameters for the dump capture
 * kernel.
 *
 * Return %0 in case of success and %-1 in case of error.
 */

int load_crashdump_segments(struct kexec_info *info, char **option)
{
	unsigned long elfcorehdr;
	unsigned long bufsz;
	void *buf;
	int err;

	/*
	 * First fetch all the memory (RAM) ranges that we are going to
	 * pass to the crashdump kernel during panic.
	 */

	err = crash_get_memory_ranges();

	if (err)
		return err;

	dump_crash_ranges();

	elf_info.page_offset = arm64_mem.page_offset;

	err = crash_create_elf64_headers(info, &elf_info, crashmem_rgns.ranges,
		crashmem_rgns.size, &buf, &bufsz, ELF_CORE_HEADER_ALIGN);

	if (err)
		return err;

	elfcorehdr = add_buffer_phys_virt(info, buf, bufsz, bufsz, 0,
		crash_reserved_mem.start, crash_reserved_mem.end,
		-1, 0);

	err = asprintf(option, " elfcorehdr=%#lx@%#lx", bufsz, elfcorehdr);

	if (err == -1)
		return err;

	dbgprintf("%s:%s\n", __func__, *option);

	return 0;
}

void modify_ehdr_for_crashdump(struct mem_ehdr *ehdr)
{
	struct mem_phdr *phdr;
	int i;

	ehdr->e_entry += crash_reserved_mem.start;

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = &ehdr->e_phdr[i];
		if (phdr->p_type != PT_LOAD)
			continue;
		phdr->p_paddr +=
			(-arm64_mem.memstart + crash_reserved_mem.start);
	}
}

void *get_crash_entry(void)
{
	return (void *)crash_reserved_mem.start + arm64_mem.text_offset;
}
