/*
 * ARM64 kexec elf support.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <libfdt.h>

#include <linux/elf.h>

#include "dt-ops.h"
#include "crashdump-arm64.h"
#include "kexec-arm64.h"
#include "fs2dt.h"
#include "kexec-syscall.h"
#include "arch/options.h"

int elf_arm64_probe(const char *kernel_buf, off_t kernel_size)
{
	int result;
	struct mem_ehdr ehdr;

	result = build_elf_exec_info(kernel_buf, kernel_size, &ehdr, 0);

	if (result < 0) {
		dbgprintf("%s: Not an ELF executable.\n", __func__);
		goto on_exit;
	}

	if (ehdr.e_machine != EM_AARCH64) {
		dbgprintf("%s: Not an AARCH64 ELF executable.\n", __func__);
		result = -EINVAL;
		goto on_exit;
	}

	result = 0;

on_exit:
	free_elf_info(&ehdr);
	return result;
}

int elf_arm64_load(int argc, char **argv, const char *kernel_buf,
	off_t kernel_size, struct kexec_info *info)
{
	int result;
	struct mem_ehdr ehdr;
	bool found_header;
	int i;

	if (info->kexec_flags & KEXEC_ON_CRASH) {
		fprintf(stderr, "kexec: kdump not yet supported on arm64\n");
		return -EINVAL;
	}

	result = build_elf_exec_info(kernel_buf, kernel_size, &ehdr, 0);

	if (result < 0) {
		dbgprintf("%s: build_elf_exec_info failed\n", __func__);
		goto exit;
	}

	/* Find and process the arm64 image header. */

	for (i = 0, found_header = false; i < ehdr.e_phnum; i++) {
		struct mem_phdr *phdr = &ehdr.e_phdr[i];
		const struct arm64_image_header *h;

		if (phdr->p_type != PT_LOAD)
			continue;

		h = (const struct arm64_image_header *)(kernel_buf
			+ phdr->p_offset);

		if (arm64_process_image_header(h))
			continue;

		found_header = true;

		arm64_mem.page_offset = phdr->p_vaddr - arm64_mem.text_offset;

		dbgprintf("%s: PE format: %s\n", __func__,
			(arm64_header_check_pe_sig(h) ? "yes" : "no"));
		dbgprintf("p_vaddr: %016llx\n", phdr->p_vaddr);

		break;
	}

	if (!found_header) {
		fprintf(stderr, "kexec: Bad arm64 image header.\n");
		result = -EINVAL;
		goto exit;
	}

	result = elf_exec_load(&ehdr, info);

	if (result) {
		fprintf(stderr, "kexec: Elf load failed.\n");
		goto exit;
	}

	dbgprintf("%s: text_offset: %016lx\n", __func__, arm64_mem.text_offset);
	dbgprintf("%s: image_size:  %016lx\n", __func__, arm64_mem.image_size);
	dbgprintf("%s: page_offset: %016lx\n", __func__, arm64_mem.page_offset);
	dbgprintf("%s: memstart:    %016lx\n", __func__, arm64_mem.memstart);
	dbgprintf("%s: e_entry:     %016llx -> %016lx\n", __func__,
		ehdr.e_entry, virt_to_phys(ehdr.e_entry));

	result = arm64_load_other_segments(info, virt_to_phys(ehdr.e_entry));
exit:
	free_elf_info(&ehdr);
	return result;
}

void elf_arm64_usage(void)
{
	printf(
"     An arm64 ELF file, big or little endian.\n"
"     Typically vmlinux or a stripped version of vmlinux.\n\n");
}
