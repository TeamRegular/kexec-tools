/*
 * ARM64 kexec binary image support.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <libfdt.h>

#include "dt-ops.h"
#include "image-header.h"
#include "kexec-arm64.h"
#include "fs2dt.h"
#include "kexec-syscall.h"
#include "arch/options.h"

int image_arm64_probe(const char *kernel_buf, off_t kernel_size)
{
	const struct arm64_image_header *h;

	if (kernel_size < sizeof(struct arm64_image_header))
		return -EINVAL;

	h = (const struct arm64_image_header *)(kernel_buf);

	if (!arm64_header_check_magic(h))
		return -1;

	dbgprintf("%s: PE format: %s\n", __func__,
		(arm64_header_check_pe_sig(h) ? "yes" : "no"));

	fprintf(stderr, "kexec: arm64 binary Image files are currently NOT SUPPORTED.\n");

	return -1;
}

int image_arm64_load(int argc, char **argv, const char *kernel_buf,
	off_t kernel_size, struct kexec_info *info)
{
	return -ENOSYS;
}

void image_arm64_usage(void)
{
	printf(
"     An arm64 binary Image file, big or little endian.\n"
"     This file type is currently NOT SUPPORTED.\n\n");
}
