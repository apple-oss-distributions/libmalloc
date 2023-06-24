/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef __NANO_MALLOC_COMMON_H
#define __NANO_MALLOC_COMMON_H

typedef enum {
	NANO_NONE	= 0,
	NANO_V2		= 2,
} nano_version_t;

// Nano malloc enabled flag
MALLOC_NOEXPORT
extern nano_version_t _malloc_engaged_nano;

// The maximum number of per-CPU allocation regions to use for Nano.
MALLOC_NOEXPORT
extern unsigned int nano_common_max_magazines;

MALLOC_NOEXPORT
extern bool nano_common_max_magazines_is_ncpu;

// Index of last region to be allocated
MALLOC_NOEXPORT
extern unsigned int nano_max_region;

MALLOC_NOEXPORT
void
nano_common_cpu_number_override_set(void);

MALLOC_NOEXPORT
void
nano_common_init(const char *envp[], const char *apple[], const char *bootargs);

MALLOC_NOEXPORT
void
nano_common_configure(void);

MALLOC_NOEXPORT
void *
nano_common_allocate_based_pages(size_t size, unsigned char align,
		unsigned debug_flags, int vm_page_label, void *base_addr);

MALLOC_NOEXPORT
bool
nano_common_allocate_vm_space(mach_vm_address_t base, mach_vm_size_t size);

MALLOC_NOEXPORT
bool
nano_common_reserve_vm_space(mach_vm_address_t base, mach_vm_size_t size);

MALLOC_NOEXPORT
bool
nano_common_unprotect_vm_space(mach_vm_address_t base, mach_vm_size_t size);

MALLOC_NOEXPORT
void
nano_common_deallocate_pages(void *addr, size_t size, unsigned debug_flags);

MALLOC_NOEXPORT
kern_return_t
nano_common_default_reader(task_t task, vm_address_t address, vm_size_t size,
		void **ptr);

#endif // __NANO_MALLOC_COMMON_H

