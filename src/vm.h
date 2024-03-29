/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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


#ifndef __VM_H
#define __VM_H

static inline bool
mvm_aslr_enabled(void)
{
	extern struct mach_header __dso_handle;
	return _dyld_get_image_slide(&__dso_handle);
}

MALLOC_NOEXPORT
void
mvm_aslr_init(void);

MALLOC_NOEXPORT
void *
mvm_allocate_pages(size_t size, unsigned char align, uint32_t debug_flags, int vm_page_label);

MALLOC_NOEXPORT
void
mvm_deallocate_pages(void *addr, size_t size, unsigned debug_flags);

MALLOC_NOEXPORT
int
mvm_madvise_free(void *szone, void *r, uintptr_t pgLo, uintptr_t pgHi, uintptr_t *last, boolean_t scribble);

MALLOC_NOEXPORT
void
mvm_protect(void *address, size_t size, unsigned protection, unsigned debug_flags);

#if CONFIG_DEFERRED_RECLAIM
MALLOC_NOEXPORT
kern_return_t
mvm_deferred_reclaim_init(void);

MALLOC_NOEXPORT
bool
mvm_reclaim_mark_used(uint64_t id, mach_vm_address_t ptr, uint32_t size, unsigned int debug_flags);

MALLOC_NOEXPORT
uint64_t
mvm_reclaim_mark_free(vm_address_t ptr, uint32_t size, unsigned int debug_flags);

MALLOC_NOEXPORT
bool
mvm_reclaim_is_available(uint64_t id);
#endif // CONFIG_DEFERRED_RECLAIM

#endif // __VM_H
