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

#include "internal.h"

#if CONFIG_NANOZONE

// Possible enablement modes for Nano V2
typedef enum {
	NANO_ENABLED,	// Available and default if Nano is turned on.
	NANO_FORCED,	// Force use of Nano V2 for all processes.
	NANO_CONDITIONAL,	// Use Nano V2 in non space-efficient processes
} nanov2_mode_t;

// Whether Nano is engaged. By default, none.
nano_version_t _malloc_engaged_nano = NANO_NONE;

// Nano mode selection boot argument
static const char mode_boot_arg[] = "nanov2_mode";
static const char enabled_mode[] = "enabled";	// Use Nano V2 for Nano
static const char forced_mode[] = "forced";		// Force Nano V2 everywhere
static const char conditional_mode[] = "conditional"; // Use Nano V2 in non space-efficient processes

// The maximum number of per-CPU allocation regions to use for Nano.
unsigned int nano_common_max_magazines;
bool nano_common_max_magazines_is_ncpu = true;

unsigned int nano_max_region = NANOV2_MAX_REGION_NUMBER;

// Boot argument for nano_common_max_magazines
static const char nano_max_magazines_boot_arg[] = "malloc_nano_max_magazines";


#pragma mark -
#pragma mark Initialization

// Shared initialization code. Determines which version of Nano should be used,
// if any, and sets _malloc_engaged_nano. The Nano version is determined as
// follows:
// 1. If the nanov2_mode boot arg has value "forced", Nano V2 is used
//		unconditionally in every process
// 2. If the nanov2_mode boot arg has value "enabled", Nano V2 is used if
//		the process wants to use Nano
void
nano_common_init(const char *envp[], const char *apple[], const char *bootargs)
{
	const char *flag = NULL;
	const char *p = NULL;

	// Use the nanov2_mode boot argument and MallocNanoZone to determine
	// whether to use nano
	nanov2_mode_t nanov2_mode = NANOV2_DEFAULT_MODE;

	p = malloc_common_value_for_key(bootargs, mode_boot_arg);
	if (p) {
		if (!strncmp(p, enabled_mode, sizeof(enabled_mode) - 1)) {
			nanov2_mode = NANO_ENABLED;
		} else if (!strncmp(p, forced_mode, sizeof(forced_mode) - 1)) {
			nanov2_mode = NANO_FORCED;
		} else if (!strncmp(p, conditional_mode, sizeof(conditional_mode) - 1)) {
			nanov2_mode = NANO_CONDITIONAL;
		}
	}

	if (nanov2_mode == NANO_FORCED) {
		_malloc_engaged_nano = NANO_V2;
	} else {
		if (nanov2_mode == NANO_CONDITIONAL) {
			// If conditional mode is selected, ignore the apple[] array and
			// make the decision based of space efficient mode.
			_malloc_engaged_nano = malloc_space_efficient_enabled ? NANO_NONE : NANO_V2;
		} else {
			flag = _simple_getenv(apple, "MallocNanoZone");
			if (flag && flag[0] == '1') {
				_malloc_engaged_nano = NANO_V2;
			}
		}
		/* Explicit overrides from the environment */
		flag = _simple_getenv(envp, "MallocNanoZone");
		if (flag) {
			if (flag[0] == '1') {
				_malloc_engaged_nano = NANO_V2;
			} else if (flag[0] == '0') {
				_malloc_engaged_nano = NANO_NONE;
			} else if (flag[0] == 'V' || flag[0] == 'v') {
				if (flag[1] == '1' || flag[1] == '2') {
					_malloc_engaged_nano = NANO_V2;
				}
			}
		}
	}
#if NANOV2_MULTIPLE_REGIONS
	// Override max region number from environment
	p = malloc_common_value_for_key(bootargs, "malloc_nano_max_region");
	if (p) {
		long value = strtol(p, NULL, 10);
		if (value) {
			if (value > NANOV2_MAX_REGION_NUMBER) {
				nano_max_region = NANOV2_MAX_REGION_NUMBER;
				malloc_report(ASL_LEVEL_INFO, "Capping 'malloc_nano_max_region' to %d\n", nano_max_region);
			} else if (value >= 0) {
				nano_max_region = (unsigned int)value;
			} else {
				malloc_report(ASL_LEVEL_ERR, "Received invalid value for 'malloc_nano_max_region': %d\n", (int)value);
			}
		}
	}
	flag = _simple_getenv(envp, "MallocNanoMaxRegion");
	if (flag) {
		long value = strtol(flag, NULL, 10);
		if (value) {
			if (value > NANOV2_MAX_REGION_NUMBER) {
				nano_max_region = NANOV2_MAX_REGION_NUMBER;
				malloc_report(ASL_LEVEL_INFO, "Capping 'MallocNanoMaxRegion' to %d\n", nano_max_region);
			} else if (value >= 0) {
				nano_max_region = (unsigned int)value;
			} else {
				malloc_report(ASL_LEVEL_ERR, "Received invalid value for 'MallocNanoMaxRegion': %d\n", (int)value);
			}
		}
	}
#endif // NANOV2_MULTIPLE_REGIONS
	if (_malloc_engaged_nano) {
		// The maximum number of nano magazines can be set either via a
		// boot argument or from the environment. Get the boot argument value
		// here and store it. We can't bounds check it until we have phys_ncpus,
		// which happens later in nano_common_configure(), along with handling
		// of the environment value setting.
		char value_buf[256];
		const char *flag = malloc_common_value_for_key_copy(bootargs,
				nano_max_magazines_boot_arg, value_buf, sizeof(value_buf));
		if (flag) {
			const char *endp;
			long value = malloc_common_convert_to_long(flag, &endp);
			if (!*endp && value >= 0) {
				nano_common_max_magazines = (unsigned int)value;
			} else {
				malloc_report(ASL_LEVEL_ERR,
					"malloc_nano_max_magazines must be positive - ignored.\n");
			}
		}
	}

	switch (_malloc_engaged_nano) {
	case NANO_V2:
		nanov2_init(envp, apple, bootargs);
		break;
	default:
		break;
	}
}

// Second phase of initialization, called from _malloc_initialize(). Used for
// code that depends on state set in _malloc_initialize(), such as the
// number of physical CPUs.
void
nano_common_configure(void)
{
	// Set nano_common_max_magazines. An initial (unvalidated) value may have
	// been set from the boot args.
	unsigned int magazines = nano_common_max_magazines > 0 ?
			nano_common_max_magazines : phys_ncpus;

	// Environment variable overrides boot arg, unless it's not valid.
	const char *flag = getenv("MallocNanoMaxMagazines");
#if RDAR_48993662
	if (!flag) {
		flag = getenv("_MallocNanoMaxMagazines");
	}
#endif // RDAR_48993662
	if (flag) {
		int value = (int)strtol(flag, NULL, 0);
		if (value < 0) {
			malloc_report(ASL_LEVEL_ERR,
					"MallocNanoMaxMagazines must be positive - ignored.\n");
		} else {
			magazines = value;
		}
	}

	if (magazines == 0) {
		magazines = phys_ncpus;
	} else if (magazines > phys_ncpus) {
		magazines = phys_ncpus;
		malloc_report(ASL_LEVEL_ERR,
				"Nano maximum magazines limited to number of physical "
				"CPUs [%d]\n", phys_ncpus);
	}
	nano_common_max_magazines = magazines;
	if (flag) {
		malloc_report(ASL_LEVEL_INFO, "Nano maximum magazines set to %d\n",
					   nano_common_max_magazines);
	}
	nano_common_cpu_number_override_set();

	switch (_malloc_engaged_nano) {
	case NANO_V2:
		nanov2_configure();
		break;
	default:
		break;
	}
}

#pragma mark -
#pragma mark VM Helper Functions

void *
nano_common_allocate_based_pages(size_t size, unsigned char align,
		unsigned debug_flags, int vm_page_label, void *base_addr)
{
	mach_vm_address_t vm_addr;
	uintptr_t addr;
	mach_vm_size_t allocation_size = round_page(size);
	mach_vm_offset_t allocation_mask = ((mach_vm_offset_t)1 << align) - 1;
	int alloc_flags = VM_FLAGS_ANYWHERE | VM_MAKE_TAG(vm_page_label);
	kern_return_t kr;

	if (!allocation_size) {
		allocation_size = vm_page_size;
	}
	if (allocation_size < size) { // size_t arithmetic wrapped!
		return NULL;
	}

	vm_addr = round_page((mach_vm_address_t)base_addr);
	if (!vm_addr) {
		vm_addr = vm_page_size;
	}
	kr = mach_vm_map(mach_task_self(), &vm_addr, allocation_size,
			allocation_mask, alloc_flags, MEMORY_OBJECT_NULL, 0, FALSE,
			VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
	if (kr) {
		if (kr != KERN_NO_SPACE) {
			malloc_zone_error(debug_flags, false, "*** can't allocate pages: "
					"mach_vm_map(size=%lu) failed (error code=%d)\n", size, kr);
		}
		return NULL;
	}
	addr = (uintptr_t)vm_addr;

	return (void *)addr;
}

static boolean_t
_nano_common_map_vm_space(mach_vm_address_t base, mach_vm_size_t size, 
		vm_prot_t cur_protection)
{
	mach_vm_address_t vm_addr = base;

	kern_return_t kr = mach_vm_map(mach_task_self(), &vm_addr, size, 0,
		VM_MAKE_TAG(VM_MEMORY_MALLOC_NANO), MEMORY_OBJECT_NULL, 0, FALSE,
		cur_protection, VM_PROT_ALL, VM_INHERIT_DEFAULT);

	if (kr != KERN_SUCCESS) {
		return FALSE;
	} else if (vm_addr != base) {
		// allocated somewhere else
		mach_vm_deallocate(mach_task_self(), vm_addr, size);
		return FALSE;
	}
	return TRUE;
}

// Allocates virtual address from a given address for a given size. Succeeds
// (and returns TRUE) only if we get exactly the range of addresses that we
// asked for.
bool
nano_common_allocate_vm_space(mach_vm_address_t base, mach_vm_size_t size)
{
	return _nano_common_map_vm_space(base, size, VM_PROT_DEFAULT);
}

// Reserve virtual address range by allocating without perimissions
bool
nano_common_reserve_vm_space(mach_vm_address_t base, mach_vm_size_t size)
{
	return _nano_common_map_vm_space(base, size, VM_PROT_NONE);
}

// Set protection to default for address range. Return true on success.
bool
nano_common_unprotect_vm_space(mach_vm_address_t base, mach_vm_size_t size)
{
	kern_return_t kr = mach_vm_protect(mach_task_self(), base,
			size, false, VM_PROT_DEFAULT);
	if (kr != KERN_SUCCESS) {
		malloc_report(ASL_LEVEL_ERR, "mach_vm_protect ret: %d\n", kr);
		return false;
	}
	return true;
}

void
nano_common_deallocate_pages(void *addr, size_t size, unsigned debug_flags)
{
	mach_vm_address_t vm_addr = (mach_vm_address_t)addr;
	mach_vm_size_t allocation_size = size;
	kern_return_t kr;

	kr = mach_vm_deallocate(mach_task_self(), vm_addr, allocation_size);
	if (kr) {
		malloc_zone_error(debug_flags, false, "Can't deallocate_pages at %p\n",
				addr);
	}
}

#pragma mark -
#pragma mark Introspection Helper Functions

kern_return_t
nano_common_default_reader(task_t task, vm_address_t address, vm_size_t size,
		void **ptr)
{
	*ptr = (void *)address;
	return 0;
}

#pragma mark -
#pragma mark Utility functions

void
nano_common_cpu_number_override_set()
{
	boolean_t is_ncpu = _os_cpu_number_override == -1 && nano_common_max_magazines == phys_ncpus;
	
	// This facilitates a shortcut in nanov2_get_allocation_block_index() --
	// if nano_common_max_magazines_is_ncpu is true, we can also assume that
	// _os_cpu_number_override == -1 (i.e. we are not in malloc_replay).
	//
	// We check here for false, because we don't want to write "true" to a __DATA page because
	// that would make it dirty: <rdar://problem/46994833>
	if (!is_ncpu) {
		nano_common_max_magazines_is_ncpu = is_ncpu;
	}
}

#endif // CONFIG_NANOZONE

