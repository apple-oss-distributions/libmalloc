/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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

#ifndef __INTERNAL_H
#define __INTERNAL_H

// Toggles for fixes for specific Radars. If we get enough of these, we
// probably should create a separate header file for them.
#define RDAR_48993662 1
#define OS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY 1

#ifdef DEBUG
#define QUEUE_MACRO_DEBUG
#endif

#include <Availability.h>
#include <TargetConditionals.h>
#include <_simple.h>
#include <platform/string.h>
#undef memcpy
#define memcpy _platform_memmove
#define _malloc_memcmp_zero_aligned8 _platform_memcmp_zero_aligned8
#include <platform/compat.h>
#include <assert.h>
#include <crt_externs.h>
#include <dirent.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <libc.h>
#include <libkern/OSAtomic.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_priv.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_time.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/shared_region.h>
#include <mach/thread_switch.h>
#include <mach/vm_map.h>
#include <mach/vm_page_size.h>
#include <mach/vm_param.h>
#include <mach/vm_reclaim.h>
#include <mach/vm_statistics.h>
#include <machine/cpu_capabilities.h>
#include <os/atomic_private.h>
#include <os/crashlog_private.h>
#include <os/lock_private.h>
#include <os/once_private.h>
#include <os/overflow.h>
#if !TARGET_OS_DRIVERKIT
# include <os/feature_private.h>
#endif
#include <os/tsd.h>
#include <paths.h>
#include <pthread/pthread.h>  // _pthread_threadid_self_np_direct()
#include <pthread/private.h>  // _pthread_threadid_self_np_direct()
#include <pthread/tsd_private.h>  // TSD keys

#include <ptrauth.h>

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <struct.h>
#include <sys/cdefs.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/random.h>
#include <sys/types.h>
#include <sys/vmparam.h>
#include <thread_stack_pcs.h>
#include <unistd.h>
#include <xlocale.h>

// pthread reserves 5 TSD keys for libmalloc
#define __TSD_MALLOC_PROB_GUARD_SAMPLE_COUNTER __PTK_LIBMALLOC_KEY0
#define __TSD_MALLOC_ZERO_CORRUPTION_COUNTER   __PTK_LIBMALLOC_KEY1
#define __TSD_MALLOC_THREAD_OPTIONS            __PTK_LIBMALLOC_KEY2
#define __TSD_MALLOC_TYPE_DESCRIPTOR           __PTK_LIBMALLOC_KEY3
#define __TSD_MALLOC_UNUSED4                   __PTK_LIBMALLOC_KEY4

#include "dtrace.h"
#include "base.h"
#include "trace.h"
#include "platform.h"
#include "debug.h"
#include "locking.h"
#include "bitarray.h"
#include "malloc/malloc.h"
#include "printf.h"
#include "early_malloc.h"
#include "frozen_malloc.h"
#include "legacy_malloc.h"
#include "magazine_malloc.h"
#include "malloc_common.h"
#include "nano_malloc_common.h"
#include "nanov2_malloc.h"
#include "pgm_malloc.h"
#include "sanitizer_malloc.h"
#include "purgeable_malloc.h"
#include "malloc_private.h"
#include "malloc/_malloc_type.h"  // public
#include "malloc_type_private.h"  // private
#include "malloc_type_internal.h" // project
#include "thresholds.h"
#include "vm.h"
#include "magazine_rack.h"
#include "magazine_zone.h"
#include "nano_zone_common.h"
#include "nano_zone.h"
#include "nanov2_zone.h"
#include "magazine_inline.h"
#include "xzone/xzone_malloc.h"
#include "xzone/xzone_inline_internal.h"
#include "stack_logging.h"
#include "stack_trace.h"
#include "malloc_implementation.h"

#pragma mark Memory Pressure Notification Masks

/* We will madvise unused memory on pressure warnings if either:
 *  - freed pages are not aggressively madvised by default
 *  - the large cache is enabled (and not enrolled in deferred reclamation)
 */
#if CONFIG_MADVISE_PRESSURE_RELIEF || (CONFIG_LARGE_CACHE && !CONFIG_DEFERRED_RECLAIM)
#define MALLOC_MEMORYSTATUS_MASK_PRESSURE_RELIEF ( \
		NOTE_MEMORYSTATUS_PRESSURE_WARN | \
		NOTE_MEMORYSTATUS_PRESSURE_NORMAL)
#else /* CONFIG_MADVISE_PRESSURE_RELIEF || (CONFIG_LARGE_CACHE && !CONFIG_DEFERRED_RECLAIM) */
#define MALLOC_MEMORYSTATUS_MASK_PRESSURE_RELIEF 0
#endif

/*
 * Resource Exception Reports are generated on process limits and
 * system-critical memory pressure.
 */
#if ENABLE_MEMORY_RESOURCE_EXCEPTION_HANDLING
#define MALLOC_MEMORYSTATUS_MASK_RESOURCE_EXCEPTION_HANDLING ( \
		NOTE_MEMORYSTATUS_PROC_LIMIT_WARN | \
		NOTE_MEMORYSTATUS_PROC_LIMIT_CRITICAL | \
		NOTE_MEMORYSTATUS_PRESSURE_CRITICAL )
#else /* ENABLE_MEMORY_RESOURCE_EXCEPTION_HANDLING */
#define MALLOC_MEMORYSTATUS_MASK_RESOURCE_EXCEPTION_HANDLING 0
#endif

/* MallocStackLogging.framework notification dependencies */
#define MSL_MEMORYPRESSURE_MASK ( NOTE_MEMORYSTATUS_PROC_LIMIT_WARN | \
		NOTE_MEMORYSTATUS_PROC_LIMIT_CRITICAL | \
		NOTE_MEMORYSTATUS_PRESSURE_CRITICAL )

/*
 * By default, libdispatch will register eligible processes for memory-pressure
 * notifications and register a notification handler. libdispatch's
 * notification handler will then call into malloc to return unused memory (see
 * `malloc_memory_event_handler()`). We export a mask to libdispatch so that it
 * will only register for notifications for which malloc is prepared to respond
 * to. Because MallocStackLogging.framework relies on its own subset of
 * notifications, we export two masks. libdispatch will initially register for
 * notifications of the `_DEFAULT` flavor. If MallocStackLogging.framework is
 * subsequently enabled, libdispatch will reregister for notifications with
 * the `_MSL` mask.
 */
#define MALLOC_MEMORYPRESSURE_MASK_DEFAULT ( NOTE_MEMORYSTATUS_MSL_STATUS | \
		MALLOC_MEMORYSTATUS_MASK_PRESSURE_RELIEF | \
		MALLOC_MEMORYSTATUS_MASK_RESOURCE_EXCEPTION_HANDLING )
#define MALLOC_MEMORYPRESSURE_MASK_MSL ( MALLOC_MEMORYPRESSURE_MASK_DEFAULT | \
		MSL_MEMORYPRESSURE_MASK )

#pragma mark Globals

MALLOC_NOEXPORT
extern bool malloc_tracing_enabled;

MALLOC_NOEXPORT
extern unsigned malloc_debug_flags;

MALLOC_NOEXPORT
extern bool malloc_space_efficient_enabled;

MALLOC_NOEXPORT
extern bool malloc_medium_space_efficient_enabled;

MALLOC_NOEXPORT
extern bool malloc_sanitizer_enabled;

MALLOC_NOEXPORT
extern malloc_zone_t *initial_xzone_zone;

#if CONFIG_MALLOC_PROCESS_IDENTITY
MALLOC_NOEXPORT
extern malloc_process_identity_t malloc_process_identity;
#endif

MALLOC_NOEXPORT MALLOC_NOINLINE
void
malloc_error_break(void);

MALLOC_NOEXPORT MALLOC_NOINLINE MALLOC_USED
int
malloc_gdb_po_unsafe(void);

__attribute__((always_inline, const))
static inline bool
malloc_traced(void)
{
	return malloc_tracing_enabled;
}

static inline uint32_t
_malloc_cpu_number(void)
{
#if TARGET_OS_SIMULATOR
	size_t n;
	pthread_cpu_number_np(&n);
	return (uint32_t)n;
#else
	return _os_cpu_number();
#endif
}

#if CONFIG_MAGAZINE_PER_CLUSTER

static inline unsigned int
_malloc_cpu_cluster_number(void)
{
#if TARGET_OS_SIMULATOR
#error current cluster id not supported on simulator
#else
	return _os_cpu_cluster_number();
#endif
}

static inline unsigned int
_malloc_get_cluster_from_cpu(unsigned int cpu_number)
{
#if TARGET_OS_SIMULATOR
#error cluster id lookup not supported on simulator
#else
	return (unsigned int)*(uint8_t *)(uintptr_t)(_COMM_PAGE_CPU_TO_CLUSTER + cpu_number);
#endif
}

#endif // CONFIG_MAGAZINE_PER_CLUSTER

/*
  * Copies the malloc library's _malloc_msl_lite_hooks_t structure to a given
  * location. Size is passed to allow the structure to  grow. Since this is
  * a temporary arrangement, we don't need to worry about
  * pointer authentication here or in the _malloc_msl_lite_hooks_t structure
  * itself.
  */
struct _malloc_msl_lite_hooks_s;
typedef void (*set_msl_lite_hooks_callout_t) (struct _malloc_msl_lite_hooks_s *hooksp, size_t size);
void set_msl_lite_hooks(set_msl_lite_hooks_callout_t callout);

#endif // __INTERNAL_H
