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

#ifndef __NANOV2_MALLOC_H
#define __NANOV2_MALLOC_H

#include <malloc/_ptrcheck.h>
__ptrcheck_abi_assume_single()

// Forward declaration for the nanozonev2 structure.
typedef struct nanozonev2_s nanozonev2_t;

MALLOC_NOEXPORT
void
nanov2_init(const char * __null_terminated * __null_terminated envp, const char * __null_terminated * __null_terminated apple, const char *bootargs);

MALLOC_NOEXPORT
void
nanov2_configure(void);

MALLOC_NOEXPORT
malloc_zone_t *
nanov2_create_zone(malloc_zone_t *helper_zone, unsigned debug_flags);

MALLOC_NOEXPORT
void
nanov2_forked_zone(nanozonev2_t *nanozone);

#endif // __NANOV2_MALLOC_H
