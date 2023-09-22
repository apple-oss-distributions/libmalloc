//
//  malloc_size_test.c
//  libmalloc
//
//  Tests for malloc_size() on both good and bad pointers.
//

#include <darwintest.h>
#include <stdlib.h>
#include <malloc/malloc.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

static void
test_malloc_size_valid(size_t min, size_t max, size_t incr)
{
	for (size_t sz = min; sz <= max; sz += incr) {
		void *ptr = malloc(sz);
		T_ASSERT_NOTNULL(ptr, "Allocate size %llu\n", (uint64_t)sz);
		T_ASSERT_GE(malloc_size(ptr), sz, "Check size value");
		T_ASSERT_GE(malloc_good_size(sz), sz, "Check good size value");
		free(ptr);
	}
}

static void
test_malloc_size_invalid(size_t min, size_t max, size_t incr)
{
	for (size_t sz = min; sz <= max; sz += incr) {
		void *ptr = malloc(sz);
		T_ASSERT_NOTNULL(ptr, "Allocate size %llu\n", (uint64_t)sz);
		T_ASSERT_EQ(malloc_size(ptr + 1), 0UL, "Check offset by 1 size value");
		T_ASSERT_EQ(malloc_size(ptr + sz/2), 0UL, "Check offset by half size value");
		free(ptr);
	}
}

T_DECL(malloc_size_valid, "Test malloc_size() on valid pointers, non-Nano",
	   T_META_ENVVAR("MallocNanoZone=0"), T_META_TAG_XZONE)
{
	// Test various sizes, roughly targetting each allocator range.
	test_malloc_size_valid(2, 256, 16);
	test_malloc_size_valid(512, 8192, 256);
	test_malloc_size_valid(8192, 65536, 1024);
}

T_DECL(malloc_size_valid_nanov2, "Test malloc_size() on valid pointers for Nanov2",
	   T_META_ENVVAR("MallocNanoZone=V2"), T_META_TAG_XZONE)
{
	test_malloc_size_valid(2, 256, 16);
}

T_DECL(malloc_size_invalid, "Test malloc_size() on invalid pointers, non-Nano",
	   T_META_ENVVAR("MallocNanoZone=0"))
{
	// Test various sizes, roughly targetting each allocator range.
	test_malloc_size_invalid(2, 256, 16);
	test_malloc_size_invalid(512, 8192, 256);
	test_malloc_size_invalid(8192, 32768, 1024);
}

T_DECL(malloc_size_invalid_nanov2, "Test malloc_size() on valid pointers for Nanov2",
	   T_META_ENVVAR("MallocNanoZone=V2"))
{
	test_malloc_size_invalid(2, 256, 16);
}
