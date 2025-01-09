// SPDX-License-Identifier: BSD-3-Clause

#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"

#define MMAP_THRESHOLD (128*1024)
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define PAGE_SIZE getpagesize()

struct block_meta *meta;

struct block_meta *find_best(size_t size, struct block_meta *list)
{
	struct block_meta *best = NULL;
	struct block_meta *current = list;

	while (current != NULL) {
		if (current->status == STATUS_FREE && current->size >= size) {
			if (best == NULL || current->size < best->size)
				best = current;
		}
		current = current->next;
	}
	return best;
}


void split(struct block_meta *block, size_t size)
{
	struct block_meta *new_block = (struct block_meta *)((char *)block + size + sizeof(struct block_meta));

	new_block->size = block->size - size - sizeof(struct block_meta);
	new_block->status = STATUS_FREE;
	new_block->next = block->next;
	new_block->prev = block;
	block->size = size;
	block->next = new_block;
	if (new_block->next != NULL)
		new_block->next->prev = new_block;
}

void add_to_list(struct block_meta *block)
{
	if (meta == NULL) {
		meta = block;
	} else {
		struct block_meta *current = meta;

		while (current->next != NULL)
			current = current->next;
		current->next = block;
		block->prev = current;
		block->next = NULL;
	}
}

struct block_meta *find_last(struct block_meta *list)
{
	struct block_meta *current = list;

	while (current->next != NULL)
		current = current->next;
	return current;
}

void coelesce(struct block_meta *block)
{
	if (block->prev != NULL && block->prev->status == STATUS_FREE) {
		block->prev->size += block->size + sizeof(struct block_meta);
		block->prev->next = block->next;
		if (block->next != NULL)
			block->next->prev = block->prev;
		block = block->prev;
	}
	if (block->next != NULL && block->next->status == STATUS_FREE) {
		block->size += block->next->size + sizeof(struct block_meta);
		block->next = block->next->next;
		if (block->next != NULL)
			block->next->prev = block;
	}
}

void coalesce_next(struct block_meta *block)
{
	if (block->next != NULL && block->next->status == STATUS_FREE) {
		block->size += block->next->size + sizeof(struct block_meta);
		block->next = block->next->next;
		if (block->next != NULL)
			block->next->prev = block;
	}
}


void *os_malloc(size_t size)
{
	struct block_meta *block = NULL;

	if (size == 0)
		return NULL;

	size_t aligned_size = ALIGN(size);

	if (meta == NULL && aligned_size < MMAP_THRESHOLD) {
		block = sbrk(MMAP_THRESHOLD);
		DIE(block == (void *) -1, "sbrk failed");
		meta = (struct block_meta *) block;
		meta->size = MMAP_THRESHOLD - sizeof(struct block_meta);
		meta->status = STATUS_FREE;
		meta->next = NULL;
		meta->prev = NULL;
		if (meta->size >= aligned_size + sizeof(struct block_meta) + 8)
			split(meta, aligned_size);
		meta->status = STATUS_ALLOC;
		return (void *)meta + sizeof(struct block_meta);
	}

	if (meta != NULL && aligned_size >= MMAP_THRESHOLD) {
		block = mmap(NULL, aligned_size + sizeof(struct block_meta), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		DIE(block == MAP_FAILED, "mmap failed");
		struct block_meta *new_block = (struct block_meta *) block;

		new_block->size = aligned_size;
		new_block->status = STATUS_MAPPED;
		new_block->next = NULL;
		new_block->prev = NULL;
		return (void *)new_block + sizeof(struct block_meta);
	}

	struct block_meta *best = find_best(aligned_size, meta);

	if (best != NULL) {
		if (best->size >= aligned_size + sizeof(struct block_meta) + 8)
			split(best, aligned_size);
		best->status = STATUS_ALLOC;
		return (void *)best + sizeof(struct block_meta);
	}

	if (size >= MMAP_THRESHOLD) {
		block = mmap(NULL, aligned_size + sizeof(struct block_meta), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		DIE(block == MAP_FAILED, "mmap failed");
		struct block_meta *new_block = (struct block_meta *) block;

		new_block->size = aligned_size;
		new_block->status = STATUS_MAPPED;
		new_block->next = NULL;
		new_block->prev = NULL;
		return (void *)new_block + sizeof(struct block_meta);
	}
	struct block_meta *last_block = find_last(meta);

	if (last_block->status != STATUS_FREE) {
		block = sbrk(aligned_size + sizeof(struct block_meta));
		DIE(block == (void *) -1, "sbrk failed");
		struct block_meta *new_block = (struct block_meta *) block;

		new_block->size = aligned_size;
		new_block->status = STATUS_ALLOC;
		new_block->next = NULL;
		new_block->prev = NULL;
		add_to_list(new_block);
		return (void *)new_block + sizeof(struct block_meta);
	}
	if (last_block->status == STATUS_FREE) {
		block = sbrk(aligned_size - last_block->size);
		DIE(block == (void *) -1, "sbrk failed");
		last_block->size = aligned_size;
		last_block->status = STATUS_ALLOC;
		return (void *)last_block + sizeof(struct block_meta);
	}
	return NULL;
}


void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	struct block_meta *meta = ptr - sizeof(struct block_meta);

	if (meta->status == STATUS_MAPPED) {
		munmap(meta, meta->size + sizeof(struct block_meta));
		DIE(meta == MAP_FAILED, "munmap failed");
	} else {
		meta->status = STATUS_FREE;
		coelesce(meta);
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	size_t total_size = nmemb * size;
	size_t total = ALIGN(total_size);
	struct block_meta *block = NULL;

	if (total + sizeof(struct block_meta) >= (size_t)PAGE_SIZE) {
		block = mmap(NULL, total + sizeof(struct block_meta), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(block == MAP_FAILED, "mmap failed");
		block->size = total;
		block->status = STATUS_MAPPED;
		block->next = NULL;
		block->prev = NULL;
		return (void *)block + sizeof(struct block_meta);
	}
	void *ptr = os_malloc(total_size);

	if (ptr != NULL)
		memset(ptr, 0, total_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	if (ptr == NULL)
		return os_malloc(size);

	struct block_meta *meta = ptr - sizeof(struct block_meta);

	if (meta->status == STATUS_FREE)
		return NULL;

	size_t aligned_size = ALIGN(size);

	if (meta->status == STATUS_MAPPED) {
		size_t smalled_size;

		if (meta->size < aligned_size)
			smalled_size = meta->size;
		else
			smalled_size = aligned_size;
		void *new_ptr = os_malloc(aligned_size);

		memcpy(new_ptr, ptr, smalled_size);
		os_free(ptr);
		return new_ptr;
	}

	if (meta->status == STATUS_ALLOC && aligned_size + sizeof(struct block_meta) >= MMAP_THRESHOLD) {
		void *new_ptr = os_malloc(aligned_size);

		memcpy(new_ptr, ptr, meta->size);
		os_free(ptr);
		return new_ptr;
	}

	struct block_meta *last = find_last(meta);

	if (meta == last) {
		if (aligned_size > meta->size) {
			sbrk(aligned_size - meta->size);
			meta->size = aligned_size;
		}

		if (aligned_size <= meta->size) {
			if (meta->size - aligned_size >= sizeof(struct block_meta) + 8) {
				split(meta, aligned_size);
				return (void *)meta + sizeof(struct block_meta);
			}
			if (meta->size - aligned_size < sizeof(struct block_meta) + 8)
				return (void *)meta + sizeof(struct block_meta);
		}
	}
	coalesce_next(meta);
	if (aligned_size <= meta->size) {
		if (meta->size - aligned_size >= sizeof(struct block_meta) + 8) {
			split(meta, aligned_size);
			return (void *)meta + sizeof(struct block_meta);
		}
		if (meta->size - aligned_size < sizeof(struct block_meta) + 8)
			return (void *)meta + sizeof(struct block_meta);
	} else {
		void *new_ptr = os_malloc(aligned_size);

		memcpy(new_ptr, ptr, meta->size);
		os_free(ptr);
		return new_ptr;	
	}
	return NULL;
}
