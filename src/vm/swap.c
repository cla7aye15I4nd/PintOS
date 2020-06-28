//
// Created by zhang on 2020/6/27.
//

#include "swap.h"
#include "../lib/debug.h"

void swap_table_init() {
	swap_block_device = block_get_role(BLOCK_SWAP);
	swap_slot = bitmap_create(block_size(swap_block_device) / SECTOR_PER_PAGE);
	bitmap_set_all(swap_slot, true);
	lock_init(&swap_lock);
}

void swap_in(uint32_t swap_index, void *page) {
	lock_acquire(&swap_lock);

	if (bitmap_test(swap_slot, swap_index) == true) {
		PANIC("Nothing on the swap block!");
	}
	for (size_t i = 0; i < SECTOR_PER_PAGE; i++) {
		block_read(swap_block_device, swap_index * SECTOR_PER_PAGE + i, page + BLOCK_SECTOR_SIZE * i);
	}
	lock_release(&swap_lock);
}

uint32_t swap_out(void *page) {
	lock_acquire(&swap_lock);
	size_t alloc = bitmap_scan_and_flip(swap_slot, 0, 1, true);
	if (alloc == BITMAP_ERROR) {
		PANIC("NO AVAILABLE SLOT IN SWAP");
	}
	for (size_t i = 0; i < SECTOR_PER_PAGE; i++) {
		block_write(swap_block_device, alloc * SECTOR_PER_PAGE + i, page + BLOCK_SECTOR_SIZE * i);
	}
	lock_release(&swap_lock);
	return alloc;
}

void swap_free(uint32_t swap_index) {
	lock_acquire(&swap_lock);
	bitmap_set(swap_slot, swap_index, true);
	lock_release(&swap_lock);
}