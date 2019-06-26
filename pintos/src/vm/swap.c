//
// Created by Arya on 2019/6/26.
//

#include "../lib/stdio.h"
#include "swap.h"
#include "../threads/vaddr.h"
#include "../lib/debug.h"

void vm_swap_init() {
    swap_block = block_get_role(BLOCK_SWAP);
    swap_map = bitmap_create(block_size(swap_block) / SECTOR_PER_PAGE);
    bitmap_set_all(swap_map, true);
}

size_t vm_swap_in(void *page) {
    size_t idx = bitmap_scan(swap_map, 0, 1, true);
    if (idx == BITMAP_ERROR) {
        PANIC("Ahhhh, out of swap block!");
    }
    bitmap_set(swap_map, idx, false);
    for (int i = 0; i < SECTOR_PER_PAGE; ++i) {
        block_write(swap_block, idx * SECTOR_PER_PAGE + i, page + BLOCK_SECTOR_SIZE);
    }
    return idx;
}

bool vm_swap_out(void *page, size_t idx) {
    if(bitmap_test(swap_map, idx)) {
        return false;
    }
    for (int i = 0; i < SECTOR_PER_PAGE; ++i) {
        block_read(swap_block, idx * SECTOR_PER_PAGE + i, page + BLOCK_SECTOR_SIZE);
    }
    bitmap_set(swap_map, idx, true);
    return true;
}

bool vm_swap_free(size_t idx) {
    if(bitmap_test(swap_map, idx)) {
        return false;
    }
    bitmap_set(swap_map, idx, true);
    return true;
}