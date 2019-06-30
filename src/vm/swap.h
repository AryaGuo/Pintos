//
// Created by Arya on 2019/6/26.
//

#ifndef SRC_SWAP_H
#define SRC_SWAP_H

#include "../devices/block.h"
#include "../lib/kernel/bitmap.h"

#define SECTOR_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)
#define SWAP_ABSENT (-1)

struct block *swap_block;

// a bitmap representing the status of swap_block. 1: free; 0: in-use
struct bitmap *swap_map;

void vm_swap_init();

size_t vm_swap_out(void *page);

bool vm_swap_in(void *page, size_t idx);

bool vm_swap_free(size_t idx);

#endif //SRC_SWAP_H
