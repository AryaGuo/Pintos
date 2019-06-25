//
// Created by Arya on 2019/6/25.
//

#ifndef SRC_FRAME_H
#define SRC_FRAME_H

#include "../lib/kernel/list.h"
#include "../lib/kernel/hash.h"

struct frame_table_entry {
    void* upage;
    void* kpage;

    struct list_elem lelem;
    struct hash_elem helem;
};

void *vm_frame_alloc(enum palloc_flags flags, void *upage);
void vm_frame_free(void *kapge);

#endif //SRC_FRAME_H
