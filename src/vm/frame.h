//
// Created by Arya on 2019/6/25.
//

#ifndef SRC_FRAME_H
#define SRC_FRAME_H

#include "../lib/kernel/list.h"
#include "../lib/kernel/hash.h"
#include "../threads/synch.h"

static struct lock frame_lock;

static struct hash frame_map;
static struct list frame_list;

struct frame_table_entry {
    void *upage;
    void *kpage;

    struct hash_elem helem;
    struct list_elem lelem;

    struct thread *t;

    bool active;
};

static unsigned frame_hash_func(const struct hash_elem *elem, void *aux);

static bool frame_less_func(const struct hash_elem *, const struct hash_elem *, void *aux);

void vm_frame_init();

void *vm_frame_alloc(enum palloc_flags flags, void *upage);

void vm_frame_free(void *kapge, bool);

void vm_frame_set_active(void *kpage, bool active);

struct frame_table_entry* find_entry_to_evict();

void vm_frame_free_withoutlock(void *kpage, bool free_kpage);
#endif //SRC_FRAME_H
