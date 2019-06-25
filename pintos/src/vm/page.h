//
// Created by Arya on 2019/6/25.
//

#ifndef SRC_PAGE_H
#define SRC_PAGE_H

#include "../lib/kernel/list.h"
#include "../lib/kernel/hash.h"
#include "../threads/synch.h"

struct supplemental_page_table {
    struct hash page_table;
};

struct supplemental_page_table_entry {
    void *upage;
    void *kpage;

    bool dirty;
    bool access;

    size_t read_bytes;
    size_t zero_bytes;

    struct hash_elem helem;
};

static unsigned page_hash_func(const struct hash_elem *elem, void *aux);

static bool page_less_func(const struct hash_elem *, const struct hash_elem *, void *aux);

static void page_destroy_func (struct hash_elem *e, void *aux);

struct supplemental_page_table* vm_spt_init();

void vm_spt_destroy(struct supplemental_page_table*);

bool vm_install_page(void *upage, void *kpage, struct supplemental_page_table* spt);

#endif //SRC_PAGE_H
