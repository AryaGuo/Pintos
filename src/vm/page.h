//
// Created by Arya on 2019/6/25.
//

#ifndef SRC_PAGE_H
#define SRC_PAGE_H

#include "../filesys/off_t.h"
#include "../lib/kernel/list.h"
#include "../lib/kernel/hash.h"
#include "../threads/synch.h"
#include "../filesys/file.h"

struct supplemental_page_table {
    struct hash page_table;
};

enum Status {
    FILE, ZERO, DEFAULT, SWAP
};

struct supplemental_page_table_entry {
    void *upage;
    void *kpage;

    bool dirty;
    bool access;

    struct hash_elem helem;

    // For lazy-loading.
    struct file *file;
    off_t ofs;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    bool writable;
    enum Status status;

    size_t block_idx;
};

static unsigned page_hash_func(const struct hash_elem *elem, void *aux);

static bool page_less_func(const struct hash_elem *, const struct hash_elem *, void *aux);

static void page_destroy_func(struct hash_elem *e, void *aux);

struct supplemental_page_table *vm_spt_init();

void vm_spt_destroy(struct supplemental_page_table *);

bool vm_install_page(void *upage, void *kpage, struct supplemental_page_table *spt);

bool vm_file_install_page(void *upage, struct file *file, off_t ofs, uint32_t read_bytes, uint32_t zero_bytes, bool
        writable, struct supplemental_page_table *spt);

bool vm_zero_install_page(void *upage, struct supplemental_page_table *spt);

struct supplemental_page_table_entry* vm_get_spte(void *upage, struct supplemental_page_table *spt);

bool vm_load(void *upage, uint32_t *pagedir, struct supplemental_page_table *spt);

void vm_unmap(void *upage, struct file *file, off_t offset, uint32_t read_bytes, uint32_t *pagedir,
              struct supplemental_page_table *spt);

void vm_spt_set_dirty(void* upage, bool is_dirty, struct supplemental_page_table *spt);

void vm_spt_set_swap(void *upage, size_t swap_id, struct supplemental_page_table *spt);

void vm_spt_set_active(void * upage, bool active, struct supplemental_page_table *spt);

#endif //SRC_PAGE_H
