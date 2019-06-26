//
// Created by Arya on 2019/6/25.
//

#include "../lib/string.h"
#include "../userprog/pagedir.h"
#include "../threads/palloc.h"
#include "../lib/stdio.h"
#include "../threads/malloc.h"
#include "../lib/debug.h"
#include "../vm/page.h"
#include "../vm/frame.h"
#include "../vm/swap.h"
#include "../filesys/file.h"

static unsigned page_hash_func(const struct hash_elem *elem, void *aux) {
    struct supplemental_page_table_entry *entry = hash_entry(elem, struct supplemental_page_table_entry, helem);
    return hash_bytes(&entry->upage, sizeof entry->upage);
}

static bool page_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux) {
    struct supplemental_page_table_entry *a_entry = hash_entry(a, struct supplemental_page_table_entry, helem);
    struct supplemental_page_table_entry *b_entry = hash_entry(b, struct supplemental_page_table_entry, helem);
    return a_entry->upage < b_entry->upage;
}

static void page_destroy_func(struct hash_elem *e, void *aux) {
    struct supplemental_page_table_entry *entry = hash_entry(e, struct supplemental_page_table_entry, helem);
    if (entry->block_idx != SWAP_ABSENT) {
        printf("impossible\n");
        ASSERT(vm_swap_free(entry->block_idx));
    }
    vm_frame_free(entry->kpage, false);
    free(entry);
}

struct supplemental_page_table *vm_spt_init() {
    struct supplemental_page_table *spt = malloc(sizeof(struct supplemental_page_table)); //todo
    hash_init(&spt->page_table, page_hash_func, page_less_func, NULL);
    return spt;
}

void vm_spt_destroy(struct supplemental_page_table *spt) {
    hash_destroy(&spt->page_table, page_destroy_func);
    free(spt);
}

bool vm_install_page(void *upage, void *kpage, struct supplemental_page_table *spt) {
    struct supplemental_page_table_entry *spte = malloc(sizeof(struct supplemental_page_table_entry));
    ASSERT (spte != NULL);
    spte->upage = upage;
    spte->kpage = kpage;
    spte->status = DEFAULT;
    spte->block_idx = SWAP_ABSENT;
//todo: dirty & access

    /* There exists the same key in hash table. */
    if (hash_insert(&spt->page_table, &spte->helem) != NULL) {
        free(spte);
        return false;
    }
    return true;
}

bool vm_file_install_page(void *upage, struct file *file, off_t ofs, uint32_t read_bytes, uint32_t zero_bytes, bool
writable, struct supplemental_page_table *spt) {
    struct supplemental_page_table_entry *spte = malloc(sizeof(struct supplemental_page_table_entry));
    ASSERT (spte != NULL);
    spte->upage = upage;
    spte->kpage = NULL;
    spte->file = file;
    spte->ofs = ofs;
    spte->read_bytes = read_bytes;
    spte->zero_bytes = zero_bytes;
    spte->writable = writable;
    spte->status = FILE;
    spte->block_idx = SWAP_ABSENT;

    /* There exists the same key in hash table. */
    if (hash_insert(&spt->page_table, &spte->helem) != NULL) {
        free(spte);
        return false;
    }
    return true;
}

bool vm_zero_install_page(void *upage, struct supplemental_page_table *spt) {
    struct supplemental_page_table_entry *spte = malloc(sizeof(struct supplemental_page_table_entry));
    ASSERT (spte != NULL);
    spte->upage = upage;
    spte->status = ZERO;
    spte->block_idx = SWAP_ABSENT;
//todo: dirty & access

    /* There exists the same key in hash table. */
    if (hash_insert(&spt->page_table, &spte->helem) != NULL) {
        free(spte);
        return false;
    }
    return true;
}

struct supplemental_page_table_entry *vm_get_spte(void *upage, struct supplemental_page_table *spt) {
    struct supplemental_page_table_entry tmp;
    tmp.upage = upage;
    struct hash_elem *ele = hash_find(spt, &tmp.helem);
    if (ele) {
        return hash_entry(ele, struct supplemental_page_table_entry, helem);
    } else {
        return NULL;
    }
}

bool vm_load(void *upage, uint32_t *pagedir, struct supplemental_page_table *spt) {
    /* Get a page of memory. */
    uint8_t *kpage = vm_frame_alloc(PAL_USER, upage);
    if (kpage == NULL)
        return false;
    struct supplemental_page_table_entry *spte = vm_get_spte(upage, spt);
    bool writable = true;
    switch (spte->status) {
        case FILE:
            /* Load this page. */
            file_seek(spte->file, spte->ofs);
            if (file_read(spte->file, kpage, spte->read_bytes) != (int) spte->read_bytes) {
                goto file_failed;
            }
            memset(kpage + spte->read_bytes, 0, spte->zero_bytes);
            writable = spte->writable;
            break;
        case ZERO:
            memset(kpage, 0, spte->zero_bytes);
            break;
        case DEFAULT:
            //todo
            ASSERT(false);
            return false;
    }
    if (!(pagedir_get_page(pagedir, upage) == NULL && pagedir_set_page(pagedir, upage, kpage, writable))) {
        goto file_failed;
    }
    spte->kpage = kpage;
    spte->status = DEFAULT;
    return true;

file_failed:
    vm_frame_free(kpage, true);
    return false;
}