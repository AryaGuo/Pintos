//
// Created by Arya on 2019/6/25.
//

#include "../lib/stdio.h"
#include "../threads/malloc.h"
#include "../lib/debug.h"
#include "../vm/page.h"
#include "frame.h"

static unsigned page_hash_func(const struct hash_elem *elem, void *aux) {
    struct supplemental_page_table_entry *entry = hash_entry(elem, struct supplemental_page_table_entry, helem);
    return hash_bytes(&entry->upage, sizeof entry->upage);
}

static bool page_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux) {
    struct supplemental_page_table_entry *a_entry = hash_entry(a, struct supplemental_page_table_entry, helem);
    struct supplemental_page_table_entry *b_entry = hash_entry(b, struct supplemental_page_table_entry, helem);
    return a_entry->upage < b_entry->upage;
}

static void page_destroy_func (struct hash_elem *e, void *aux) {
    struct supplemental_page_table_entry *entry = hash_entry(e, struct supplemental_page_table_entry, helem);
    vm_frame_free(entry->kpage, false);
    free(entry);
}

struct supplemental_page_table* vm_spt_init() {
    struct supplemental_page_table *spt = malloc(sizeof(struct supplemental_page_table)); //todo
    hash_init(&spt->page_table, page_hash_func, page_less_func, NULL);
    return spt;
}

void vm_spt_destroy(struct supplemental_page_table* spt) {
    hash_destroy(&spt->page_table, page_destroy_func);
    free(spt);
}

bool vm_install_page(void *upage, void *kpage, struct supplemental_page_table* spt) {
    struct supplemental_page_table_entry *spte = malloc(sizeof(struct supplemental_page_table_entry));
    ASSERT (spte != NULL);
    spte->upage = upage;
    spte->kpage = kpage;

    /* There exists the same key in hash table. */
    if(hash_insert(&spt->page_table, &spte->helem) != NULL) {
        free(spte);
        return false;
    }
    return true;
}

