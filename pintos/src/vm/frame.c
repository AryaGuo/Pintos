//
// Created by Arya on 2019/6/25.
//

#include "../threads/thread.h"
#include "../threads/malloc.h"
#include "../lib/debug.h"
#include "../threads/palloc.h"
#include "../vm/frame.h"

static unsigned frame_hash_func(const struct hash_elem *elem, void *aux) {
    struct frame_table_entry *entry = hash_entry(elem, struct frame_table_entry, helem);
    return hash_bytes(&entry->kpage, sizeof entry->kpage);
}

static bool frame_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux) {
    struct frame_table_entry *a_entry = hash_entry(a, struct frame_table_entry, helem);
    struct frame_table_entry *b_entry = hash_entry(b, struct frame_table_entry, helem);
    return a_entry->kpage < b_entry->kpage;
}

struct frame_table_entry *get_hash_entry(void *kpage) {
    struct frame_table_entry tmp;
    tmp.kpage = kpage;
    struct hash_elem *ele = hash_find(&frame_map, &tmp.helem);
    ASSERT (ele != NULL);
    return hash_entry(ele, struct frame_table_entry, helem);
}

void vm_frame_init() {
    lock_init(&frame_lock);
    hash_init(&frame_map, frame_hash_func, frame_less_func, NULL);
//    list_init(&frame_list);
}

void *vm_frame_alloc(enum palloc_flags flags, void *upage) {
    void *kpage = palloc_get_page(flags | PAL_USER);
    if (kpage == NULL) {
        return NULL; //todo: swap
    }
    lock_acquire(&frame_lock);
    struct frame_table_entry *entry = malloc(sizeof(struct frame_table_entry));
    ASSERT(entry != NULL);
    entry->upage = upage;
    entry->kpage = kpage;
    entry->t = thread_current();
    entry->active = true;
    hash_insert(&frame_map, &entry->helem);
    lock_release(&frame_lock);
    return kpage;
}

void vm_frame_free(void *kpage, bool free_kpage) {
    lock_acquire(&frame_lock);
    struct frame_table_entry *entry = get_hash_entry(kpage);
    hash_delete(&frame_map, &entry->helem);
    free(entry);
    if (free_kpage) {
        palloc_free_page(kpage);
    }
    lock_release(&frame_lock);
}

void vm_frame_set_active(void *kpage, bool new_active) {
    lock_acquire(&frame_lock);
    struct frame_table_entry *entry = get_hash_entry(kpage);
    entry->active = new_active;
    lock_release(&frame_lock);
}
