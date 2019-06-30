//
// Created by Arya on 2019/6/25.
//

#include "../threads/thread.h"
#include "../threads/malloc.h"
#include "../lib/debug.h"
#include "../threads/palloc.h"
#include "../vm/frame.h"
#include "../userprog/pagedir.h"
#include "swap.h"
#include "page.h"

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
    struct frame_table_entry *tmp = malloc(sizeof(struct frame_table_entry));
    tmp->kpage = kpage;
    struct hash_elem *ele = hash_find(&frame_map, &tmp->helem);
    free(tmp);
    if (ele != NULL) return hash_entry(ele, struct frame_table_entry, helem);
    else return NULL;
}

void vm_frame_init() {
    lock_init(&frame_lock);
    hash_init(&frame_map, frame_hash_func, frame_less_func, NULL);
    list_init(&frame_list);
}

void *vm_frame_alloc(enum palloc_flags flags, void *upage) {
    void *kpage = palloc_get_page(flags | PAL_USER);
    lock_acquire(&frame_lock);
    if (kpage == NULL) {
        struct frame_table_entry *frame = find_entry_to_evict();
        pagedir_clear_page(frame->t->pagedir, frame->upage);
        size_t swap_id = vm_swap_out(frame->kpage);
        bool is_dirty = pagedir_is_dirty(frame->t->pagedir, frame->upage) ||
                        pagedir_is_dirty(frame->t->pagedir, frame->kpage);
        vm_spt_set_swap(frame->upage, swap_id, frame->t->spt);
        vm_spt_set_dirty(frame->upage, is_dirty, frame->t->spt);
        vm_frame_free_withoutlock(frame->kpage, true);
        kpage = palloc_get_page(flags | PAL_USER);
    }
    struct frame_table_entry *entry = malloc(sizeof(struct frame_table_entry));
    ASSERT(entry != NULL); // I have no idea if assertion is true
    entry->upage = upage;
    entry->kpage = kpage;
    entry->t = thread_current();
    entry->active = true;
    hash_insert(&frame_map, &entry->helem);
    list_push_back(&frame_list, &entry->lelem);
    lock_release(&frame_lock);
    return kpage;
}

void vm_frame_free_withoutlock(void *kpage, bool free_kpage){
    struct frame_table_entry *entry = get_hash_entry(kpage);
    if (entry != NULL) {
        hash_delete(&frame_map, &entry->helem);
        list_remove(&entry->lelem);
        free(entry);
    }
    if (free_kpage) {
        palloc_free_page(kpage);
    }
}

void vm_frame_free(void *kpage, bool free_kpage) {
    lock_acquire(&frame_lock);
    struct frame_table_entry *entry = get_hash_entry(kpage);
    if (entry != NULL) {
        hash_delete(&frame_map, &entry->helem);
        list_remove(&entry->lelem);
        free(entry);
    }
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

struct frame_table_entry *find_entry_to_evict() {
    for (struct list_elem *e = list_begin(&frame_list); e != list_end(&frame_list); e = list_next(e)) {
        struct frame_table_entry *entry = list_entry(e, struct frame_table_entry, lelem);
        if (!entry->active) {
            return entry;
        }
    }
    PANIC("no available frame to swap out.");
    return NULL;
}