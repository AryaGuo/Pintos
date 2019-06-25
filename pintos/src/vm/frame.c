//
// Created by Arya on 2019/6/25.
//

#include "../threads/palloc.h"
#include "../vm/frame.h"

void *vm_frame_alloc(enum palloc_flags flags, void *upage){
    return palloc_get_page(flags | PAL_USER);
}
void vm_frame_free(void *kapge){
    palloc_free_page(kapge);
}