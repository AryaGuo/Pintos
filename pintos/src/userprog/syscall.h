#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "../threads/interrupt.h"
#include "../threads/synch.h"

typedef int mapid_t;

/* mmap */
struct mmap_entry {
    struct file *file;
    void *addr;
    mapid_t mid;
    struct list_elem elem;
};

void syscall_init(void);

void exit_with_error(int ret);

void sys_halt(struct intr_frame *f);

void sys_exit(struct intr_frame *f);

void sys_exec(struct intr_frame *f);

void sys_wait(struct intr_frame *f);

void sys_create(struct intr_frame *f);

void sys_remove(struct intr_frame *f);

void sys_open(struct intr_frame *f);

void sys_filesize(struct intr_frame *f);

void sys_read(struct intr_frame *f);

void sys_write(struct intr_frame *f);

void sys_seek(struct intr_frame *f);

void sys_tell(struct intr_frame *f);

void sys_close(struct intr_frame *f);

void my_munmap(struct mmap_entry *entry);

void sys_munmap(struct intr_frame *f);

void sys_mmap(struct intr_frame *f);

void preload(void *buffer, int size);

void pages_set_active(void *buffer, int size, bool active);


#endif /* userprog/syscall.h */
