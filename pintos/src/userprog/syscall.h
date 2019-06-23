#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "../threads/interrupt.h"
#include "../threads/synch.h"
struct semaphore load_finished;

void syscall_init (void);

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

#endif /* userprog/syscall.h */
