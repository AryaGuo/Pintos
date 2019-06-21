#include "../userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "../threads/vaddr.h"
#include "../threads/interrupt.h"
#include "../threads/thread.h"

static void syscall_handler(struct intr_frame *);

void exit_with_error(int ret);

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}


void exit_with_error(int ret) {
    struct thread *t = thread_current();
    t->exit_code = ret;
    thread_exit();
}

void sys_halt(struct intr_frame *f) {

}

void sys_exit(struct intr_frame *f) {
    if (!is_user_vaddr((int *) f->esp) + 2) {
        exit_with_error(-1);
        // todo: wtf?
    }
    int ret = *((int *) f->esp + 1);
    struct thread *t = thread_current();
    t->exit_code = ret;
    f->eax = 0;
    thread_exit();
}

void sys_exec(struct intr_frame *f) {

}

void sys_wait(struct intr_frame *f) {

}

void sys_create(struct intr_frame *f) {

}

void sys_remove(struct intr_frame *f) {

}

void sys_open(struct intr_frame *f) {

}

void sys_filesize(struct intr_frame *f) {

}

void sys_read(struct intr_frame *f) {

}

void sys_write(struct intr_frame *f) {
    int fd = *((int *) f->esp + 1);
    void *buffer = (void *) *((int *) f->esp + 2);
    unsigned size = (unsigned) *((int *) f->esp + 3);
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        f->eax = 0;
    } else {
        // todo
    }
}

void sys_seek(struct intr_frame *f) {

}

void sys_tell(struct intr_frame *f) {

}

void sys_close(struct intr_frame *f) {

}

static void
syscall_handler(struct intr_frame *f) {
    int syscall_num = *((int *) f->esp);
    switch (syscall_num) {
        case SYS_HALT:
            sys_halt(f);
            break;
        case SYS_EXIT:
            sys_exit(f);
            break;
        case SYS_EXEC:
            sys_exec(f);
            break;
        case SYS_WAIT:
            sys_wait(f);
            break;
        case SYS_CREATE:
            sys_create(f);
            break;
        case SYS_REMOVE:
            sys_remove(f);
            break;
        case SYS_OPEN:
            sys_open(f);
            break;
        case SYS_FILESIZE:
            sys_filesize(f);
            break;
        case SYS_READ:
            sys_read(f);
            break;
        case SYS_WRITE:
            sys_write(f);
            break;
        case SYS_SEEK:
            sys_seek(f);
            break;
        case SYS_TELL:
            sys_tell(f);
            break;
        case SYS_CLOSE:
            sys_close(f);
            break;
        default:
            ASSERT(false);//todo
    }
    printf("system call!\n");
    thread_exit();
}
