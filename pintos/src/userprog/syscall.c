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

static int get_user(const uint8_t *uaddr) {
    if(!((void*)uaddr < PHYS_BASE)) {
        return -1;
    }
    int res;
    asm("movl $1f, %0; movzbl %1, %0; 1:"
    : "=&a" (res) : "m" (*uaddr));
    return res;
}

static bool put_user(uint8_t *udst, uint8_t byte) {
    if(!((void*)udst < PHYS_BASE)) {
        return -1;
    }
    int error_code;
    asm("movl %1f, %0; movb %b2, %1; 1:"
    : "=&a" (error_code), "=m" (*udst) : "r" (byte));
    return error_code != -1;
}

void exit_with_error(int ret) {

//    if (lock_held_by_current_thread(&filesys_lock)) todo
//        lock_release (&filesys_lock);
    struct thread *t = thread_current();
    t->exit_code = ret;
    thread_exit();
}

static void
check_user (const uint8_t *uaddr) {
    // check uaddr range or segfaults
    if(get_user (uaddr) == -1)
        exit_with_error(-1);
}

void sys_halt(struct intr_frame *f) {
    printf("\nsys_halt\n");
}

/* Read from user memory, starting at src with length of bytes. */
static int mem_read_user(void *src, void *dst, size_t bytes) {
    int32_t val;
    size_t i;
    for (i = 0; i < bytes; ++i) {
        val = get_user(src + i);
        if (val == -1) {
            exit_with_error(-1);
        }
        *(char*)(dst + i) = val & 0xff;
    }
    return (int)bytes;
}

void sys_exit(struct intr_frame *f) {
    printf("\nsys_exit\n");
    struct thread *t = thread_current();
    mem_read_user(f->esp + 4, &t->exit_code, sizeof(t->exit_code));
    f->eax = 0;
    thread_exit();
}

void sys_exec(struct intr_frame *f) {
    printf("\nsys_exec\n");
}

void sys_wait(struct intr_frame *f) {
    printf("\nsys_wait\n");
}

void sys_create(struct intr_frame *f) {
    printf("\nsys_create\n");
}

void sys_remove(struct intr_frame *f) {
    printf("\nsys_remove\n");
}

void sys_open(struct intr_frame *f) {
    printf("\nsys_open\n");
}

void sys_filesize(struct intr_frame *f) {
    printf("\nsys_filesize\n");
}

void sys_read(struct intr_frame *f) {
    printf("\nsys_read\n");
}

void sys_write(struct intr_frame *f) {
    printf("\nsys_write\n");
    int fd;
    void *buffer;
    unsigned size;
    mem_read_user(f->esp + 4, &fd, sizeof(fd));
    mem_read_user(f->esp + 8, &buffer, sizeof(buffer));
    mem_read_user(f->esp + 12, &size, sizeof(size));

printf("%d\n%x\n%u\n", fd, (int)buffer, size);

    check_user((const uint8_t*) buffer);
    check_user((const uint8_t*) buffer + size - 1);
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        f->eax = size;
    } else {
        // todo
    }
}

void sys_seek(struct intr_frame *f) {
    printf("\nsys_seek\n");
}

void sys_tell(struct intr_frame *f) {
    printf("\nsys_tell\n");
}

void sys_close(struct intr_frame *f) {
    printf("\nsys_close\n");
}

static void
syscall_handler(struct intr_frame *f) {
    int syscall_num;
    mem_read_user(f->esp, &syscall_num, sizeof(syscall_num));
    printf("SYSCALL NUM: %d\n", syscall_num);
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
}
