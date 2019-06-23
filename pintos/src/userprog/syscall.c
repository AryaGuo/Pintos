#include "../userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "../threads/palloc.h"
#include "../devices/input.h"
#include "../devices/shutdown.h"
#include "../threads/synch.h"
#include "../threads/vaddr.h"
#include "../threads/interrupt.h"
#include "../threads/thread.h"
#include "../filesys/inode.h"
#include "../filesys/file.h"
#include "../filesys/filesys.h"
#include "../filesys/directory.h"
#include "process.h"
//#define DEBUGGING

static void syscall_handler(struct intr_frame *);

void exit_with_error(int ret);

static struct lock filesys_lock;
void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    sema_init(&load_finished, 0);
    lock_init(&filesys_lock);
}

static int get_user(const uint8_t *uaddr) {
    if (!((void *) uaddr < PHYS_BASE)) {
        return -1;
    }
    int res;
    asm("movl $1f, %0; movzbl %1, %0; 1:"
    : "=&a" (res) : "m" (*uaddr));
    return res;
}

static bool put_user(uint8_t *udst, uint8_t byte) {
    if (!((void *) udst < PHYS_BASE)) {
        return -1;
    }
    int error_code;
    asm("movl $1f, %0; movb %b2, %1; 1:"
    : "=&a" (error_code), "=m" (*udst) : "r" (byte));
    return error_code != -1;
}

void exit_with_error(int ret) {
    if (lock_held_by_current_thread(&filesys_lock))
        lock_release (&filesys_lock);
    struct thread *t = thread_current();
    t->pcb->exitcode = ret;
    thread_exit();
}

static void
check_user(const uint8_t *uaddr) {
    // check uaddr range or segfaults
    if (get_user(uaddr) == -1)
        exit_with_error(-1);
}

/* Read from user memory, starting at src with length of bytes. */
static int mem_read_user(void *src, void *dst, size_t bytes) {
    //printf("read from %d\n", (int)src);
    int32_t val;
    size_t i;
    for (i = 0; i < bytes; ++i) {
        val = get_user(src + i);
        if (val == -1) {
            exit_with_error(-1);
        }
        *(char *) (dst + i) = val & 0xff;
    }
    return (int) bytes;
}

void sys_halt(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("sys_halt\n");
#endif
    shutdown_power_off();
}

void sys_exit(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("sys_exit\n");
#endif
    struct thread *t = thread_current();
    mem_read_user(f->esp + 4, &t->pcb->exitcode, sizeof(t->pcb->exitcode));
    printf("%s: exit(%d)\n", t->name, t->pcb->exitcode);
    f->eax = 0;
    if (lock_held_by_current_thread(&filesys_lock))
        lock_release (&filesys_lock);
    thread_exit();
}

void sys_exec(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("sys_exec\n");
#endif
    const char *cmd_line;
    mem_read_user(f->esp + 4, &cmd_line, sizeof(cmd_line));
    lock_acquire (&filesys_lock);
    f->eax = (uint32_t) process_execute(cmd_line);
    lock_release(&filesys_lock);
    sema_down(&load_finished);
}

void sys_wait(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("sys_wait\n");
#endif
    pid_t pid;
    mem_read_user(f->esp + 4, &pid, sizeof(pid));
    f->eax = (uint32_t) process_wait(pid);
}

void sys_create(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("sys_create\n");
#endif
    char* file;
    unsigned initial_size;
    mem_read_user(f->esp + 4, &file, sizeof(file));
    mem_read_user(f->esp + 8, &initial_size, sizeof(initial_size));
    check_user((const uint8_t*)file);
    lock_acquire(&filesys_lock);
    f->eax = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
}

void sys_remove(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("sys_remove\n");
#endif
    char* file;
    mem_read_user(f->esp + 4, &file, sizeof(file));
    check_user((const uint8_t*)file);
    lock_acquire(&filesys_lock);
    f->eax = filesys_remove(file);
    lock_release(&filesys_lock);
}
struct file_desc* find_file_desc(struct thread* t, int fd){
    if (fd < 3) {
        return NULL;
    }
    struct list* fd_list = &t->file_descriptor;
    if (!list_empty(fd_list)) {
        for (struct list_elem *e = list_begin(fd_list); e != list_end(fd_list); e = list_next(e)){
            struct file_desc *desc = list_entry(e, struct file_desc, elem);
            if (desc->id == fd){
                    return desc;
            }
        }

    }
    return NULL;
}
void sys_open(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("\nsys_open\n");
#endif
    char* file;
    mem_read_user(f->esp + 4, &file, sizeof(file));
    check_user((const uint8_t*)file);
    struct file_desc* fd = palloc_get_page(0);
    if (fd == NULL){
        f->eax = -1;
        return;
    }

    lock_acquire(&filesys_lock);
    printf("%s\n",file);
    struct file* file_opened = filesys_open(file);
    if (file_opened == NULL) {
        palloc_free_page(fd);
        f->eax = -1;
    }
    else {
       /* struct inode * inode = file_get_inode(file_opened);
        if (inode != NULL && inode_is_directory(inode)){
            fd->dir = dir_open(inode_reopen(inode));
        }
        else {
            fd->dir = NULL;

        }*/
        printf("find file\n");
        fd->file = file_opened;
        struct list* fd_list = &thread_current()->file_descriptor;
        if (list_empty(fd_list)){
            fd->id = 3;
        }
        else {
            fd->id = (list_entry(list_back(fd_list), struct file_desc, elem)->id) + 1;
        }
        list_push_back(fd_list, &(fd->elem));
        f->eax = fd->id;
        printf("open success\n");
    }
    lock_release(&filesys_lock);
}

void sys_filesize(struct intr_frame *f) {
    printf("\nsys_filesize\n");
    int fd;
    mem_read_user(f->esp + 4, &fd, sizeof(fd));

    lock_acquire(&filesys_lock);
    struct file_desc* file_desc = find_file_desc(thread_current(), fd);
    if (file_desc != NULL && file_desc->file != NULL){
        f->eax = file_length(file_desc->file);
    }
    else {
        f->eax = -1;
    }
    lock_release(&filesys_lock);
}

void sys_read(struct intr_frame *f) {
    printf("\nsys_read\n");
    int fd;
    void *buffer;
    unsigned size;
    mem_read_user(f->esp + 4, &fd, sizeof(fd));
    mem_read_user(f->esp + 8, &buffer, sizeof(buffer));
    mem_read_user(f->esp + 12, &size, sizeof(size));

    check_user((const uint8_t*) buffer);
    check_user((const uint8_t*) buffer + size - 1);

    lock_acquire(&filesys_lock);
    if (fd == STDIN_FILENO) {
        for (int i = 0; i < size; i++)
            if (!put_user(buffer + i, input_getc())){
                exit_with_error(-1);
            }
        f->eax = size;
    }
    else {
        struct file_desc* file_desc = find_file_desc(thread_current(), fd);
        if (file_desc != NULL && file_desc->file != NULL){
            f->eax = file_read(file_desc->file, buffer, size);
        }
        else {
            f->eax = -1;
        }
    }
    lock_release(&filesys_lock);
}

void sys_write(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("sys_write\n");
#endif
    int fd;
    void *buffer;
    unsigned size;
    mem_read_user(f->esp + 4, &fd, sizeof(fd));
    mem_read_user(f->esp + 8, &buffer, sizeof(buffer));
    mem_read_user(f->esp + 12, &size, sizeof(size));

    check_user((const uint8_t*) buffer);
    check_user((const uint8_t*) buffer + size - 1);

    lock_acquire (&filesys_lock);
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        f->eax = size;
        printf("\nsys_write finished\n");
    } else {
        struct file_desc* file_desc = find_file_desc(thread_current(), fd);
        if (file_desc != NULL && file_desc->file != NULL){
            f->eax = file_write(file_desc->file, buffer, size);
        }
        else {
            f->eax = -1;
        }
    }
    lock_release (&filesys_lock);
}

void sys_seek(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("\nsys_seek\n");
#endif
    int fd;
    unsigned position;
    mem_read_user(f->esp + 4, &fd, sizeof(fd));
    mem_read_user(f->esp + 8, &position, sizeof(position));
    lock_acquire(&filesys_lock);
    struct file_desc* file_desc = find_file_desc(thread_current(), fd);
    if (file_desc != NULL && file_desc->file != NULL){
        file_seek(file_desc->file, position);
    }
    lock_release(&filesys_lock);
}

void sys_tell(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("\nsys_tell\n");
#endif
    int fd;
    mem_read_user(f->esp + 4, &fd, sizeof(fd));
    lock_acquire(&filesys_lock);
    struct file_desc* file_desc = find_file_desc(thread_current(), fd);
    if (file_desc != NULL && file_desc->file != NULL){
        f->eax = file_tell(file_desc->file);
    }
    else {
        f->eax = -1;
    }
    lock_release(&filesys_lock);
}

void sys_close(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("\nsys_close\n");
#endif
    int fd;
    mem_read_user(f->esp + 4, &fd, sizeof(fd));
    lock_acquire(&filesys_lock);
    struct file_desc* file_desc = find_file_desc(thread_current(), fd);
    printf("file get %d\n", (int)file_desc);
    if (file_desc != NULL && file_desc->file != NULL){
        file_close(file_desc->file);
       /* if (file_desc->dir != NULL) {
            dir_close(file_desc->dir);
        }*/
        list_remove(&file_desc->elem);
        palloc_free_page(file_desc);
    }
    lock_release(&filesys_lock);
}

static void
syscall_handler(struct intr_frame *f) {
    int syscall_num;
    mem_read_user(f->esp, &syscall_num, sizeof(syscall_num));
//    printf("SYSCALL NUM: %d\n", syscall_num);
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
