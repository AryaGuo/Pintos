#include "../userprog/syscall.h"
#include <stdio.h>
#include "../lib/syscall-nr.h"
#include "../lib/user/syscall.h"
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
#include "../userprog/process.h"
#include "../lib/kernel/list.h"
#include "../lib/stdio.h"
#include "../lib/kernel/stdio.h"
#include "../lib/debug.h"
#include "../vm/page.h"
#include "../threads/malloc.h"
#include "../vm/frame.h"

//#define DEBUGGING

static void syscall_handler(struct intr_frame *);

static struct lock filesys_lock;

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
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
        return false;
    }
    int error_code;
    asm("movl $1f, %0; movb %b2, %1; 1:"
    : "=&a" (error_code), "=m" (*udst) : "r" (byte));
    return error_code != -1;
}

void exit_with_error(int ret) {
#ifdef DEBUGGING
    printf("exit_with_error\n");
#endif
    if (lock_held_by_current_thread(&filesys_lock))
        lock_release(&filesys_lock);
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
    f->eax = 0;
    if (lock_held_by_current_thread(&filesys_lock))
        lock_release(&filesys_lock);
    thread_exit();
}

void sys_exec(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("sys_exec\n");
#endif
    const char *cmd_line;
    mem_read_user(f->esp + 4, &cmd_line, sizeof(cmd_line));
    for (int i = 0; i < sizeof(char *); ++i) {
        check_user((const uint8_t *) cmd_line + i);
    }
    lock_acquire(&filesys_lock);
    tid_t child_tid = process_execute(cmd_line);
    f->eax = (uint32_t) child_tid;
    lock_release(&filesys_lock);
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
    char *file;
    unsigned initial_size;
    mem_read_user(f->esp + 4, &file, sizeof(file));
    mem_read_user(f->esp + 8, &initial_size, sizeof(initial_size));
    check_user((const uint8_t *) file);
    lock_acquire(&filesys_lock);
    f->eax = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
}

void sys_remove(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("sys_remove\n");
#endif
    char *file;
    mem_read_user(f->esp + 4, &file, sizeof(file));
    check_user((const uint8_t *) file);
    lock_acquire(&filesys_lock);
    f->eax = filesys_remove(file);
    lock_release(&filesys_lock);
}

struct file_desc *find_file_desc(struct thread *t, int fd) {
    if (fd < 3) {
        return NULL;
    }
    struct list *fd_list = &t->file_descriptor;
    if (!list_empty(fd_list)) {
        for (struct list_elem *e = list_begin(fd_list); e != list_end(fd_list); e = list_next(e)) {
            struct file_desc *desc = list_entry(e, struct file_desc, elem);
            if (desc->id == fd) {
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
    char *file;
    mem_read_user(f->esp + 4, &file, sizeof(file));
    check_user((const uint8_t *) file);
    struct file_desc *fd = palloc_get_page(0);
    if (fd == NULL) {
        f->eax = -1;
        return;
    }
    lock_acquire(&filesys_lock);
    struct file *file_opened = filesys_open(file);
    if (file_opened == NULL) {
        palloc_free_page(fd);
        f->eax = -1;
    } else {
        fd->file = file_opened;
        struct list *fd_list = &thread_current()->file_descriptor;
        if (list_empty(fd_list)) {
            fd->id = 3;
        } else {
            fd->id = (list_entry(list_back(fd_list), struct file_desc, elem)->id) + 1;
        }
        list_push_back(fd_list, &(fd->elem));
        f->eax = fd->id;
    }

    lock_release(&filesys_lock);
}

void sys_filesize(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("\nsys_filesize\n");
#endif
    int fd;
    mem_read_user(f->esp + 4, &fd, sizeof(fd));

    lock_acquire(&filesys_lock);
    struct file_desc *file_desc = find_file_desc(thread_current(), fd);
    if (file_desc != NULL && file_desc->file != NULL) {
        f->eax = file_length(file_desc->file);
    } else {
        f->eax = -1;
    }
    lock_release(&filesys_lock);
}

void sys_read(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("\nsys_read\n");
#endif
    int fd;
    void *buffer;
    unsigned size;
    mem_read_user(f->esp + 4, &fd, sizeof(fd));
    mem_read_user(f->esp + 8, &buffer, sizeof(buffer));
    mem_read_user(f->esp + 12, &size, sizeof(size));

    check_user((const uint8_t *) buffer);
    check_user((const uint8_t *) buffer + size - 1);

    lock_acquire(&filesys_lock);
    if (fd == STDIN_FILENO) {
        for (int i = 0; i < size; i++)
            if (!put_user(buffer + i, input_getc())) {
                exit_with_error(-1);
            }
        f->eax = size;
    } else {
        struct file_desc *file_desc = find_file_desc(thread_current(), fd);
        if (file_desc != NULL && file_desc->file != NULL) {
            preload(buffer, size);
            f->eax = file_read(file_desc->file, buffer, size);
            disable_active(buffer,size);
        } else {
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

    check_user((const uint8_t *) buffer);
    check_user((const uint8_t *) buffer + size - 1);

    lock_acquire(&filesys_lock);
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        f->eax = size;
    } else {
        struct file_desc *file_desc = find_file_desc(thread_current(), fd);
        if (file_desc != NULL && file_desc->file != NULL) {
            preload(buffer, size);
            f->eax = file_write(file_desc->file, buffer, size);
            disable_active(buffer,size);
        } else {
            f->eax = -1;
        }
    }
    lock_release(&filesys_lock);
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
    struct file_desc *file_desc = find_file_desc(thread_current(), fd);
    if (file_desc != NULL && file_desc->file != NULL) {
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
    struct file_desc *file_desc = find_file_desc(thread_current(), fd);
    if (file_desc != NULL && file_desc->file != NULL) {
        f->eax = file_tell(file_desc->file);
    } else {
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
    struct file_desc *file_desc = find_file_desc(thread_current(), fd);
    if (file_desc != NULL && file_desc->file != NULL) {
        file_close(file_desc->file);
        /* if (file_desc->dir != NULL) {
             dir_close(file_desc->dir);
         }*/
        list_remove(&file_desc->elem);
        palloc_free_page(file_desc);
    }
    lock_release(&filesys_lock);
}

void sys_mmap(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("\nsys_mmap\n");
#endif
    int fd;
    void *addr;
    mem_read_user(f->esp + 4, &fd, sizeof(fd));
    mem_read_user(f->esp + 8, &addr, sizeof(addr));    // todo fd == 2

    if (fd <= 1 || (int) addr % PGSIZE != 0) {
        f->eax = -1;
        return;
    }

    lock_acquire(&filesys_lock);
    struct thread *cur = thread_current();
    struct file_desc *desc = find_file_desc(cur, fd);
    if(!desc || !desc->file ) {
        goto invalid;
    }
    off_t size = file_length(desc->file);
    if (size == 0) {
        goto invalid;
    }

    off_t num = (size + PGSIZE - 1) / PGSIZE;

    struct file *file = file_reopen(desc->file);
    if (!file) {
        goto invalid;
    }

    for (int i = 0; i < num; i++) {
        if (vm_get_spte(addr + i * PGSIZE, cur->spt) != NULL) {
            goto invalid;
        }
    }
    for (int i = 0; i < num; i++) {
        size_t read_bytes = PGSIZE;
        if (i == num - 1) read_bytes = (size_t) size % PGSIZE;
        vm_file_install_page(addr + i * PGSIZE, file, i * PGSIZE, read_bytes, PGSIZE - read_bytes, true, cur->spt);
    }
    mapid_t mid = ++cur->mmap_cnt;
    struct mmap_entry *entry = malloc(sizeof(struct mmap_entry));
    entry->file = file;
    entry->addr = addr;
    entry->mid = mid;
    list_push_back(&cur->mmap, &entry->elem);
    f->eax = mid;
    lock_release(&filesys_lock);
    return;

invalid:
    if (file != NULL) file_close(file);
    f->eax = -1;
    lock_release(&filesys_lock);
}

void sys_munmap(struct intr_frame *f) {
#ifdef DEBUGGING
    printf("\nsys_munmap\n");
#endif
    mapid_t mid;
    mem_read_user(f->esp + 4 , &mid, sizeof(mid));
    struct thread* cur = thread_current();
    if (!list_empty(&cur->mmap)){
        for (struct list_elem* e = list_begin(&cur->mmap); e != list_end(&cur->mmap); e = list_next(e)){
            struct mmap_entry* entry = list_entry(e, struct mmap_entry, elem);
            if (entry->mid == mid){
                my_munmap(entry);
                return;
            }
        }
    }
}

void my_munmap(struct mmap_entry* entry){
    lock_acquire(&filesys_lock);
    off_t size = file_length(entry->file);
    struct thread * cur = thread_current();
    for (off_t offset = 0; offset < size; offset += PGSIZE){
        size_t read_bytes = PGSIZE;
        if (offset + PGSIZE > size) read_bytes = (size_t) size % PGSIZE;
        vm_unmap(entry->addr, entry->file, offset, read_bytes, cur->pagedir, cur->spt);
    }
    list_remove(&entry->elem);
    file_close(entry->file);
    free(entry);
    lock_release(&filesys_lock);
}

void preload(void * buffer, int size){
    uint32_t *pagedir = thread_current()->pagedir;
    struct supplemental_page_table *spt = thread_current()->spt;
    for (void *upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE){
        vm_load(upage, pagedir, spt);
        vm_spt_set_active(upage, true, spt);
    }
}

void disable_active(void * buffer, int size){
    struct supplemental_page_table *spt = thread_current()->spt;
    for (void *upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE){
        vm_spt_set_active(upage, false, spt);
    }
}

static void
syscall_handler(struct intr_frame *f) {
    int syscall_num;
    mem_read_user(f->esp, &syscall_num, sizeof(syscall_num));
    thread_current()->pcb->esp = f->esp;
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
        case SYS_MMAP:
            sys_mmap(f);
            break;
        case SYS_MUNMAP:
            sys_munmap(f);
            break;
        default:
            ASSERT(false);//todo
    }
}
