#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "../user/syscall.h"
#include "../threads/thread.h"
#include "../filesys/off_t.h"
#include "../threads/synch.h"

tid_t process_execute (const char *args);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct process_control_block {
    pid_t pid;                /* The pid of process */

    char* fn_copy;      /* The command line of this process being executed */

    struct list_elem elem;    /* element for thread.child_list */
    struct thread* parent_thread;    /* the parent process. */

    bool waiting;             /* indicates whether parent process is waiting on this. */
    bool exited;              /* indicates whether the process is done (exited). */
    bool orphan;              /* indicates whether the parent process has terminated before. */
    int32_t exitcode;         /* the exit code passed from exit(), when exited = true */

    /* Synchronization */
    struct semaphore load_finished;   /* the semaphore used between start_process() and process_execute() */
    struct semaphore sema_wait;             /* the semaphore used for wait() : parent blocks until child exits */
    struct file *executable;
};
#endif /* userprog/process.h */
