#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "../threads/thread.h"
#include "../filesys/off_t.h"

tid_t process_execute (const char *args);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
