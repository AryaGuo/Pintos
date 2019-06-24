#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "../threads/interrupt.h"
#include "../threads/synch.h"

void syscall_init (void);
void exit_with_error(int ret);

#endif /* userprog/syscall.h */
