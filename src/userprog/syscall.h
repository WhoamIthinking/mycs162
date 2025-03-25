#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"

void syscall_init (void);
void sys_halt (void);
void sys_exit (int status);
void sys_write (struct intr_frame *f);
#endif /**< userprog/syscall.h */
