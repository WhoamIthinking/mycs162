#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"

void syscall_init (void);
void sys_halt (void);
void sys_exit (int status);
void sys_write (struct intr_frame *f);
bool sys_create(const char *name, unsigned initial_size);
int sys_open(const char *name);
int sys_close(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_filesize(int fd);
#endif /**< userprog/syscall.h */
