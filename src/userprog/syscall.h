#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"

void syscall_init (void);
void sys_halt (void);
void sys_exit (int status);
int sys_write(int fd, const void *buffer, unsigned size);
bool sys_create(const char *name, unsigned initial_size);
int sys_open(const char *name);
int sys_close(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_filesize(int fd);
int sys_exec(const char *cmd_line);
#endif /**< userprog/syscall.h */
