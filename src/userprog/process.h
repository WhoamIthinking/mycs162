#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct process_args{
    char *program_name;
    int argc;//number of arguments
    char **argv;//arguments
    char *fncopy;//copy of file name
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /**< userprog/process.h */
